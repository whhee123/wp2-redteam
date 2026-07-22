"""One-case-per-container Docker scheduler with no container network."""

from __future__ import annotations

import asyncio
import secrets
import time
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import docker
from docker.errors import APIError, DockerException, ImageNotFound, NotFound

from sandbox.config import SandboxConfig, SandboxLimits
from sandbox.errors import CleanupError, InfrastructureError
from sandbox.scheduler.models import SandboxHandle


class DockerSandboxScheduler:
    """Create, inspect, and remove isolated Runtime containers."""

    component_label = "trace-g.component"
    component_value = "agent-sandbox"
    model_network_policy_label = "trace-g.network-policy"
    model_network_policy_value = "ollama-only"

    def __init__(
        self,
        config: SandboxConfig,
        *,
        client: Any | None = None,
        scheduler_instance_id: str | None = None,
    ) -> None:
        self.config = config
        self.client = client or docker.from_env()
        self.scheduler_instance_id = scheduler_instance_id or uuid4().hex

    async def create(
        self,
        execution_id: str,
        image_ref: str,
        limits: SandboxLimits,
    ) -> SandboxHandle:
        return await asyncio.to_thread(self._create_sync, execution_id, image_ref, limits)

    def _create_sync(
        self,
        execution_id: str,
        image_ref: str,
        limits: SandboxLimits,
    ) -> SandboxHandle:
        container = None
        workspace_volume = None
        token = secrets.token_urlsafe(32)
        try:
            network_mode = self.config.network_mode
            extra_hosts = None
            if self.config.ollama_endpoint is not None:
                network = self._restricted_model_network()
                network_mode = network.name
                extra_hosts = {"host.docker.internal": "host-gateway"}
            tmpfs = {
                "/tmp": (
                    f"rw,noexec,nosuid,size={limits.tmpfs_size},uid=10001,gid=10001,mode=0700"
                )
            }
            volumes = None
            if self.config.workspace_storage == "archive_volume":
                workspace_volume = self.client.volumes.create(
                    name=f"trace-g-workspace-{uuid4().hex}",
                    driver="local",
                    driver_opts={
                        "type": "tmpfs",
                        "device": "tmpfs",
                        "o": (
                            f"size={limits.tmpfs_size},uid=10001,gid=10001,"
                            "mode=0700,noexec,nosuid"
                        ),
                    },
                    labels={
                        self.component_label: "workspace-volume",
                        "trace-g.execution-id": execution_id,
                        "trace-g.owner-instance": self.scheduler_instance_id,
                    },
                )
                volumes = {workspace_volume.name: {"bind": "/workspace", "mode": "rw"}}
            else:
                tmpfs["/workspace"] = (
                    f"rw,noexec,nosuid,size={limits.tmpfs_size},"
                    "uid=10001,gid=10001,mode=0700"
                )
            container = self.client.containers.run(
                image=image_ref,
                detach=True,
                init=True,
                user="10001:10001",
                read_only=True,
                mem_limit=limits.memory_limit,
                nano_cpus=limits.nano_cpus,
                pids_limit=limits.pids_limit,
                network_mode=network_mode,
                extra_hosts=extra_hosts,
                cap_drop=["ALL"],
                security_opt=["no-new-privileges:true"],
                tmpfs=tmpfs,
                volumes=volumes,
                environment={
                    "SANDBOX_TOKEN": token,
                    "EXECUTION_ID": execution_id,
                },
                labels={
                    self.component_label: self.component_value,
                    "trace-g.execution-id": execution_id,
                    "trace-g.owner-instance": self.scheduler_instance_id,
                    "trace-g.created-unix": str(int(time.time())),
                    "trace-g.workspace-volume": (
                        workspace_volume.name if workspace_volume is not None else ""
                    ),
                },
            )
            container.reload()
            image_digest = self._image_digest(container)
            return SandboxHandle(
                execution_id=execution_id,
                container_id=container.id,
                runtime_url=f"http://127.0.0.1:{self.config.runtime_container_port}",
                transport="docker_exec",
                capability_token=token,
                image_digest=image_digest,
                scheduler_instance_id=self.scheduler_instance_id,
                workspace_volume_name=(
                    workspace_volume.name if workspace_volume is not None else None
                ),
                created_at=datetime.now(UTC),
            )
        except ImageNotFound as exc:
            self._remove_partial(container, workspace_volume)
            raise InfrastructureError(f"sandbox image not found: {image_ref}") from exc
        except (DockerException, APIError, KeyError, IndexError) as exc:
            self._remove_partial(container, workspace_volume)
            raise InfrastructureError("failed to create sandbox container") from exc
        except Exception:
            self._remove_partial(container, workspace_volume)
            raise

    def _restricted_model_network(self):
        network_name = self.config.model_network_name
        if not network_name:
            raise InfrastructureError("restricted model network is not configured")
        try:
            network = self.client.networks.get(network_name)
            network.reload()
        except (DockerException, NotFound) as exc:
            raise InfrastructureError("restricted model network does not exist") from exc
        labels = network.attrs.get("Labels") or {}
        if labels.get(self.model_network_policy_label) != self.model_network_policy_value:
            raise InfrastructureError("model network is missing the ollama-only policy label")
        if network.attrs.get("Driver") != "bridge":
            raise InfrastructureError("model network must use the bridge driver")
        return network

    async def wait_until_ready(self, handle: SandboxHandle) -> None:
        deadline = time.monotonic() + self.config.startup_timeout_seconds
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                health = await asyncio.to_thread(
                    self._container_health_status,
                    handle.container_id,
                )
                if health == "healthy":
                    return
            except Exception as exc:  # readiness polling intentionally aggregates failures
                last_error = exc
            await asyncio.sleep(0.1)
        raise InfrastructureError("Runtime health check timed out") from last_error

    async def destroy(self, handle: SandboxHandle) -> None:
        await asyncio.to_thread(self._destroy_sync, handle)

    def _destroy_sync(self, handle: SandboxHandle) -> None:
        failure: Exception | None = None
        try:
            container = self.client.containers.get(handle.container_id)
        except NotFound:
            container = None
        if container is not None:
            try:
                container.remove(force=True, v=True)
            except NotFound:
                pass
            except (DockerException, APIError) as exc:
                failure = exc
        if handle.workspace_volume_name:
            try:
                volume = self.client.volumes.get(handle.workspace_volume_name)
                volume.remove(force=True)
            except NotFound:
                pass
            except (DockerException, APIError) as exc:
                failure = failure or exc
        if failure is not None:
            raise CleanupError(
                f"failed to remove sandbox resources for {handle.execution_id}"
            ) from failure
        try:
            self.client.containers.get(handle.container_id)
        except NotFound:
            return
        raise CleanupError(f"container still exists after removal: {handle.container_id}")

    async def cleanup_orphans(self, max_age_seconds: int = 3_600) -> int:
        return await asyncio.to_thread(self._cleanup_orphans_sync, max_age_seconds)

    def _cleanup_orphans_sync(self, max_age_seconds: int) -> int:
        now = int(time.time())
        removed = 0
        containers = self.client.containers.list(
            all=True,
            filters={"label": f"{self.component_label}={self.component_value}"},
        )
        for container in containers:
            labels = container.labels or {}
            try:
                created = int(labels.get("trace-g.created-unix", "0"))
            except ValueError:
                continue
            if created <= 0 or now - created < max_age_seconds:
                continue
            try:
                volume_name = labels.get("trace-g.workspace-volume")
                container.remove(force=True, v=True)
                if volume_name:
                    with suppress(NotFound):
                        self.client.volumes.get(volume_name).remove(force=True)
                removed += 1
            except NotFound:
                continue
        return removed

    def _container_health_status(self, container_id: str) -> str:
        container = self.client.containers.get(container_id)
        container.reload()
        if container.status not in {"created", "running"}:
            logs = container.logs(tail=50).decode("utf-8", errors="replace")
            raise InfrastructureError(f"Runtime container exited early: {logs[-2_000:]}")
        return str(container.attrs.get("State", {}).get("Health", {}).get("Status", "starting"))

    @staticmethod
    def _image_digest(container: Any) -> str:
        image = container.image
        image.reload()
        repo_digests = image.attrs.get("RepoDigests") or []
        return repo_digests[0] if repo_digests else image.id

    @staticmethod
    def _remove_partial(container: Any | None, workspace_volume: Any | None = None) -> None:
        if container is not None:
            with suppress(Exception):
                container.remove(force=True, v=True)
        if workspace_volume is not None:
            with suppress(Exception):
                workspace_volume.remove(force=True)
