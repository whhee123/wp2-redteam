"""Safe Docker Archive API transfer for isolated replay artifacts."""

from __future__ import annotations

import asyncio
import io
import json
import re
import tarfile
from pathlib import PurePosixPath
from typing import Any

from docker.errors import DockerException, NotFound

from sandbox.replay.artifact_store import ArtifactStore
from sandbox.replay.canonical import canonical_json_bytes
from sandbox.replay.exceptions import ArtifactIntegrityError
from sandbox.replay.models import ArtifactRef, ReplayManifest
from sandbox.scheduler.models import SandboxHandle


class ArtifactTransfer:
    def __init__(self, docker_client: Any, artifact_store: ArtifactStore) -> None:
        self.docker_client = docker_client
        self.artifact_store = artifact_store

    async def download(
        self,
        handle: SandboxHandle,
        *,
        max_total_bytes: int = 256 * 1024 * 1024,
        max_file_bytes: int = 64 * 1024 * 1024,
    ) -> dict[str, bytes]:
        return await asyncio.to_thread(
            self._download_sync,
            handle,
            max_total_bytes,
            max_file_bytes,
        )

    async def upload(
        self,
        handle: SandboxHandle,
        manifest: ReplayManifest,
        *,
        max_total_bytes: int = 256 * 1024 * 1024,
    ) -> None:
        await asyncio.to_thread(self._upload_sync, handle, manifest, max_total_bytes)

    def _download_sync(
        self,
        handle: SandboxHandle,
        max_total_bytes: int,
        max_file_bytes: int,
    ) -> dict[str, bytes]:
        try:
            container = self.docker_client.containers.get(handle.container_id)
            chunks, _ = container.get_archive("/workspace/replay-out")
            archive = bytearray()
            for chunk in chunks:
                archive.extend(chunk)
                if len(archive) > max_total_bytes:
                    raise ArtifactIntegrityError("replay artifact archive exceeds total limit")
        except ArtifactIntegrityError:
            raise
        except (DockerException, NotFound) as exc:
            raise ArtifactIntegrityError("failed to download replay artifacts") from exc
        return self._extract_archive(bytes(archive), max_total_bytes, max_file_bytes)

    @classmethod
    def _extract_archive(
        cls,
        archive: bytes,
        max_total_bytes: int,
        max_file_bytes: int,
    ) -> dict[str, bytes]:
        if len(archive) > max_total_bytes:
            raise ArtifactIntegrityError("replay artifact archive exceeds total limit")
        files: dict[str, bytes] = {}
        total_extracted = 0
        try:
            with tarfile.open(fileobj=io.BytesIO(archive), mode="r:*") as tar:
                for member in tar:
                    root_name = member.name.replace("\\", "/").rstrip("/")
                    if member.isdir() and root_name == "replay-out":
                        continue
                    name = cls._safe_member_name(member.name)
                    if member.isdir():
                        continue
                    if not member.isfile():
                        raise ArtifactIntegrityError("tar contains a non-regular member")
                    if member.size > max_file_bytes:
                        raise ArtifactIntegrityError("tar member exceeds per-file limit")
                    total_extracted += member.size
                    if total_extracted > max_total_bytes:
                        raise ArtifactIntegrityError("extracted artifacts exceed total limit")
                    stream = tar.extractfile(member)
                    if stream is None:
                        raise ArtifactIntegrityError("tar member cannot be read")
                    payload = stream.read(max_file_bytes + 1)
                    if len(payload) != member.size:
                        raise ArtifactIntegrityError("tar member size does not match its header")
                    if name in files:
                        raise ArtifactIntegrityError("tar contains duplicate member names")
                    files[name] = payload
        except ArtifactIntegrityError:
            raise
        except (tarfile.TarError, OSError) as exc:
            raise ArtifactIntegrityError("invalid replay artifact tar archive") from exc
        return files

    @staticmethod
    def _safe_member_name(name: str) -> str:
        normalized = name.replace("\\", "/")
        if normalized.startswith(("/", "//")) or re.match(r"^[A-Za-z]:", normalized):
            raise ArtifactIntegrityError("tar member path is absolute")
        parts = list(PurePosixPath(normalized).parts)
        if parts and parts[0] == "replay-out":
            parts = parts[1:]
        if not parts or any(part in {"", ".", ".."} for part in parts):
            raise ArtifactIntegrityError("tar member path is unsafe")
        return "/".join(parts)

    def _upload_sync(
        self,
        handle: SandboxHandle,
        manifest: ReplayManifest,
        max_total_bytes: int,
    ) -> None:
        payloads: dict[str, bytes] = {
            "manifest.json": canonical_json_bytes(manifest),
        }
        references = self._manifest_references(manifest)
        for reference in references:
            payloads[f"artifacts/{reference.relative_path}"] = self.artifact_store.read_bytes(
                reference
            )
        total_size = sum(len(payload) for payload in payloads.values())
        if total_size > max_total_bytes:
            raise ArtifactIntegrityError("replay upload exceeds total limit")
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as tar:
            for relative_path, payload in sorted(payloads.items()):
                info = tarfile.TarInfo(f"replay-in/{relative_path}")
                info.size = len(payload)
                info.mode = 0o600
                info.uid = 10001
                info.gid = 10001
                info.uname = "sandbox"
                info.gname = "sandbox"
                tar.addfile(info, io.BytesIO(payload))
        try:
            container = self.docker_client.containers.get(handle.container_id)
            if not container.put_archive("/workspace", buffer.getvalue()):
                raise ArtifactIntegrityError("Runtime rejected replay artifact archive")
        except ArtifactIntegrityError:
            raise
        except (DockerException, NotFound) as exc:
            raise ArtifactIntegrityError("failed to upload replay artifacts") from exc

    def _manifest_references(self, manifest: ReplayManifest) -> list[ArtifactRef]:
        references = [
            manifest.prompt,
            manifest.events,
            manifest.initial_state,
            manifest.determinism_config,
            manifest.model_decisions,
            manifest.tool_records,
            manifest.checkpoints,
        ]
        references.extend(
            reference
            for reference in (
                manifest.recording_audit,
                manifest.filesystem_snapshot,
                manifest.mock_responses,
                manifest.parent_prefix,
            )
            if reference is not None
        )
        checkpoint_payload = self.artifact_store.read_bytes(manifest.checkpoints)
        for line in checkpoint_payload.splitlines():
            if not line.strip():
                continue
            data = json.loads(line)
            state_artifact = data.get("state_artifact")
            if state_artifact:
                references.append(ArtifactRef.model_validate(state_artifact))
        unique: dict[str, ArtifactRef] = {reference.sha256: reference for reference in references}
        return list(unique.values())
