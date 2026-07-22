"""Host-side recording orchestration built around the week-one lifecycle."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import uuid4

from sandbox.client.artifact_transfer import ArtifactTransfer
from sandbox.config import WeekOneConfig
from sandbox.engine.case_source import TemplateCaseSource
from sandbox.engine.models import Runtime, Scheduler, Scorer
from sandbox.models import ExecutionRequest, ExecutionStatus, RecordingOptions, TestCase
from sandbox.replay.artifact_store import ArtifactStore
from sandbox.replay.audit_store import ReplayAuditStore
from sandbox.replay.canonical import canonical_json_bytes
from sandbox.replay.comparator import Comparator
from sandbox.replay.digests import sha256_digest
from sandbox.replay.exceptions import ReplayPreparationError
from sandbox.replay.manifest import ManifestStore, seal_manifest
from sandbox.replay.models import (
    ArtifactRef,
    CheckpointComparison,
    CheckpointKind,
    CheckpointStateEnvelope,
    ForkInjection,
    ForkSuffixMode,
    RecordedForkInjection,
    ReplayForkRequest,
    ReplayManifest,
    ReplayMode,
    ReplayRequest,
    ReplayResult,
    ReplayStatus,
    StateCheckpoint,
)
from sandbox.replay.normalizer import normalize_behavior_trace
from sandbox.storage.trajectory_store import TrajectoryStore
from sandbox.versions import (
    AGENT_VERSION,
    GRAPH_VERSION,
    POLICY_VERSION,
    TOOL_REGISTRY_VERSION,
)

REQUIRED_RECORDING_FILES = {
    "prompt.json",
    "events.jsonl",
    "initial-state.json",
    "determinism-config.json",
    "model-decisions.jsonl",
    "tool-records.jsonl",
    "checkpoints.jsonl",
}


class ReplayEngine:
    def __init__(
        self,
        config: WeekOneConfig,
        scheduler: Scheduler,
        runtime: Runtime,
        scorer: Scorer,
        manifest_store: ManifestStore,
        artifact_store: ArtifactStore,
        artifact_transfer: ArtifactTransfer,
        case_source: TemplateCaseSource | None = None,
        comparator: Comparator | None = None,
    ) -> None:
        self.config = config
        self.scheduler = scheduler
        self.runtime = runtime
        self.scorer = scorer
        self.manifest_store = manifest_store
        self.artifact_store = artifact_store
        self.artifact_transfer = artifact_transfer
        self.case_source = case_source or TemplateCaseSource()
        self.comparator = comparator or Comparator()

    async def record_template(self, template_id: str, *, seed: int | None = None) -> ReplayManifest:
        case = self.case_source.generate(
            template_id,
            seed=self.config.seed if seed is None else seed,
        )
        return await self.record(case)

    async def record(self, case: TestCase) -> ReplayManifest:
        execution_id = f"exec-record-{uuid4().hex}"
        replay_id = f"replay-{uuid4().hex}"
        request = ExecutionRequest(
            execution_id=execution_id,
            case_id=case.case_id,
            prompt=case.prompt,
            max_steps=self.config.max_steps,
            timeout_seconds=self.config.sandbox.execution_timeout_seconds,
            metadata=case.metadata,
            seed=case.seed,
            scenario_id=case.scenario_id,
            agent_version=AGENT_VERSION,
            recording=RecordingOptions(enabled=True),
            model=self.config.model,
        )
        trajectory_store = TrajectoryStore(
            self.config.tracing.output_dir,
            execution_id,
            max_events=self.config.tracing.max_events,
        )
        handle = None
        manifest: ReplayManifest | None = None
        cleanup_error: Exception | None = None
        try:
            handle = await self.scheduler.create(
                execution_id,
                self.config.sandbox.image,
                self.config.sandbox.limits,
            )
            request = request.model_copy(update={"image_digest": handle.image_digest})
            await self.scheduler.wait_until_ready(handle)
            await self.runtime.submit(handle, request)
            async for page in self.runtime.poll_and_stream_events(handle, request):
                trajectory_store.append(page.events)
            result = await self.runtime.get_result(handle, execution_id)
            trajectory = trajectory_store.commit(
                final_sequence=result.final_sequence,
                trace_count=result.trace_count,
            )
            if result.status == ExecutionStatus.SUCCEEDED:
                self.scorer.score(trajectory)
            downloaded = await self.artifact_transfer.download(handle)
            missing = REQUIRED_RECORDING_FILES - set(downloaded)
            if missing:
                raise ReplayPreparationError(
                    -32102,
                    f"recording artifacts are missing: {sorted(missing)}",
                )
            downloaded = {
                **downloaded,
                "events.jsonl": b"".join(
                    canonical_json_bytes(event.model_dump(mode="json")) + b"\n"
                    for event in trajectory.events
                ),
            }
            manifest = self._build_manifest(
                replay_id=replay_id,
                case=case,
                image_ref=self.config.sandbox.image,
                image_digest=handle.image_digest,
                events=list(trajectory.events),
                downloaded=downloaded,
            )
            self.manifest_store.save(manifest)
        finally:
            if handle is not None:
                try:
                    await self.scheduler.destroy(handle)
                except Exception as exc:
                    cleanup_error = exc
        if cleanup_error is not None:
            raise ReplayPreparationError(-32108, f"container cleanup failed: {cleanup_error}")
        if manifest is None:
            raise ReplayPreparationError(-32108, "recording produced no manifest")
        return manifest

    async def replay(
        self,
        replay_id: str,
        *,
        mode: ReplayMode = ReplayMode.STRICT,
        replay_run_id: str | None = None,
    ) -> ReplayResult:
        manifest = self.manifest_store.load(replay_id)
        if not manifest.recording_complete:
            raise ReplayPreparationError(-32102, "incomplete recording cannot be replayed")
        self._verify_manifest_artifacts(manifest)
        run_id = replay_run_id or f"run-{uuid4().hex}"
        audit = ReplayAuditStore(run_id)
        audit.append(
            "replay_started",
            {"source_replay_id": replay_id, "mode": mode.value},
        )
        audit.append(
            "manifest_validated",
            {"manifest_digest": manifest.manifest_digest},
        )
        execution_id = f"exec-replay-{uuid4().hex}"
        request = ReplayRequest(
            execution_id=execution_id,
            replay_run_id=run_id,
            source_replay_id=replay_id,
            mode=mode,
            manifest_relative_path="manifest.json",
        )
        trajectory_store = TrajectoryStore(
            self.config.tracing.output_dir,
            execution_id,
            max_events=self.config.tracing.max_events,
        )
        handle = None
        removed = True
        result: ReplayResult | None = None
        try:
            handle = await self.scheduler.create(
                execution_id,
                manifest.image_ref,
                self.config.sandbox.limits,
            )
            removed = False
            audit.append(
                "container_created",
                {"image_digest": handle.image_digest},
            )
            if handle.image_digest != manifest.image_digest:
                raise ReplayPreparationError(-32104, "sandbox image digest does not match Manifest")
            await self.scheduler.wait_until_ready(handle)
            await self.artifact_transfer.upload(handle, manifest)
            audit.append("artifacts_uploaded")
            await self.runtime.replay_submit(handle, request)
            audit.append("state_restore_requested")
            async for page in self.runtime.poll_execution_events(
                handle,
                execution_id,
                timeout_seconds=self.config.sandbox.execution_timeout_seconds,
            ):
                trajectory_store.append(page.events)
            execution_result = await self.runtime.get_result(handle, execution_id)
            trajectory = trajectory_store.commit(
                final_sequence=execution_result.final_sequence,
                trace_count=execution_result.trace_count,
            )
            if execution_result.status == ExecutionStatus.SUCCEEDED:
                source_events = self._read_events(manifest.events)
                comparison = self.comparator.compare(source_events, list(trajectory.events))
                source_checkpoints = self.checkpoints(replay_id)
                checkpoint_comparisons = self._compare_checkpoint_digests(
                    source_checkpoints,
                    execution_result.checkpoint_digests,
                )
                source_final_state_digest = (
                    source_checkpoints[-1].state_digest if source_checkpoints else None
                )
                replay_final_state_digest = execution_result.final_state_digest
                state_matched = (
                    bool(checkpoint_comparisons)
                    and len(checkpoint_comparisons) == len(source_checkpoints)
                    and len(checkpoint_comparisons)
                    == len(execution_result.checkpoint_digests)
                    and all(item.matched for item in checkpoint_comparisons)
                    and source_final_state_digest == replay_final_state_digest
                )
                fully_matched = comparison.matched and state_matched
                result = ReplayResult(
                    replay_run_id=run_id,
                    source_replay_id=replay_id,
                    source_trajectory_id=manifest.trajectory_id,
                    replay_trajectory_id=f"trajectory-{uuid4().hex}",
                    status=(ReplayStatus.MATCHED if fully_matched else ReplayStatus.DIVERGED),
                    source_behavior_digest=comparison.source_digest,
                    replay_behavior_digest=comparison.replay_digest,
                    source_final_state_digest=source_final_state_digest,
                    replay_final_state_digest=replay_final_state_digest,
                    checkpoint_comparisons=checkpoint_comparisons,
                    first_divergence_behavior_index=comparison.first_divergence_behavior_index,
                    source_divergence_sequence=comparison.source_sequence,
                    replay_divergence_sequence=comparison.replay_sequence,
                    divergence_reason=(
                        comparison.reason
                        if not comparison.matched
                        else (None if state_matched else "checkpoint or final state digest differs")
                    ),
                    error_code=None if fully_matched else -32108,
                    container_removed=False,
                )
                audit.append(
                    "replay_matched" if fully_matched else "replay_diverged",
                    {
                        "source_behavior_digest": comparison.source_digest,
                        "replay_behavior_digest": comparison.replay_digest,
                    },
                )
            else:
                terminal_data = trajectory.events[-1].data if trajectory.events else {}
                replay_error_code = terminal_data.get("replay_error_code")
                semantic_divergence = replay_error_code in {-32106, -32107, -32108}
                result = ReplayResult(
                    replay_run_id=run_id,
                    source_replay_id=replay_id,
                    source_trajectory_id=manifest.trajectory_id,
                    status=(
                        ReplayStatus.DIVERGED
                        if semantic_divergence
                        else ReplayStatus.FAILED
                    ),
                    divergence_reason=str(
                        terminal_data.get("message") or execution_result.error_message
                    ),
                    error_code=(
                        int(replay_error_code)
                        if isinstance(replay_error_code, int)
                        else -32108
                    ),
                    container_removed=False,
                )
                audit.append(
                    "replay_failed",
                    {"execution_status": execution_result.status.value},
                )
        finally:
            if handle is not None:
                await self.scheduler.destroy(handle)
                removed = True
                audit.append("container_removed")
        if result is None:
            raise ReplayPreparationError(-32108, "replay produced no result")
        result = result.model_copy(update={"container_removed": removed})
        trajectory_path = trajectory_store.final_path
        self.manifest_store.save_run_artifacts(
            replay_id,
            run_id,
            result=canonical_json_bytes(result),
            trajectory=trajectory_path.read_bytes(),
            audit=audit.to_jsonl(),
        )
        return result

    @staticmethod
    def _compare_checkpoint_digests(
        source_checkpoints: list[StateCheckpoint],
        replay_checkpoints: list,
    ) -> list[CheckpointComparison]:
        comparisons: list[CheckpointComparison] = []
        for source, replay in zip(source_checkpoints, replay_checkpoints, strict=False):
            if source.state_digest is None:
                continue
            kind = CheckpointKind(replay.kind)
            comparisons.append(
                CheckpointComparison(
                    source_checkpoint_id=source.checkpoint_id,
                    replay_checkpoint_id=f"replay-checkpoint-{replay.checkpoint_index}",
                    kind=kind,
                    source_state_digest=source.state_digest,
                    replay_state_digest=replay.state_digest,
                    matched=(source.kind == kind and source.state_digest == replay.state_digest),
                )
            )
        return comparisons

    async def fork(
        self,
        parent_replay_id: str,
        checkpoint_id: str,
        injection: ForkInjection,
        *,
        suffix_mode: ForkSuffixMode = ForkSuffixMode.LIVE_AND_RECORD,
        operator: str = "local-cli",
    ) -> ReplayManifest:
        parent = self.manifest_store.load(parent_replay_id)
        if not parent.recording_complete:
            raise ReplayPreparationError(-32105, "incomplete recording cannot be forked")
        self._verify_manifest_artifacts(parent)
        checkpoint = next(
            (
                item
                for item in self.checkpoints(parent_replay_id)
                if item.checkpoint_id == checkpoint_id
            ),
            None,
        )
        if checkpoint is None or not checkpoint.recoverable or checkpoint.state_artifact is None:
            raise ReplayPreparationError(-32105, "checkpoint is missing or not recoverable")
        if injection.type not in checkpoint.allowed_injection_types:
            raise ReplayPreparationError(-32112, "injection type is not allowed at checkpoint")
        state = CheckpointStateEnvelope.model_validate_json(
            self.artifact_store.read_bytes(checkpoint.state_artifact)
        )
        prompt = state.agent_state.get("prompt")
        if not isinstance(prompt, str):
            raise ReplayPreparationError(-32111, "checkpoint prompt state is invalid")
        if injection.type == "prompt_replace":
            if not isinstance(injection.content, str):
                raise ReplayPreparationError(-32112, "prompt replacement must be a string")
            prompt = injection.content
        elif injection.type == "prompt_append":
            if not isinstance(injection.content, str):
                raise ReplayPreparationError(-32112, "prompt append must be a string")
            prompt += injection.content
        child_replay_id = f"replay-{uuid4().hex}"
        execution_id = f"exec-fork-{uuid4().hex}"
        request = ReplayForkRequest(
            execution_id=execution_id,
            child_replay_id=child_replay_id,
            manifest_relative_path="manifest.json",
            checkpoint_id=checkpoint_id,
            suffix_mode=suffix_mode,
            injection=injection,
        )
        child_case = TestCase(
            case_id=f"{parent.case_id}-fork",
            prompt=prompt,
            scenario_id=parent.scenario_id,
            seed=parent.seed,
            metadata={"parent_replay_id": parent_replay_id},
        )
        trajectory_store = TrajectoryStore(
            self.config.tracing.output_dir,
            execution_id,
            max_events=self.config.tracing.max_events,
        )
        handle = None
        child_manifest: ReplayManifest | None = None
        cleanup_error: Exception | None = None
        try:
            handle = await self.scheduler.create(
                execution_id,
                parent.image_ref,
                self.config.sandbox.limits,
            )
            if handle.image_digest != parent.image_digest:
                raise ReplayPreparationError(-32104, "sandbox image digest does not match Manifest")
            await self.scheduler.wait_until_ready(handle)
            await self.artifact_transfer.upload(handle, parent)
            await self.runtime.replay_fork_submit(handle, request)
            async for page in self.runtime.poll_execution_events(
                handle,
                execution_id,
                timeout_seconds=self.config.sandbox.execution_timeout_seconds,
            ):
                trajectory_store.append(page.events)
            execution_result = await self.runtime.get_result(handle, execution_id)
            if execution_result.status != ExecutionStatus.SUCCEEDED:
                raise ReplayPreparationError(-32108, "fork execution did not succeed")
            trajectory = trajectory_store.commit(
                final_sequence=execution_result.final_sequence,
                trace_count=execution_result.trace_count,
            )
            downloaded = await self.artifact_transfer.download(handle)
            missing = REQUIRED_RECORDING_FILES - set(downloaded)
            if missing:
                raise ReplayPreparationError(
                    -32102,
                    f"fork artifacts are missing: {sorted(missing)}",
                )
            recorded_injection = RecordedForkInjection(
                **injection.model_dump(mode="json"),
                content_digest=sha256_digest(injection.content),
                operator=operator,
                created_at=datetime.now(UTC),
            )
            child_manifest = self._build_manifest(
                replay_id=child_replay_id,
                case=child_case,
                image_ref=parent.image_ref,
                image_digest=parent.image_digest,
                events=list(trajectory.events),
                downloaded=downloaded,
                parent_manifest=parent,
                fork_checkpoint=checkpoint,
                recorded_injection=recorded_injection,
            )
            self.manifest_store.save(child_manifest)
        finally:
            if handle is not None:
                try:
                    await self.scheduler.destroy(handle)
                except Exception as exc:
                    cleanup_error = exc
        if cleanup_error is not None:
            raise ReplayPreparationError(-32108, f"container cleanup failed: {cleanup_error}")
        if child_manifest is None:
            raise ReplayPreparationError(-32108, "fork produced no child Manifest")
        return child_manifest

    def checkpoints(self, replay_id: str) -> list[StateCheckpoint]:
        manifest = self.manifest_store.load(replay_id)
        self._verify_manifest_artifacts(manifest)
        try:
            return [
                StateCheckpoint.model_validate_json(line)
                for line in self.artifact_store.read_bytes(manifest.checkpoints).splitlines()
                if line.strip()
            ]
        except ValueError as exc:
            raise ReplayPreparationError(-32102, "recorded checkpoints are invalid") from exc

    def _build_manifest(
        self,
        *,
        replay_id: str,
        case: TestCase,
        image_ref: str,
        image_digest: str,
        events: list,
        downloaded: dict[str, bytes],
        parent_manifest: ReplayManifest | None = None,
        fork_checkpoint: StateCheckpoint | None = None,
        recorded_injection: RecordedForkInjection | None = None,
    ) -> ReplayManifest:
        prompt_payload = self._parse_json(downloaded["prompt.json"], "prompt.json")
        if prompt_payload != {"prompt": case.prompt}:
            raise ReplayPreparationError(-32103, "recorded prompt does not match the request")
        initial_state = self._parse_json(downloaded["initial-state.json"], "initial-state.json")
        determinism = self._parse_json(
            downloaded["determinism-config.json"],
            "determinism-config.json",
        )
        references = {
            "prompt": self._put(downloaded["prompt.json"], "application/json"),
            "events": self._put(downloaded["events.jsonl"], "application/x-ndjson"),
            "initial_state": self._put(downloaded["initial-state.json"], "application/json"),
            "determinism_config": self._put(
                downloaded["determinism-config.json"], "application/json"
            ),
            "model_decisions": self._put(
                downloaded["model-decisions.jsonl"], "application/x-ndjson"
            ),
            "tool_records": self._put(
                downloaded["tool-records.jsonl"], "application/x-ndjson"
            ),
        }
        references["checkpoints"] = self._store_checkpoints(downloaded)
        recording_audit = None
        if "recording-audit.jsonl" in downloaded:
            recording_audit = self._put(
                downloaded["recording-audit.jsonl"],
                "application/x-ndjson",
            )
        manifest = ReplayManifest(
            replay_id=replay_id,
            trajectory_id=f"trajectory-{uuid4().hex}",
            created_at=events[0].timestamp,
            case_id=case.case_id,
            scenario_id=case.scenario_id,
            seed=case.seed,
            image_ref=image_ref,
            image_digest=image_digest,
            image_digest_kind="repo_digest" if "@sha256:" in image_digest else "image_id",
            runtime_version="0.2.0",
            agent_version=AGENT_VERSION,
            graph_version=GRAPH_VERSION,
            tool_registry_version=TOOL_REGISTRY_VERSION,
            policy_version=POLICY_VERSION,
            default_tool_replay_mode="execute_and_verify",
            recording_complete=bool(determinism.get("recording_complete", True)),
            incomplete_reason=determinism.get("incomplete_reason"),
            prompt_digest=sha256_digest(case.prompt),
            initial_state_digest=sha256_digest(initial_state),
            normalized_behavior_trace_digest=sha256_digest(normalize_behavior_trace(events)),
            determinism_config_digest=sha256_digest(determinism),
            recording_audit=recording_audit,
            parent_replay_id=(parent_manifest.replay_id if parent_manifest else None),
            parent_trajectory_id=(parent_manifest.trajectory_id if parent_manifest else None),
            fork_sequence=(fork_checkpoint.sequence if fork_checkpoint else None),
            fork_checkpoint_id=(fork_checkpoint.checkpoint_id if fork_checkpoint else None),
            injection_digest=(
                sha256_digest(recorded_injection.model_dump(mode="json"))
                if recorded_injection
                else None
            ),
            parent_prefix_digest=(
                self._parent_prefix_digest(parent_manifest, fork_checkpoint)
                if parent_manifest and fork_checkpoint
                else None
            ),
            parent_prefix=(
                self._parent_prefix_artifact(parent_manifest, fork_checkpoint)
                if parent_manifest and fork_checkpoint
                else None
            ),
            metadata={
                "case_source_version": case.metadata.get("case_source_version", "unknown"),
                **(
                    {"fork_injection": recorded_injection.model_dump(mode="json")}
                    if recorded_injection
                    else {}
                ),
            },
            **references,
        )
        return seal_manifest(manifest)

    def _parent_prefix_digest(
        self,
        parent: ReplayManifest,
        checkpoint: StateCheckpoint,
    ) -> str:
        events = [
            event
            for event in self._read_events(parent.events)
            if event.sequence <= checkpoint.sequence
        ]
        return sha256_digest(normalize_behavior_trace(events))

    def _parent_prefix_artifact(
        self,
        parent: ReplayManifest,
        checkpoint: StateCheckpoint,
    ) -> ArtifactRef:
        events = [
            event
            for event in self._read_events(parent.events)
            if event.sequence <= checkpoint.sequence
        ]
        payload = b"".join(
            canonical_json_bytes(event.model_dump(mode="json")) + b"\n"
            for event in events
        )
        return self._put(payload, "application/x-ndjson")

    def _store_checkpoints(self, downloaded: dict[str, bytes]) -> ArtifactRef:
        rewritten: list[bytes] = []
        for line in downloaded["checkpoints.jsonl"].splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                checkpoint = StateCheckpoint.model_validate(data)
            except (ValueError, UnicodeError) as exc:
                raise ReplayPreparationError(-32102, "invalid checkpoint artifact") from exc
            if checkpoint.state_artifact is not None:
                source_path = checkpoint.state_artifact.relative_path
                if source_path not in downloaded:
                    raise ReplayPreparationError(
                        -32102,
                        f"checkpoint state is missing: {source_path}",
                    )
                state_reference = self._put(downloaded[source_path], "application/json")
                if state_reference.sha256 != checkpoint.state_digest:
                    raise ReplayPreparationError(-32103, "checkpoint state digest mismatch")
                checkpoint = checkpoint.model_copy(update={"state_artifact": state_reference})
            rewritten.append(canonical_json_bytes(checkpoint) + b"\n")
        return self._put(b"".join(rewritten), "application/x-ndjson")

    def _verify_manifest_artifacts(self, manifest: ReplayManifest) -> None:
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
        for reference in references:
            self.artifact_store.verify(reference)
        for line in self.artifact_store.read_bytes(manifest.checkpoints).splitlines():
            if not line.strip():
                continue
            checkpoint = StateCheckpoint.model_validate_json(line)
            if checkpoint.state_artifact is not None:
                self.artifact_store.verify(checkpoint.state_artifact)

    def _read_events(self, reference: ArtifactRef):
        from sandbox.models import TraceEvent

        try:
            return [
                TraceEvent.model_validate_json(line)
                for line in self.artifact_store.read_bytes(reference).splitlines()
                if line.strip()
            ]
        except ValueError as exc:
            raise ReplayPreparationError(-32102, "recorded behavior events are invalid") from exc

    def _put(self, payload: bytes, media_type: str) -> ArtifactRef:
        return self.artifact_store.put_bytes(payload, media_type=media_type)

    @staticmethod
    def _parse_json(payload: bytes, name: str):
        try:
            value = json.loads(payload)
        except (ValueError, UnicodeError) as exc:
            raise ReplayPreparationError(-32102, f"invalid JSON artifact: {name}") from exc
        if canonical_json_bytes(value) != payload:
            raise ReplayPreparationError(-32103, f"artifact is not canonical JSON: {name}")
        return value
