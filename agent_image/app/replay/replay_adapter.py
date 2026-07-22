"""Load verified uploaded artifacts and execute strict or live replay."""

from __future__ import annotations

import json
from pathlib import Path

from app.adapter.langgraph_adapter import LangGraphAdapter
from app.agent.model_factory import ModelFactory
from app.replay.checkpoint import RecordingSession
from app.replay.decision_recorder import LiveDecisionModel, RecordedDecisionModel
from app.replay.state_codec import StateCodec
from app.replay.tool_recorder import ToolReplayer
from app.tools.base import ToolRegistry
from sandbox.protocol import ExecutionRequest, ModelOptions
from sandbox.replay.digests import sha256_bytes, sha256_digest
from sandbox.replay.exceptions import ArtifactIntegrityError, ReplayDivergenceError
from sandbox.replay.manifest import verify_manifest
from sandbox.replay.models import (
    ArtifactRef,
    CheckpointStateEnvelope,
    ForkSuffixMode,
    RecordedModelDecision,
    RecordedToolInteraction,
    ReplayCheckpointsRequest,
    ReplayForkRequest,
    ReplayManifest,
    ReplayMode,
    ReplayRequest,
    StateCheckpoint,
)


class ReplayAdapter:
    def __init__(self, input_dir: Path = Path("/workspace/replay-in")) -> None:
        self.input_dir = input_dir
        self.last_checkpoint_digests = []
        self.last_final_state_digest: str | None = None

    def load(self, replay_request: ReplayRequest):
        manifest_path = self._safe_input_path(replay_request.manifest_relative_path)
        manifest = ReplayManifest.model_validate_json(manifest_path.read_bytes())
        verify_manifest(manifest)
        prompt_payload = self._read_json(manifest.prompt)
        determinism = self._read_json(manifest.determinism_config)
        initial_envelope = CheckpointStateEnvelope.model_validate(
            self._read_json(manifest.initial_state)
        )
        decisions = self._read_jsonl(manifest.model_decisions, RecordedModelDecision)
        interactions = self._read_jsonl(manifest.tool_records, RecordedToolInteraction)
        tools = ToolRegistry()
        initial = StateCodec().restore(
            initial_envelope,
            tools,
            execution_id=replay_request.execution_id,
        )
        prompt = prompt_payload.get("prompt")
        if not isinstance(prompt, str):
            raise ArtifactIntegrityError("recorded prompt artifact is invalid")
        initial["prompt"] = prompt
        request = ExecutionRequest(
            execution_id=replay_request.execution_id,
            case_id=manifest.case_id,
            prompt=prompt,
            max_steps=int(determinism["max_steps"]),
            timeout_seconds=int(determinism["timeout_seconds"]),
            seed=manifest.seed,
            scenario_id=manifest.scenario_id,
            agent_version=manifest.agent_version,
            image_digest=manifest.image_digest,
            model=(
                ModelOptions.model_validate(determinism["model"])
                if determinism.get("model") is not None
                else None
            ),
        )
        model = (
            RecordedDecisionModel(
                decisions,
                start_index=initial_envelope.next_model_decision_index,
            )
            if replay_request.mode == ReplayMode.STRICT
            else LiveDecisionModel(
                ModelFactory.create(request.model),
                decisions,
                start_index=initial_envelope.next_model_decision_index,
            )
        )
        return (
            request,
            model,
            ToolReplayer(
                tools,
                interactions,
                start_index=initial_envelope.next_tool_interaction_index,
            ),
            initial,
            str(determinism.get("start_node", "agent")),
        )

    async def execute(self, replay_request: ReplayRequest):
        request, model, tools, initial, start_node = self.load(replay_request)
        adapter = LangGraphAdapter()
        async for event in adapter.execute_replay(
            request,
            model=model,
            tools=tools,
            initial=initial,
            start_node=start_node,
        ):
            yield event
        self.last_checkpoint_digests = adapter.last_checkpoint_digests
        self.last_final_state_digest = adapter.last_final_state_digest

    def load_fork(self, fork_request: ReplayForkRequest):
        manifest_path = self._safe_input_path(fork_request.manifest_relative_path)
        manifest = ReplayManifest.model_validate_json(manifest_path.read_bytes())
        verify_manifest(manifest)
        determinism = self._read_json(manifest.determinism_config)
        checkpoints = self._read_jsonl(manifest.checkpoints, StateCheckpoint)
        checkpoint = next(
            (
                item
                for item in checkpoints
                if item.checkpoint_id == fork_request.checkpoint_id
            ),
            None,
        )
        if checkpoint is None or not checkpoint.recoverable or checkpoint.state_artifact is None:
            raise ReplayDivergenceError(-32105, "checkpoint is missing or not recoverable")
        if fork_request.injection.type not in checkpoint.allowed_injection_types:
            raise ReplayDivergenceError(-32112, "injection type is not allowed at checkpoint")
        envelope = CheckpointStateEnvelope.model_validate(
            self._read_json(checkpoint.state_artifact)
        )
        base_tools = ToolRegistry()
        initial = StateCodec().restore(
            envelope,
            base_tools,
            execution_id=fork_request.execution_id,
        )
        start_node, replacement_decisions = self._apply_injection(
            initial,
            fork_request,
        )
        if fork_request.suffix_mode == ForkSuffixMode.STRICT_WITH_REPLACEMENTS:
            if replacement_decisions is None:
                raise ReplayDivergenceError(
                    -32112,
                    "strict_with_replacements requires complete replacement decisions",
                )
            base_model = RecordedDecisionModel(replacement_decisions)
        else:
            model_options = (
                ModelOptions.model_validate(determinism["model"])
                if determinism.get("model") is not None
                else None
            )
            base_model = ModelFactory.create(model_options)
        prompt = initial.get("prompt")
        if not isinstance(prompt, str) or not prompt:
            raise ReplayDivergenceError(-32112, "fork state contains no valid prompt")
        request = ExecutionRequest(
            execution_id=fork_request.execution_id,
            case_id=f"{manifest.case_id}-fork",
            prompt=prompt,
            max_steps=int(initial.get("max_steps", 20)),
            timeout_seconds=120,
            seed=manifest.seed,
            scenario_id=manifest.scenario_id,
            agent_version=manifest.agent_version,
            image_digest=manifest.image_digest,
            model=model_options if "model_options" in locals() else None,
        )
        recording = RecordingSession(
            request,
            base_model,
            base_tools,
            start_node=start_node,
        )
        recording.audit_events.extend(
            [
                {
                    "event_type": "fork_started",
                    "checkpoint_id": checkpoint.checkpoint_id,
                    "suffix_mode": fork_request.suffix_mode.value,
                },
                {
                    "event_type": "fork_injection_applied",
                    "injection_type": fork_request.injection.type,
                    "content_digest": sha256_digest(fork_request.injection.content),
                },
            ]
        )
        return request, recording.model, recording.tools, initial, recording, start_node

    async def execute_fork(self, fork_request: ReplayForkRequest):
        request, model, tools, initial, recording, start_node = self.load_fork(fork_request)
        async for event in LangGraphAdapter().execute_fork(
            request,
            model=model,
            tools=tools,
            initial=initial,
            recording=recording,
            start_node=start_node,
        ):
            yield event

    @staticmethod
    def _apply_injection(initial: dict, fork_request: ReplayForkRequest):
        injection = fork_request.injection
        replacement_decisions = None
        if injection.type in {"prompt_replace", "prompt_append"}:
            if not isinstance(injection.content, str):
                raise ReplayDivergenceError(-32112, "prompt injection content must be a string")
            if injection.type == "prompt_replace":
                initial["prompt"] = injection.content
            else:
                initial["prompt"] = str(initial.get("prompt", "")) + injection.content
            initial["action"] = None
            initial["tool_result"] = None
            return "agent", None
        if injection.type == "model_decision_replace":
            if not isinstance(injection.content, dict):
                raise ReplayDivergenceError(-32112, "model decision injection must be an object")
            action = injection.content.get("action")
            if action is not None and not isinstance(action, dict):
                raise ReplayDivergenceError(-32112, "replacement action is invalid")
            initial["action"] = action
            initial["continue_loop"] = bool(injection.content.get("continue_loop", False))
            raw_decisions = injection.content.get("remaining_decisions")
            if raw_decisions is not None:
                if not isinstance(raw_decisions, list):
                    raise ReplayDivergenceError(-32112, "remaining decisions must be a list")
                replacement_decisions = [
                    RecordedModelDecision.model_validate(item)
                    for item in raw_decisions
                ]
            return ("tool" if action else "finalize"), replacement_decisions
        if not isinstance(injection.content, dict):
            raise ReplayDivergenceError(-32112, "tool result injection must be an object")
        if not isinstance(injection.content.get("allowed"), bool) or not isinstance(
            injection.content.get("outcome"),
            str,
        ):
            raise ReplayDivergenceError(-32112, "replacement tool result is invalid")
        initial["tool_result"] = injection.content
        should_loop = bool(initial.get("continue_loop")) and int(
            initial.get("step_count", 0)
        ) < int(initial.get("max_steps", 1))
        return ("agent" if should_loop else "finalize"), None

    def checkpoints(self, request: ReplayCheckpointsRequest):
        manifest_path = self._safe_input_path(request.manifest_relative_path)
        manifest = ReplayManifest.model_validate_json(manifest_path.read_bytes())
        verify_manifest(manifest)
        return self._read_jsonl(manifest.checkpoints, StateCheckpoint)

    def _read_json(self, reference: ArtifactRef):
        try:
            return json.loads(self._read_artifact(reference))
        except (ValueError, UnicodeError) as exc:
            raise ArtifactIntegrityError("uploaded JSON artifact is invalid") from exc

    def _read_jsonl(self, reference: ArtifactRef, model_type):
        records = []
        for line in self._read_artifact(reference).splitlines():
            if line.strip():
                records.append(model_type.model_validate_json(line))
        index_name = None
        if model_type is RecordedModelDecision:
            index_name = "decision_index"
        elif model_type is RecordedToolInteraction:
            index_name = "interaction_index"
        if index_name is not None and [getattr(record, index_name) for record in records] != list(
            range(len(records))
        ):
            raise ArtifactIntegrityError("recorded indexes are not contiguous")
        return records

    def _read_artifact(self, reference: ArtifactRef) -> bytes:
        path = self.input_dir / "artifacts" / Path(*reference.relative_path.split("/"))
        resolved = path.resolve()
        artifact_root = (self.input_dir / "artifacts").resolve()
        if artifact_root not in resolved.parents or not resolved.is_file():
            raise ArtifactIntegrityError("uploaded replay artifact is missing")
        payload = resolved.read_bytes()
        if len(payload) != reference.size_bytes or sha256_bytes(payload) != reference.sha256:
            raise ArtifactIntegrityError("uploaded replay artifact digest mismatch")
        return payload

    def _safe_input_path(self, relative_path: str) -> Path:
        if not relative_path or "\\" in relative_path:
            raise ArtifactIntegrityError("manifest path is invalid")
        path = (self.input_dir / Path(*relative_path.split("/"))).resolve()
        root = self.input_dir.resolve()
        if root not in path.parents or not path.is_file():
            raise ArtifactIntegrityError("uploaded replay manifest is missing")
        return path


# Backward-compatible name used by the first strict-replay tests.
StrictReplayAdapter = ReplayAdapter
