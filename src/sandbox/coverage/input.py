"""Resolve committed trajectories, replay manifests, and prompt metadata."""

from __future__ import annotations

import json
from pathlib import Path

from sandbox.coverage.exceptions import CoverageInputError
from sandbox.coverage.models import CoverageInput
from sandbox.engine.case_source import TemplateCaseSource
from sandbox.protocol import TraceEvent
from sandbox.replay.artifact_store import ArtifactStore
from sandbox.replay.digests import sha256_bytes, sha256_digest
from sandbox.replay.manifest import ManifestStore
from sandbox.replay.models import ReplayAuditEvent, ReplayManifest, ReplayResult
from sandbox.storage.trajectory_store import TrajectoryStore


class CoverageInputResolver:
    def __init__(
        self,
        *,
        trajectory_root: Path = Path("data/trajectories"),
        manifest_root: Path = Path("data/replays"),
        artifact_root: Path = Path("data/artifacts"),
        case_source: TemplateCaseSource | None = None,
    ) -> None:
        self.trajectory_root = trajectory_root
        self.manifest_store = ManifestStore(manifest_root)
        self.artifact_store = ArtifactStore(artifact_root)
        self.case_source = case_source or TemplateCaseSource()

    def resolve(
        self,
        *,
        trajectory_id: str | None = None,
        trajectory_path: Path | None = None,
        case_id: str | None = None,
        prompt: str | None = None,
        seed: int | None = None,
    ) -> CoverageInput:
        if (trajectory_id is None) == (trajectory_path is None):
            raise CoverageInputError("provide exactly one of trajectory_id or trajectory_path")
        if trajectory_path is not None:
            return self.from_trajectory_path(
                trajectory_path,
                case_id=case_id,
                prompt=prompt,
                seed=seed,
            )
        assert trajectory_id is not None
        direct = self.trajectory_root / f"{trajectory_id}.jsonl"
        if direct.is_file():
            return self.from_trajectory_path(direct, case_id=case_id, prompt=prompt, seed=seed)
        manifest = self._find_manifest(trajectory_id)
        if manifest is not None:
            return self.from_manifest(manifest)
        replay_run = self._find_replay_run(trajectory_id)
        if replay_run is not None:
            manifest, trajectory_path, source_kind = replay_run
            return self.from_replay_run(
                trajectory_id,
                manifest,
                trajectory_path,
                source_kind=source_kind,
            )
        if self.trajectory_root.is_dir():
            for path in sorted(self.trajectory_root.glob("*.jsonl")):
                candidate = self.from_trajectory_path(path)
                if candidate.trajectory_id == trajectory_id:
                    return candidate
        raise CoverageInputError(f"trajectory not found: {trajectory_id}")

    def from_trajectory_path(
        self,
        path: Path,
        *,
        case_id: str | None = None,
        prompt: str | None = None,
        seed: int | None = None,
    ) -> CoverageInput:
        try:
            trajectory = TrajectoryStore.load(path)
        except Exception as exc:
            raise CoverageInputError(f"cannot load committed trajectory: {path}") from exc
        started_case_id = self._started_case_id(list(trajectory.events))
        resolved_prompt = prompt or self._prompt_for_case(case_id or started_case_id, seed=seed)
        final_answer = self._final_answer(list(trajectory.events))
        trajectory_digest = sha256_bytes(path.read_bytes())
        prompt_digest = sha256_digest(resolved_prompt) if resolved_prompt is not None else None
        derived_trajectory_id = sha256_digest(
            {
                "trajectory_digest": trajectory_digest,
                "prompt_digest": prompt_digest,
            }
        )
        input_digest = sha256_digest(
            {
                "trajectory_id": derived_trajectory_id,
                "trajectory_digest": trajectory_digest,
                "prompt_digest": prompt_digest,
                "final_answer_digest": (
                    sha256_digest(final_answer) if final_answer is not None else None
                ),
                "manifest_digest": None,
            }
        )
        return CoverageInput(
            trajectory_id=derived_trajectory_id,
            execution_id=trajectory.execution_id,
            source_kind="week1" if resolved_prompt is not None else "raw",
            events=list(trajectory.events),
            prompt=resolved_prompt,
            final_answer=final_answer,
            input_digest=input_digest,
        )

    def from_manifest(self, manifest: ReplayManifest | str) -> CoverageInput:
        resolved = self.manifest_store.load(manifest) if isinstance(manifest, str) else manifest
        try:
            events_payload = self.artifact_store.read_bytes(resolved.events)
            prompt_payload = self.artifact_store.read_bytes(resolved.prompt)
            events = [
                TraceEvent.model_validate_json(line)
                for line in events_payload.decode("utf-8").splitlines()
                if line.strip()
            ]
            prompt_object = json.loads(prompt_payload)
            prompt = prompt_object["prompt"]
            if not isinstance(prompt, str):
                raise TypeError("prompt artifact does not contain text")
        except Exception as exc:
            raise CoverageInputError(
                f"cannot resolve replay artifacts: {resolved.replay_id}"
            ) from exc
        if not events:
            raise CoverageInputError("replay event artifact is empty")
        final_answer = self._final_answer(events)
        input_digest = sha256_digest(
            {
                "trajectory_id": resolved.trajectory_id,
                "trajectory_digest": resolved.events.sha256,
                "prompt_digest": resolved.prompt.sha256,
                "final_answer_digest": (
                    sha256_digest(final_answer) if final_answer is not None else None
                ),
                "manifest_digest": resolved.manifest_digest,
            }
        )
        return CoverageInput(
            trajectory_id=resolved.trajectory_id,
            execution_id=events[0].execution_id,
            source_kind="fork" if resolved.parent_replay_id else "recording",
            events=events,
            prompt=prompt,
            final_answer=final_answer,
            input_digest=input_digest,
            manifest_digest=resolved.manifest_digest,
        )

    def from_replay_run(
        self,
        trajectory_id: str,
        manifest: ReplayManifest,
        trajectory_path: Path,
        *,
        source_kind: str,
    ) -> CoverageInput:
        try:
            trajectory = TrajectoryStore.load(trajectory_path)
            prompt_payload = self.artifact_store.read_bytes(manifest.prompt)
            prompt_object = json.loads(prompt_payload)
            prompt = prompt_object["prompt"]
            if not isinstance(prompt, str):
                raise TypeError("prompt artifact does not contain text")
        except Exception as exc:
            raise CoverageInputError(f"cannot resolve replay run: {trajectory_id}") from exc
        trajectory_digest = sha256_bytes(trajectory_path.read_bytes())
        final_answer = self._final_answer(list(trajectory.events))
        input_digest = sha256_digest(
            {
                "trajectory_id": trajectory_id,
                "trajectory_digest": trajectory_digest,
                "prompt_digest": manifest.prompt.sha256,
                "final_answer_digest": (
                    sha256_digest(final_answer) if final_answer is not None else None
                ),
                "manifest_digest": manifest.manifest_digest,
            }
        )
        return CoverageInput(
            trajectory_id=trajectory_id,
            execution_id=trajectory.execution_id,
            source_kind=source_kind,
            events=list(trajectory.events),
            prompt=prompt,
            final_answer=final_answer,
            input_digest=input_digest,
            manifest_digest=manifest.manifest_digest,
        )

    def _find_manifest(self, trajectory_id: str) -> ReplayManifest | None:
        if not self.manifest_store.root.is_dir():
            return None
        for child in sorted(self.manifest_store.root.iterdir()):
            if not child.is_dir() or not (child / "manifest.json").is_file():
                continue
            try:
                manifest = self.manifest_store.load(child.name)
            except Exception:
                continue
            if manifest.trajectory_id == trajectory_id:
                return manifest
        return None

    def _find_replay_run(
        self,
        trajectory_id: str,
    ) -> tuple[ReplayManifest, Path, str] | None:
        if not self.manifest_store.root.is_dir():
            return None
        for replay_dir in sorted(self.manifest_store.root.iterdir()):
            runs_dir = replay_dir / "runs"
            if not replay_dir.is_dir() or not runs_dir.is_dir():
                continue
            try:
                manifest = self.manifest_store.load(replay_dir.name)
            except Exception:
                continue
            for run_dir in sorted(runs_dir.iterdir()):
                result_path = run_dir / "result.json"
                trajectory_path = run_dir / "trajectory.jsonl"
                if not result_path.is_file() or not trajectory_path.is_file():
                    continue
                try:
                    result = ReplayResult.model_validate_json(result_path.read_bytes())
                except Exception:
                    continue
                if result.replay_trajectory_id != trajectory_id:
                    continue
                source_kind = self._replay_source_kind(run_dir)
                return manifest, trajectory_path, source_kind
        return None

    @staticmethod
    def _replay_source_kind(run_dir: Path) -> str:
        audit_path = run_dir / "replay-audit.jsonl"
        if audit_path.is_file():
            try:
                first = next(
                    line for line in audit_path.read_text(encoding="utf-8").splitlines() if line
                )
                event = ReplayAuditEvent.model_validate_json(first)
                mode = event.data.get("mode")
                if mode == "strict":
                    return "strict_replay"
                if mode == "live":
                    return "live_replay"
            except (StopIteration, ValueError, OSError):
                pass
        return "live_replay"

    def _prompt_for_case(self, case_id: str | None, *, seed: int | None) -> str | None:
        if not case_id:
            return None
        template_id = case_id
        resolved_seed = seed
        if "-seed-" in case_id:
            template_id, suffix = case_id.rsplit("-seed-", 1)
            try:
                resolved_seed = int(suffix)
            except ValueError:
                return None
        if template_id not in self.case_source.template_ids:
            return None
        return self.case_source.generate(template_id, seed=resolved_seed or 42).prompt

    @staticmethod
    def _started_case_id(events: list[TraceEvent]) -> str | None:
        for event in events:
            if event.event_type == "execution_started":
                value = event.data.get("case_id")
                return value if isinstance(value, str) else None
        return None

    @staticmethod
    def _final_answer(events: list[TraceEvent]) -> str | None:
        for event in reversed(events):
            if event.event_type == "execution_finished":
                value = event.data.get("final_answer")
                return value if isinstance(value, str) else None
        return None
