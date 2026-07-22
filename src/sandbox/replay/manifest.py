"""Immutable ReplayManifest sealing, verification, and persistence."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from sandbox.replay.canonical import canonical_json_bytes
from sandbox.replay.digests import sha256_bytes, sha256_digest
from sandbox.replay.exceptions import ManifestIntegrityError
from sandbox.replay.models import ReplayManifest


def manifest_payload(manifest: ReplayManifest) -> dict:
    # This exact mode/exclusion contract is part of Canonical JSON v1.
    return manifest.model_dump(
        mode="json",
        exclude={"manifest_digest"},
        exclude_none=False,
    )


def compute_manifest_digest(manifest: ReplayManifest) -> str:
    return sha256_digest(manifest_payload(manifest))


def seal_manifest(manifest: ReplayManifest) -> ReplayManifest:
    if manifest.manifest_digest is not None:
        raise ManifestIntegrityError("manifest is already sealed")
    return manifest.model_copy(update={"manifest_digest": compute_manifest_digest(manifest)})


def verify_manifest(manifest: ReplayManifest, detached_digest: str | None = None) -> None:
    if manifest.manifest_digest is None:
        raise ManifestIntegrityError("manifest is not sealed")
    actual = compute_manifest_digest(manifest)
    if actual != manifest.manifest_digest:
        raise ManifestIntegrityError("embedded manifest digest does not match payload")
    if detached_digest is not None and detached_digest.strip() != actual:
        raise ManifestIntegrityError("manifest.sha256 does not match payload")


class ManifestStore:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def save(self, manifest: ReplayManifest) -> Path:
        verify_manifest(manifest)
        replay_dir = self._replay_dir(manifest.replay_id)
        manifest_path = replay_dir / "manifest.json"
        digest_path = replay_dir / "manifest.sha256"
        if manifest_path.exists() or digest_path.exists():
            raise ManifestIntegrityError("replay manifest already exists and is immutable")
        replay_dir.mkdir(parents=True, exist_ok=False)
        try:
            self._atomic_write(manifest_path, canonical_json_bytes(manifest))
            self._atomic_write(digest_path, (manifest.manifest_digest + "\n").encode("ascii"))
        except Exception:
            manifest_path.unlink(missing_ok=True)
            digest_path.unlink(missing_ok=True)
            replay_dir.rmdir()
            raise
        return manifest_path

    def load(self, replay_id: str) -> ReplayManifest:
        replay_dir = self._replay_dir(replay_id)
        manifest_path = replay_dir / "manifest.json"
        digest_path = replay_dir / "manifest.sha256"
        if not manifest_path.is_file() or not digest_path.is_file():
            raise ManifestIntegrityError("replay manifest is missing")
        raw = manifest_path.read_bytes()
        try:
            manifest = ReplayManifest.model_validate_json(raw)
            detached = digest_path.read_text(encoding="ascii").strip()
        except (ValueError, UnicodeError) as exc:
            raise ManifestIntegrityError("replay manifest is invalid") from exc
        verify_manifest(manifest, detached)
        if sha256_bytes(canonical_json_bytes(manifest)) != sha256_bytes(raw):
            raise ManifestIntegrityError("manifest.json is not canonical JSON")
        return manifest

    def save_run_artifacts(
        self,
        replay_id: str,
        replay_run_id: str,
        *,
        result: bytes,
        trajectory: bytes,
        audit: bytes | None = None,
    ) -> Path:
        replay_dir = self._replay_dir(replay_id)
        if not (replay_dir / "manifest.json").is_file():
            raise ManifestIntegrityError("source replay manifest is missing")
        if not replay_run_id or any(c in replay_run_id for c in "/\\:"):
            raise ManifestIntegrityError("invalid replay_run_id")
        run_dir = replay_dir / "runs" / replay_run_id
        run_dir.mkdir(parents=True, exist_ok=False)
        self._atomic_write(run_dir / "result.json", result)
        self._atomic_write(run_dir / "trajectory.jsonl", trajectory)
        if audit is not None:
            self._atomic_write(run_dir / "replay-audit.jsonl", audit)
        return run_dir

    def _replay_dir(self, replay_id: str) -> Path:
        if not replay_id or replay_id in {".", ".."} or any(c in replay_id for c in "/\\:"):
            raise ManifestIntegrityError("invalid replay_id")
        candidate = (self.root / replay_id).resolve()
        if self.root not in candidate.parents:
            raise ManifestIntegrityError("replay path escapes store root")
        return candidate

    @staticmethod
    def _atomic_write(path: Path, payload: bytes) -> None:
        fd, temporary_name = tempfile.mkstemp(prefix=".manifest-", dir=path.parent)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
