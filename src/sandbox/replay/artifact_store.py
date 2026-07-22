"""Content-addressed, atomic artifact persistence."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from sandbox.replay.digests import sha256_bytes
from sandbox.replay.exceptions import ArtifactIntegrityError
from sandbox.replay.models import ArtifactRef


class ArtifactStore:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def put_bytes(self, payload: bytes, *, media_type: str) -> ArtifactRef:
        digest = sha256_bytes(payload)
        relative_path = self.relative_path_for_digest(digest)
        destination = self._resolve_relative(relative_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            self._verify_path(destination, digest=digest, size_bytes=len(payload))
        else:
            fd, temporary_name = tempfile.mkstemp(prefix=".artifact-", dir=destination.parent)
            temporary = Path(temporary_name)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
                self._verify_path(temporary, digest=digest, size_bytes=len(payload))
                os.replace(temporary, destination)
            finally:
                temporary.unlink(missing_ok=True)
        return ArtifactRef(
            media_type=media_type,
            sha256=digest,
            size_bytes=len(payload),
            relative_path=relative_path,
        )

    def read_bytes(self, reference: ArtifactRef) -> bytes:
        expected_path = self.relative_path_for_digest(reference.sha256)
        if reference.relative_path != expected_path:
            raise ArtifactIntegrityError("artifact path does not match its digest")
        path = self._resolve_relative(reference.relative_path)
        if not path.is_file():
            raise ArtifactIntegrityError(f"artifact is missing: {reference.sha256}")
        payload = path.read_bytes()
        if len(payload) != reference.size_bytes or sha256_bytes(payload) != reference.sha256:
            raise ArtifactIntegrityError(f"artifact integrity check failed: {reference.sha256}")
        return payload

    def verify(self, reference: ArtifactRef) -> None:
        self.read_bytes(reference)

    @staticmethod
    def relative_path_for_digest(digest: str) -> str:
        algorithm, separator, hex_digest = digest.partition(":")
        if algorithm != "sha256" or not separator or len(hex_digest) != 64:
            raise ArtifactIntegrityError("unsupported artifact digest")
        return f"sha256/{hex_digest[:2]}/{hex_digest[2:4]}/{hex_digest}"

    def _resolve_relative(self, relative_path: str) -> Path:
        candidate = (self.root / Path(*relative_path.split("/"))).resolve()
        if candidate == self.root or self.root not in candidate.parents:
            raise ArtifactIntegrityError("artifact path escapes the store root")
        return candidate

    @staticmethod
    def _verify_path(path: Path, *, digest: str, size_bytes: int) -> None:
        payload = path.read_bytes()
        if len(payload) != size_bytes or sha256_bytes(payload) != digest:
            raise ArtifactIntegrityError("artifact write verification failed")

