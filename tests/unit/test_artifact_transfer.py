from __future__ import annotations

import io
import tarfile

import pytest

from sandbox.client.artifact_transfer import ArtifactTransfer
from sandbox.replay.exceptions import ArtifactIntegrityError


def _tar(members: list[tuple[str, bytes, str]]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, payload, kind in members:
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            if kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                info.size = 0
            archive.addfile(info, io.BytesIO(payload) if info.isfile() else None)
    return buffer.getvalue()


def test_extract_archive_returns_paths_relative_to_replay_out() -> None:
    archive = _tar(
        [
            ("replay-out/prompt.json", b"{}", "file"),
            ("replay-out/states/a.json", b"{\"a\":1}", "file"),
        ]
    )
    files = ArtifactTransfer._extract_archive(archive, 1_000_000, 1_000)
    assert files == {"prompt.json": b"{}", "states/a.json": b'{"a":1}'}


@pytest.mark.parametrize(
    "name,kind",
    [
        ("replay-out/../escape", "file"),
        ("/absolute", "file"),
        ("C:/drive", "file"),
        ("replay-out/link", "symlink"),
    ],
)
def test_extract_archive_rejects_unsafe_members(name: str, kind: str) -> None:
    with pytest.raises(ArtifactIntegrityError):
        ArtifactTransfer._extract_archive(_tar([(name, b"x", kind)]), 1_000_000, 1_000)

