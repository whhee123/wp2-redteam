"""SHA-256 helpers for raw artifacts and canonical JSON values."""

from __future__ import annotations

import hashlib

from sandbox.replay.canonical import canonical_json_bytes


def sha256_bytes(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def sha256_digest(value: object) -> str:
    return sha256_bytes(canonical_json_bytes(value))

