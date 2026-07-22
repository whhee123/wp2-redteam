"""Versioned prompt normalization and content-addressed identifiers."""

from __future__ import annotations

import re
import unicodedata
from typing import Any

from pydantic import BaseModel

from sandbox.replay.digests import sha256_digest

NORMALIZATION_VERSION = "1.0"


def normalize_prompt(prompt: str) -> str:
    text = unicodedata.normalize("NFKC", prompt).replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip() for line in text.split("\n")]
    normalized: list[str] = []
    in_code_block = False
    previous_blank = False
    for line in lines:
        if line.strip().startswith("```"):
            in_code_block = not in_code_block
        current = line if in_code_block else re.sub(r"[\t ]+", " ", line)
        blank = not current.strip()
        if blank and previous_blank:
            continue
        normalized.append(current)
        previous_blank = blank
    return "\n".join(normalized).strip()


def prompt_digest(prompt: str) -> str:
    return sha256_digest(prompt)


def normalized_prompt_digest(prompt: str) -> str:
    return sha256_digest(normalize_prompt(prompt))


def prompt_dedupe_key(prompt: str) -> str:
    return sha256_digest(
        {
            "candidate_kind": "prompt",
            "normalized_prompt_sha256": normalized_prompt_digest(prompt),
        }
    )


def fork_dedupe_key(
    *,
    parent_replay_id: str,
    checkpoint_id: str,
    injection_type: str,
    content: str,
) -> str:
    return sha256_digest(
        {
            "candidate_kind": "fork",
            "parent_replay_id": parent_replay_id,
            "checkpoint_id": checkpoint_id,
            "injection_type": injection_type,
            "normalized_prompt_sha256": normalized_prompt_digest(content),
        }
    )


def _digest_projection(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return _digest_projection(value.model_dump(mode="json", exclude_none=False))
    if isinstance(value, float):
        return format(value, ".17g")
    if isinstance(value, dict):
        return {
            str(key): _digest_projection(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, list | tuple):
        return [_digest_projection(item) for item in value]
    return value


def stable_digest(value: Any) -> str:
    return sha256_digest(_digest_projection(value))
