"""Shared validation for identifiers that become resource or file names."""

from __future__ import annotations

import re

EXECUTION_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
FUZZ_EXECUTION_ID_PATTERN = re.compile(r"^fuzz-[0-9a-f]{24}$")


def validate_execution_id(execution_id: str, *, fuzz_only: bool = False) -> str:
    if execution_id in {".", ".."} or not EXECUTION_ID_PATTERN.fullmatch(execution_id):
        raise ValueError("invalid execution_id")
    if fuzz_only and not FUZZ_EXECUTION_ID_PATTERN.fullmatch(execution_id):
        raise ValueError("invalid fuzz execution_id")
    return execution_id
