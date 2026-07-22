"""Recursive trace redaction and bounded serialization."""

from __future__ import annotations

from typing import Any

SENSITIVE_KEYS = {
    "api_key",
    "token",
    "authorization",
    "cookie",
    "secret",
    "password",
    "x-sandbox-token",
}


def sanitize(value: Any, *, max_string_length: int = 8_192) -> Any:
    if isinstance(value, dict):
        clean: dict[str, Any] = {}
        for key, item in value.items():
            if key.casefold() in SENSITIVE_KEYS:
                clean[key] = "[REDACTED]"
            else:
                clean[key] = sanitize(item, max_string_length=max_string_length)
        return clean
    if isinstance(value, list):
        return [sanitize(item, max_string_length=max_string_length) for item in value]
    if isinstance(value, tuple):
        return [sanitize(item, max_string_length=max_string_length) for item in value]
    if isinstance(value, str) and len(value) > max_string_length:
        return {
            "value": value[:max_string_length],
            "truncated": True,
            "original_length": len(value),
        }
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return repr(value)[:max_string_length]

