"""Value-level abstraction for stable behavior features."""

from __future__ import annotations

import json
import re
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"
)
TIMESTAMP_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\b")
EXECUTION_ID_RE = re.compile(r"\bexec-[0-9a-f]{16,64}\b", re.IGNORECASE)


def normalize_text(value: str) -> str:
    value = UUID_RE.sub("<UUID>", value)
    value = EXECUTION_ID_RE.sub("<EXECUTION_ID>", value)
    return TIMESTAMP_RE.sub("<TIMESTAMP>", value)


def normalize_path(value: str) -> str:
    path = value.replace("\\", "/")
    if path.startswith("/workspace/replay-out/states/") or path.startswith("/tmp/"):
        return "<TMP_PATH>"
    traversal = ".." in path.split("/")
    normalized = str(PurePosixPath(path))
    if not normalized.startswith("/"):
        normalized = "/workspace/" + normalized.lstrip("/")
    parts = normalized.split("/")
    filename = parts[-1]
    suffix = PurePosixPath(filename).suffix
    marker = f"<FILE>{suffix}" if suffix else "<FILE>"
    if normalized.startswith("/workspace/"):
        base = f"/workspace/{marker}"
    elif normalized.startswith("/etc/"):
        base = f"/etc/{marker}"
    elif normalized.startswith("/private/"):
        base = f"/private/{marker}"
    else:
        root = parts[1] if len(parts) > 2 and parts[1] else "root"
        base = f"/{root}/{marker}"
    return f"<TRAVERSAL>{base}" if traversal else base


def normalize_command(value: str) -> str:
    stripped = value.strip()
    if not stripped:
        return "command(<EMPTY>)"
    command = stripped.split(maxsplit=1)[0].casefold()
    if command in {"curl", "wget"}:
        return f"command({command}:<URL>)"
    return f"command({command}:<ARGS>)"


def normalize_url(value: str) -> str:
    try:
        parts = urlsplit(value)
    except ValueError:
        return "<URL>"
    if not parts.scheme or not parts.netloc:
        return "<URL>"
    query_items = [
        (key, "<VALUE>")
        for key, _ in parse_qsl(parts.query, keep_blank_values=True)
    ]
    query = urlencode(query_items)
    return urlunsplit((parts.scheme.casefold(), parts.netloc.casefold(), parts.path, query, ""))


def value_shape(name: str, value: Any) -> str:
    lowered = name.casefold()
    if lowered in {"path", "file", "filename"} and isinstance(value, str):
        return f"path({normalize_path(value)})"
    if lowered in {"command", "cmd"} and isinstance(value, str):
        return normalize_command(value)
    if lowered in {"endpoint", "url", "uri"} and isinstance(value, str):
        if value.startswith(("http://", "https://")):
            return f"url({normalize_url(value)})"
        return (
            "endpoint(/mock/<ENDPOINT>)"
            if value.startswith("/mock/")
            else "endpoint(<ENDPOINT>)"
        )
    if isinstance(value, dict):
        keys = ",".join(sorted(str(key) for key in value))
        return f"object({keys})"
    if isinstance(value, list):
        item_types = sorted({type(item).__name__ for item in value})
        return f"list({','.join(item_types)})"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int | float):
        return "number"
    if value is None:
        return "null"
    return "string"


def normalize_feature_payload(value: Any) -> str:
    if isinstance(value, str):
        return normalize_text(value)
    return normalize_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    )
