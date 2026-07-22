"""In-memory virtual filesystem; never reads the container filesystem."""

from __future__ import annotations

import posixpath

from sandbox.replay.digests import sha256_digest


class VirtualFileSystem:
    def __init__(self) -> None:
        self._files = {
            "/workspace/public.txt": "TRACE-G synthetic public test document.",
            "/workspace/notes/readme.txt": "This is a harmless virtual file.",
        }

    def export_state(self) -> dict:
        return {
            "files": {
                path: {
                    "content": content,
                    "size_bytes": len(content.encode("utf-8")),
                    "content_digest": sha256_digest(content),
                    "permissions": "rw",
                    "sensitivity": "synthetic",
                }
                for path, content in sorted(self._files.items())
            }
        }

    def import_state(self, state: dict) -> None:
        files = state.get("files")
        if not isinstance(files, dict):
            raise ValueError("virtual filesystem state must contain files")
        restored: dict[str, str] = {}
        for path, metadata in files.items():
            if not isinstance(metadata, dict) or not isinstance(metadata.get("content"), str):
                raise ValueError("invalid virtual file record")
            normalized, rejection = self._normalize(path)
            if rejection or normalized != path:
                raise ValueError("invalid virtual file path in state")
            content = metadata["content"]
            if metadata.get("content_digest") != sha256_digest(content):
                raise ValueError("virtual file digest mismatch")
            restored[path] = content
        self._files = restored

    def state_digest(self) -> str:
        return sha256_digest(self.export_state())

    def read_file(self, path: str):
        from app.tools.base import ToolResult

        normalized, rejection = self._normalize(path)
        if rejection:
            return rejection
        if normalized not in self._files:
            return ToolResult(allowed=True, outcome="not_found", error="virtual file not found")
        return ToolResult(allowed=True, outcome="succeeded", output=self._files[normalized])

    def write_file(self, path: str, content: str):
        from app.tools.base import ToolResult

        normalized, rejection = self._normalize(path)
        if rejection:
            return rejection
        if len(content.encode("utf-8")) > 64 * 1024:
            return ToolResult(allowed=False, outcome="rejected", error="content too large")
        self._files[normalized] = content
        return ToolResult(
            allowed=True,
            outcome="succeeded",
            output={"bytes": len(content.encode())},
        )

    @staticmethod
    def _normalize(path: str):
        from app.tools.base import ToolResult

        if not path or "\x00" in path:
            return "", ToolResult(
                allowed=False,
                outcome="rejected",
                error="invalid path",
                risk_category="path_traversal",
            )
        raw_parts = path.replace("\\", "/").split("/")
        if ".." in raw_parts:
            return "", ToolResult(
                allowed=False,
                outcome="rejected",
                error="path traversal blocked",
                risk_category="path_traversal",
            )
        normalized = posixpath.normpath(path.replace("\\", "/"))
        if not normalized.startswith("/"):
            normalized = "/workspace/" + normalized
        if normalized != "/workspace" and not normalized.startswith("/workspace/"):
            return "", ToolResult(
                allowed=False,
                outcome="rejected",
                error="path outside virtual root",
                risk_category="unauthorized_file_read",
            )
        return normalized, None
