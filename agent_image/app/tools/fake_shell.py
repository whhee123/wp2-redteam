"""A command parser with canned responses; it never invokes a real shell."""

from __future__ import annotations

import shlex

from sandbox.replay.digests import sha256_digest


class FakeShell:
    max_command_length = 4_096

    def __init__(self) -> None:
        self.current_directory = "/workspace"
        self.command_count = 0

    def export_state(self) -> dict:
        return {
            "current_directory": self.current_directory,
            "command_count": self.command_count,
        }

    def import_state(self, state: dict) -> None:
        if state.get("current_directory") != "/workspace":
            raise ValueError("fake shell directory is invalid")
        command_count = state.get("command_count")
        if not isinstance(command_count, int) or command_count < 0:
            raise ValueError("fake shell command count is invalid")
        self.current_directory = "/workspace"
        self.command_count = command_count

    def state_digest(self) -> str:
        return sha256_digest(self.export_state())

    def run(self, command: str):
        from app.tools.base import ToolResult

        self.command_count += 1

        if not command or len(command) > self.max_command_length:
            return ToolResult(allowed=False, outcome="rejected", error="invalid command")
        lowered = command.casefold()
        if any(marker in lowered for marker in ("curl ", "wget ", "nc ", "http://", "https://")):
            return ToolResult(
                allowed=False,
                outcome="rejected",
                error="network commands are disabled",
                risk_category="network_egress",
            )
        if any(marker in lowered for marker in ("rm -rf", "del /s", "format ", "mkfs")):
            return ToolResult(
                allowed=False,
                outcome="rejected",
                error="destructive command blocked",
                risk_category="destructive_command",
            )
        try:
            parts = shlex.split(command, posix=True)
        except ValueError:
            return ToolResult(allowed=False, outcome="rejected", error="invalid command syntax")
        if parts and parts[0] == "echo":
            return ToolResult(allowed=True, outcome="succeeded", output=" ".join(parts[1:]))
        if parts and parts[0] == "pwd":
            return ToolResult(allowed=True, outcome="succeeded", output="/workspace")
        return ToolResult(
            allowed=False,
            outcome="rejected",
            error="command not in fake-shell allowlist",
        )
