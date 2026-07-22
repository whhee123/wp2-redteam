"""Registry for virtual filesystem, fake shell, and Mock API tools."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from app.tools.fake_filesystem import VirtualFileSystem
from app.tools.fake_shell import FakeShell
from app.tools.mock_api import MockApi
from sandbox.replay.digests import sha256_digest
from sandbox.versions import TOOL_REGISTRY_VERSION


@dataclass(frozen=True)
class ToolResult:
    allowed: bool
    outcome: str
    output: Any = None
    error: str | None = None
    risk_category: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ToolRegistry:
    version = TOOL_REGISTRY_VERSION

    def __init__(self) -> None:
        self.filesystem = VirtualFileSystem()
        self.shell = FakeShell()
        self.api = MockApi()

    def export_state(self) -> dict[str, Any]:
        return {
            "virtual_filesystem_state": self.filesystem.export_state(),
            "fake_shell_state": self.shell.export_state(),
            "mock_api_state": self.api.export_state(),
        }

    def import_state(self, state: dict[str, Any]) -> None:
        self.filesystem.import_state(state["virtual_filesystem_state"])
        self.shell.import_state(state["fake_shell_state"])
        self.api.import_state(state["mock_api_state"])

    def state_digest(self) -> str:
        return sha256_digest(self.export_state())

    def execute(self, action: dict[str, Any]) -> ToolResult:
        name = action.get("name")
        arguments = action.get("arguments") or {}
        if name == "read_file":
            return self.filesystem.read_file(str(arguments.get("path", "")))
        if name == "write_file":
            return self.filesystem.write_file(
                str(arguments.get("path", "")),
                str(arguments.get("content", "")),
            )
        if name == "run_command":
            return self.shell.run(str(arguments.get("command", "")))
        if name == "call_internal_api":
            return self.api.call(
                str(arguments.get("endpoint", "")),
                arguments.get("payload") or {},
            )
        return ToolResult(allowed=False, outcome="rejected", error="unknown tool")
