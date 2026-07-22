"""Versioned registry for deterministic controlled tools."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from pydantic import ValidationError

from app.tools.enterprise_host import SyntheticHost
from app.tools.fake_database import FakeDatabase
from app.tools.fake_filesystem import VirtualFileSystem
from app.tools.fake_mailbox import FakeMailbox
from app.tools.fake_shell import FakeShell
from app.tools.mock_api import MockApi
from app.tools.synthetic_network import SyntheticNetwork
from app.tools.virtual_vault import VirtualVault
from sandbox.replay.digests import sha256_digest
from sandbox.tool_contracts import TOOL_SPEC_BY_NAME, TOOL_SPECS, ToolSpec
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
        self.host = SyntheticHost()
        self.database = FakeDatabase()
        self.mailbox = FakeMailbox()
        self.network = SyntheticNetwork()
        self.vault = VirtualVault()
        self._legacy_state_mode = False

    @property
    def specs(self) -> tuple[ToolSpec, ...]:
        return TOOL_SPECS

    def get_spec(self, name: str) -> ToolSpec | None:
        return TOOL_SPEC_BY_NAME.get(name)

    def export_state(self) -> dict[str, Any]:
        state = {
            "virtual_filesystem_state": self.filesystem.export_state(),
            "fake_shell_state": self.shell.export_state(),
            "mock_api_state": self.api.export_state(),
        }
        if not self._legacy_state_mode:
            state["enterprise_tool_state"] = {
                "registry_version": self.version,
                "host": self.host.export_state(),
                "database": self.database.export_state(),
                "mailbox": self.mailbox.export_state(),
                "network": self.network.export_state(),
                "vault": self.vault.export_state(),
            }
        return state

    def import_state(self, state: dict[str, Any]) -> None:
        self.filesystem.import_state(state["virtual_filesystem_state"])
        self.shell.import_state(state["fake_shell_state"])
        self.api.import_state(state["mock_api_state"])
        enterprise = state.get("enterprise_tool_state")
        if enterprise is None or enterprise.get("legacy_mode") is True:
            self._legacy_state_mode = True
            return
        if enterprise.get("registry_version") != self.version:
            raise ValueError("enterprise tool registry version is incompatible")
        self.host.import_state(enterprise["host"])
        self.database.import_state(enterprise["database"])
        self.mailbox.import_state(enterprise["mailbox"])
        self.network.import_state(enterprise["network"])
        self.vault.import_state(enterprise["vault"])
        self._legacy_state_mode = False

    def state_digest(self) -> str:
        return sha256_digest(self.export_state())

    def execute(self, action: dict[str, Any]) -> ToolResult:
        name = action.get("name")
        if not isinstance(name, str):
            return ToolResult(allowed=False, outcome="rejected", error="invalid tool name")
        spec = self.get_spec(name)
        if spec is None:
            return ToolResult(allowed=False, outcome="rejected", error="unknown tool")
        arguments = action.get("arguments") or {}
        try:
            parsed = spec.validate_arguments(arguments)
        except ValidationError as exc:
            return ToolResult(
                allowed=False,
                outcome="rejected",
                error=f"invalid tool arguments: {exc.errors()[0]['msg']}",
            )
        values = parsed.model_dump(mode="python")

        if name == "read_file":
            return self.filesystem.read_file(values["path"])
        if name == "write_file":
            return self.filesystem.write_file(values["path"], values["content"])
        if name == "run_command":
            return self.shell.run(values["command"])
        if name == "call_internal_api":
            return self.api.call(values["endpoint"], values["payload"])
        if name == "list_directory":
            return self.filesystem.list_directory(values["path"])
        if name == "search_files":
            return self.filesystem.search_files(
                values["query"],
                values["root"],
                values["max_results"],
            )
        if name == "read_environment":
            return self.host.read_environment(values["name"])
        if name == "list_processes":
            return self.host.list_processes()
        if name == "query_database":
            return self.database.query(**values)
        if name == "send_email":
            return self.mailbox.send(values["to"], values["subject"], values["body"])
        if name == "http_request":
            return self.network.request(values["method"], values["url"], values["body"])
        if name == "retrieve_secret":
            return self.vault.retrieve(values["secret_id"])
        raise AssertionError(f"registered tool has no handler: {name}")