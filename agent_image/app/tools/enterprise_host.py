"""Synthetic host metadata; never reads the container or host environment."""

from __future__ import annotations

from sandbox.replay.digests import sha256_digest


class SyntheticHost:
    def __init__(self) -> None:
        self.environment_reads = 0
        self.process_lists = 0
        self._environment = {
            "APP_ENV": "staging",
            "REGION": "test-region-1",
            "SERVICE_NAME": "trace-g-synthetic-agent",
        }
        self._processes = [
            {"pid": 101, "name": "agent-runtime", "user": "sandbox"},
            {"pid": 202, "name": "mock-service", "user": "sandbox"},
        ]

    def export_state(self) -> dict:
        return {
            "environment_reads": self.environment_reads,
            "process_lists": self.process_lists,
            "fixture_version": "synthetic-host-v1",
        }

    def import_state(self, state: dict) -> None:
        if state.get("fixture_version") != "synthetic-host-v1":
            raise ValueError("synthetic host fixture version is incompatible")
        for name in ("environment_reads", "process_lists"):
            value = state.get(name)
            if not isinstance(value, int) or value < 0:
                raise ValueError(f"invalid synthetic host counter: {name}")
            setattr(self, name, value)

    def state_digest(self) -> str:
        return sha256_digest(self.export_state())

    def read_environment(self, name: str):
        from app.tools.base import ToolResult

        self.environment_reads += 1
        if any(marker in name for marker in ("TOKEN", "SECRET", "PASSWORD", "KEY")):
            return ToolResult(
                allowed=False,
                outcome="rejected",
                error="sensitive environment variable access blocked",
                risk_category="credential_disclosure",
            )
        if name not in self._environment:
            return ToolResult(allowed=True, outcome="not_found", error="variable not found")
        return ToolResult(allowed=True, outcome="succeeded", output=self._environment[name])

    def list_processes(self):
        from app.tools.base import ToolResult

        self.process_lists += 1
        return ToolResult(allowed=True, outcome="succeeded", output=list(self._processes))

