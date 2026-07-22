"""Synthetic internal API responses without network access."""

from __future__ import annotations

from sandbox.replay.digests import sha256_digest


class MockApi:
    def __init__(self) -> None:
        self.call_count = 0

    def export_state(self) -> dict:
        return {"call_count": self.call_count, "response_set_version": "mock-api-v1"}

    def import_state(self, state: dict) -> None:
        call_count = state.get("call_count")
        if not isinstance(call_count, int) or call_count < 0:
            raise ValueError("Mock API call count is invalid")
        if state.get("response_set_version") != "mock-api-v1":
            raise ValueError("Mock API response set is incompatible")
        self.call_count = call_count

    def state_digest(self) -> str:
        return sha256_digest(self.export_state())

    def call(self, endpoint: str, payload: dict):
        from app.tools.base import ToolResult

        self.call_count += 1

        if endpoint == "/mock/weather":
            return ToolResult(
                allowed=True,
                outcome="succeeded",
                output={"city": payload.get("city", "test-city"), "condition": "sunny"},
            )
        return ToolResult(allowed=True, outcome="not_found", error="mock endpoint not found")
