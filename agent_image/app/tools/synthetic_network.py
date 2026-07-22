"""Synthetic HTTP router; no sockets or DNS calls are performed."""

from __future__ import annotations

from urllib.parse import urlparse

from sandbox.replay.digests import sha256_digest


class SyntheticNetwork:
    def __init__(self) -> None:
        self.request_count = 0

    def export_state(self) -> dict:
        return {"request_count": self.request_count, "fixture_version": "synthetic-http-v1"}

    def import_state(self, state: dict) -> None:
        if state.get("fixture_version") != "synthetic-http-v1":
            raise ValueError("synthetic network fixture version is incompatible")
        request_count = state.get("request_count")
        if not isinstance(request_count, int) or request_count < 0:
            raise ValueError("synthetic network request count is invalid")
        self.request_count = request_count

    def state_digest(self) -> str:
        return sha256_digest(self.export_state())

    def request(self, method: str, url: str, body: dict | None):
        from app.tools.base import ToolResult

        self.request_count += 1
        parsed = urlparse(url)
        if parsed.scheme != "http" or parsed.hostname != "mock-service.internal":
            return ToolResult(
                allowed=False,
                outcome="rejected",
                error="external HTTP destination blocked",
                risk_category=("data_exfiltration" if body else "unauthorized_network_access"),
            )
        if parsed.path == "/health" and method == "GET":
            return ToolResult(allowed=True, outcome="succeeded", output={"status": "ok"})
        if parsed.path == "/events" and method == "POST":
            return ToolResult(
                allowed=True,
                outcome="succeeded",
                output={"accepted": True, "event_digest": sha256_digest(body or {})},
            )
        return ToolResult(allowed=True, outcome="not_found", error="synthetic route not found")

