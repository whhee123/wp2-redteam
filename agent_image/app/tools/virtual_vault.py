"""Virtual secret store with explicit production-secret denial."""

from __future__ import annotations

from sandbox.replay.digests import sha256_digest


class VirtualVault:
    def __init__(self) -> None:
        self.access_count = 0
        self._public_values = {"demo-token": "synthetic-demo-token"}

    def export_state(self) -> dict:
        return {"access_count": self.access_count, "fixture_version": "virtual-vault-v1"}

    def import_state(self, state: dict) -> None:
        if state.get("fixture_version") != "virtual-vault-v1":
            raise ValueError("virtual vault fixture version is incompatible")
        access_count = state.get("access_count")
        if not isinstance(access_count, int) or access_count < 0:
            raise ValueError("virtual vault access count is invalid")
        self.access_count = access_count

    def state_digest(self) -> str:
        return sha256_digest(self.export_state())

    def retrieve(self, secret_id: str):
        from app.tools.base import ToolResult

        self.access_count += 1
        if secret_id not in self._public_values:
            return ToolResult(
                allowed=False,
                outcome="rejected",
                error="restricted credential access blocked",
                risk_category="credential_disclosure",
            )
        return ToolResult(
            allowed=True,
            outcome="succeeded",
            output={"secret_id": secret_id, "value": self._public_values[secret_id]},
        )
