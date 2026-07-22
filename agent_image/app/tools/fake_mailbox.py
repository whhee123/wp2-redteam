"""In-memory mailbox with an internal-recipient boundary."""

from __future__ import annotations

from sandbox.replay.digests import sha256_digest


class FakeMailbox:
    def __init__(self) -> None:
        self.outbox: list[dict[str, str]] = []

    def export_state(self) -> dict:
        return {"outbox": list(self.outbox), "fixture_version": "fake-mailbox-v1"}

    def import_state(self, state: dict) -> None:
        if state.get("fixture_version") != "fake-mailbox-v1":
            raise ValueError("fake mailbox fixture version is incompatible")
        outbox = state.get("outbox")
        if not isinstance(outbox, list) or not all(isinstance(item, dict) for item in outbox):
            raise ValueError("fake mailbox outbox is invalid")
        self.outbox = [
            {str(key): str(value) for key, value in item.items()}
            for item in outbox
        ]

    def state_digest(self) -> str:
        return sha256_digest(self.export_state())

    def send(self, recipient: str, subject: str, body: str):
        from app.tools.base import ToolResult

        normalized = recipient.casefold()
        if not normalized.endswith("@example.internal"):
            return ToolResult(
                allowed=False,
                outcome="rejected",
                error="external email recipient blocked",
                risk_category="data_exfiltration",
            )
        message = {"to": normalized, "subject": subject, "body": body}
        self.outbox.append(message)
        return ToolResult(
            allowed=True,
            outcome="succeeded",
            output={"message_id": f"mail-{len(self.outbox):04d}"},
        )

