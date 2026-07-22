"""Tool decorators for recording, strict execution verification, and stubbing."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from app.tools.base import ToolResult
from sandbox.protocol import ToolReplayMode
from sandbox.replay.digests import sha256_digest
from sandbox.replay.exceptions import ReplayDivergenceError
from sandbox.replay.models import RecordedToolInteraction


class ToolRecorder:
    def __init__(self, tools, *, replay_mode: ToolReplayMode) -> None:
        self.tools = tools
        self.replay_mode = replay_mode
        self.interactions: list[RecordedToolInteraction] = []
        self._sequence = 0
        self._before_checkpoint_id = "unbound"

    def set_context(self, *, sequence: int, before_checkpoint_id: str) -> None:
        self._sequence = sequence
        self._before_checkpoint_id = before_checkpoint_id

    def execute(self, action: dict[str, Any]) -> ToolResult:
        name = str(action.get("name", ""))
        arguments = action.get("arguments") or {}
        before_digest = self.tools.state_digest()
        result = self.tools.execute(action)
        result_payload = result.to_dict()
        after_digest = self.tools.state_digest()
        self.interactions.append(
            RecordedToolInteraction(
                interaction_id=f"interaction-{uuid4().hex}",
                sequence=self._sequence,
                interaction_index=len(self.interactions),
                before_checkpoint_id=self._before_checkpoint_id,
                tool_name=name,
                arguments=arguments,
                arguments_digest=sha256_digest(arguments),
                result=result_payload,
                result_digest=sha256_digest(result_payload),
                replay_mode=self.replay_mode,
                policy_decision="allowed" if result.allowed else "blocked",
                side_effect_digest_before=before_digest,
                side_effect_digest_after=after_digest,
            )
        )
        return result

    def attach_after_checkpoint(self, checkpoint_id: str) -> None:
        if not self.interactions:
            raise RuntimeError("no tool interaction is available")
        self.interactions[-1] = self.interactions[-1].model_copy(
            update={"after_checkpoint_id": checkpoint_id}
        )

    def export_state(self) -> dict[str, Any]:
        return self.tools.export_state()

    def import_state(self, state: dict[str, Any]) -> None:
        self.tools.import_state(state)

    def state_digest(self) -> str:
        return self.tools.state_digest()

    @property
    def filesystem(self):
        return self.tools.filesystem

    @property
    def shell(self):
        return self.tools.shell

    @property
    def api(self):
        return self.tools.api


class ToolReplayer:
    def __init__(
        self,
        tools,
        records: list[RecordedToolInteraction],
        *,
        start_index: int = 0,
    ) -> None:
        self.tools = tools
        self.records = records
        self.next_index = start_index
        self.last_record: RecordedToolInteraction | None = None

    def execute(self, action: dict[str, Any]) -> ToolResult:
        if self.next_index >= len(self.records):
            raise ReplayDivergenceError(-32107, "recorded tool interactions are exhausted")
        record = self.records[self.next_index]
        name = str(action.get("name", ""))
        arguments = action.get("arguments") or {}
        if record.interaction_index != self.next_index:
            raise ReplayDivergenceError(-32102, "tool interaction index is not contiguous")
        if record.tool_name != name or record.arguments_digest != sha256_digest(arguments):
            raise ReplayDivergenceError(-32107, "tool call diverged")
        if record.replay_mode == ToolReplayMode.EXECUTE_AND_VERIFY:
            before_digest = self.tools.state_digest()
            result = self.tools.execute(action)
            after_digest = self.tools.state_digest()
            if (
                sha256_digest(result.to_dict()) != record.result_digest
                or before_digest != record.side_effect_digest_before
                or after_digest != record.side_effect_digest_after
            ):
                raise ReplayDivergenceError(-32107, "tool result or side effect diverged")
        else:
            if not isinstance(record.result, dict):
                raise ReplayDivergenceError(-32107, "stubbed tool result is invalid")
            if record.side_effect_digest_before != record.side_effect_digest_after:
                raise ReplayDivergenceError(-32107, "stateful stub requires a state delta")
            result = ToolResult(**record.result)
        self.next_index += 1
        self.last_record = record
        return result

    def assert_consumed(self) -> None:
        if self.next_index != len(self.records):
            raise ReplayDivergenceError(-32108, "recorded tool interactions remain unconsumed")

    def export_state(self) -> dict[str, Any]:
        return self.tools.export_state()

    def import_state(self, state: dict[str, Any]) -> None:
        self.tools.import_state(state)

    def state_digest(self) -> str:
        return self.tools.state_digest()
