"""Compare normalized behavior traces and report the first semantic divergence."""

from __future__ import annotations

from dataclasses import dataclass

from sandbox.protocol import TraceEvent
from sandbox.replay.digests import sha256_digest
from sandbox.replay.normalizer import normalize_behavior_trace


@dataclass(frozen=True)
class BehaviorComparison:
    matched: bool
    source_digest: str
    replay_digest: str
    first_divergence_behavior_index: int | None = None
    source_sequence: int | None = None
    replay_sequence: int | None = None
    reason: str | None = None


class Comparator:
    def compare(self, source: list[TraceEvent], replay: list[TraceEvent]) -> BehaviorComparison:
        source_trace = normalize_behavior_trace(source)
        replay_trace = normalize_behavior_trace(replay)
        source_digest = sha256_digest(source_trace)
        replay_digest = sha256_digest(replay_trace)
        limit = min(len(source_trace), len(replay_trace))
        for index in range(limit):
            source_event = source_trace[index]
            replay_event = replay_trace[index]
            if self._comparable(source_event) != self._comparable(replay_event):
                return BehaviorComparison(
                    matched=False,
                    source_digest=source_digest,
                    replay_digest=replay_digest,
                    first_divergence_behavior_index=index,
                    source_sequence=source_event["source_sequence"],
                    replay_sequence=replay_event["source_sequence"],
                    reason="normalized behavior event differs",
                )
        if len(source_trace) != len(replay_trace):
            source_sequence = (
                source_trace[limit]["source_sequence"]
                if len(source_trace) > limit
                else None
            )
            replay_sequence = (
                replay_trace[limit]["source_sequence"]
                if len(replay_trace) > limit
                else None
            )
            return BehaviorComparison(
                matched=False,
                source_digest=source_digest,
                replay_digest=replay_digest,
                first_divergence_behavior_index=limit,
                source_sequence=source_sequence,
                replay_sequence=replay_sequence,
                reason="normalized behavior trace length differs",
            )
        return BehaviorComparison(
            matched=True,
            source_digest=source_digest,
            replay_digest=replay_digest,
        )

    @staticmethod
    def _comparable(event: dict) -> dict:
        return {key: value for key, value in event.items() if key != "source_sequence"}
