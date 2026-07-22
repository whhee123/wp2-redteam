"""Deterministic behavior feature extraction."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from sandbox.coverage.events import (
    event_data,
    event_sequence,
    event_source,
    event_type,
    iter_tool_windows,
    terminal_kind,
)
from sandbox.coverage.feature_normalizer import value_shape
from sandbox.coverage.models import BehaviorFeature, BehaviorFeatureKind, BehaviorProfile
from sandbox.replay.digests import sha256_digest


class BehaviorFeatureExtractor:
    def __init__(self, *, max_features: int = 500) -> None:
        self.max_features = max_features

    def extract(
        self,
        *,
        trajectory_id: str,
        execution_id: str,
        events: list[dict[str, Any]],
    ) -> BehaviorProfile:
        collected: dict[tuple[BehaviorFeatureKind, str], list[int]] = defaultdict(list)
        frequencies: dict[tuple[BehaviorFeatureKind, str], int] = defaultdict(int)

        def add(kind: BehaviorFeatureKind, value: str, sequences: list[int]) -> None:
            if not value:
                return
            key = (kind, value)
            collected[key].extend(sequence for sequence in sequences if sequence >= 0)
            frequencies[key] += 1

        tool_calls = [event for event in events if event_type(event) == "tool_call"]
        tool_names = [str(event_data(event).get("name", "")) for event in tool_calls]
        tool_sequences = [event_sequence(event) for event in tool_calls]

        for name, sequence in zip(tool_names, tool_sequences, strict=True):
            add(BehaviorFeatureKind.TOOL_UNIGRAM, name, [sequence])

        for size, kind in (
            (2, BehaviorFeatureKind.TOOL_BIGRAM),
            (3, BehaviorFeatureKind.TOOL_TRIGRAM),
        ):
            for index in range(len(tool_names) - size + 1):
                add(
                    kind,
                    "→".join(tool_names[index : index + size]),
                    tool_sequences[index : index + size],
                )

        nodes: list[tuple[str, int]] = []
        for event in events:
            if event_type(event) != "node_start":
                continue
            node = event_source(event).removeprefix("langgraph.")
            if not node or (nodes and nodes[-1][0] == node):
                continue
            nodes.append((node, event_sequence(event)))
        for (left, left_sequence), (right, right_sequence) in zip(
            nodes, nodes[1:], strict=False
        ):
            add(BehaviorFeatureKind.NODE_EDGE, f"{left}→{right}", [left_sequence, right_sequence])

        security_states = ["normal"]
        windows = iter_tool_windows(events)
        for window in windows:
            result = window.result or {}
            allowed = result.get("allowed")
            outcome = str(result.get("outcome", ""))
            risk_category = result.get("risk_category")
            if allowed is False or window.security_categories:
                state = "blocked"
            elif allowed is True and outcome in {"success", "succeeded"} and risk_category:
                state = "risky_success"
            else:
                state = "normal"
            security_states.append(state)

            if allowed is False:
                result_kind = "blocked"
            elif outcome in {"success", "succeeded"}:
                result_kind = "succeeded"
            elif outcome == "not_found":
                result_kind = "not_found"
            else:
                result_kind = "error"
            add(
                BehaviorFeatureKind.TOOL_RESULT,
                f"{window.tool_name}:{result_kind}",
                window.evidence_sequences,
            )

            shapes = [
                f"{name}={value_shape(name, value)}"
                for name, value in sorted(window.arguments.items())
            ]
            shape_value = f"{window.tool_name}:" + (",".join(shapes) if shapes else "<NO_ARGS>")
            add(
                BehaviorFeatureKind.PARAM_SHAPE,
                shape_value,
                [window.call_sequence],
            )

        if security_states[-1] != "normal":
            security_states.append("normal")
        for left, right in zip(security_states, security_states[1:], strict=False):
            if left != right:
                add(BehaviorFeatureKind.SECURITY_TRANSITION, f"{left}→{right}", [])

        terminal_sequences = [
            event_sequence(event) for event in events if event_type(event).startswith("execution_")
        ]
        add(
            BehaviorFeatureKind.TERMINATION,
            terminal_kind(events),
            terminal_sequences[-1:] if terminal_sequences else [],
        )

        features = [
            BehaviorFeature(
                kind=kind,
                value=value,
                source_sequences=sorted(set(sequences)),
                frequency=frequencies[(kind, value)],
            )
            for (kind, value), sequences in sorted(
                collected.items(), key=lambda item: (item[0][0].value, item[0][1])
            )
        ]
        if len(features) > self.max_features:
            features = features[: self.max_features]
        profile_payload = [
            {"kind": feature.kind.value, "value": feature.value}
            for feature in features
        ]
        return BehaviorProfile(
            trajectory_id=trajectory_id,
            execution_id=execution_id,
            features=features,
            profile_hash=sha256_digest(profile_payload),
            feature_count=len(features),
        )
