"""Tool-window correlation between behavior features and risk evidence."""

from __future__ import annotations

from sandbox.coverage.events import iter_tool_windows
from sandbox.coverage.models import (
    BehaviorProfile,
    BehaviorRiskLink,
    CoverageInput,
    RiskHit,
)


class BehaviorRiskCorrelator:
    """Associate behavior and risk only when both belong to the same tool window."""

    def correlate(
        self,
        coverage_input: CoverageInput,
        profile: BehaviorProfile,
        hits: list[RiskHit],
        *,
        new_behavior_keys: set[tuple[str, str]],
        new_risk_categories: set[str],
        improved_risk_categories: set[str],
    ) -> list[BehaviorRiskLink]:
        windows = iter_tool_windows(coverage_input.events)
        grouped: dict[tuple[str, str, str, int], dict[str, object]] = {}

        for hit in hits:
            risk_sequences = {
                reference.event_sequence
                for reference in hit.evidence
                if reference.source == "trace_event" and reference.event_sequence is not None
            }
            if not risk_sequences:
                continue
            for window in windows:
                window_sequences = set(window.evidence_sequences)
                risk_overlap = risk_sequences & window_sequences
                if not risk_overlap:
                    continue
                for feature in profile.features:
                    behavior_overlap = set(feature.source_sequences) & window_sequences
                    if not behavior_overlap:
                        continue
                    key = (
                        feature.kind.value,
                        feature.value,
                        hit.category_id,
                        window.call_sequence,
                    )
                    aggregate = grouped.setdefault(
                        key,
                        {
                            "tool_name": window.tool_name,
                            "behavior_sequences": set(),
                            "risk_depth": 0,
                            "risk_recognizers": set(),
                            "risk_sequences": set(),
                        },
                    )
                    behavior_sequences = aggregate["behavior_sequences"]
                    risk_recognizers = aggregate["risk_recognizers"]
                    aggregate_risk_sequences = aggregate["risk_sequences"]
                    assert isinstance(behavior_sequences, set)
                    assert isinstance(risk_recognizers, set)
                    assert isinstance(aggregate_risk_sequences, set)
                    behavior_sequences.update(behavior_overlap)
                    risk_recognizers.add(hit.recognizer)
                    aggregate_risk_sequences.update(risk_overlap)
                    aggregate["risk_depth"] = max(int(aggregate["risk_depth"]), hit.depth)

        links: list[BehaviorRiskLink] = []
        for (kind, value, category_id, call_sequence), aggregate in sorted(grouped.items()):
            behavior_new = (kind, value) in new_behavior_keys
            risk_new = category_id in new_risk_categories
            novelty_class = (
                "both_new"
                if behavior_new and risk_new
                else "behavior_new"
                if behavior_new
                else "risk_new"
                if risk_new
                else "known_pair"
            )
            links.append(
                BehaviorRiskLink(
                    tool_name=str(aggregate["tool_name"]),
                    tool_call_sequence=call_sequence,
                    behavior_kind=kind,
                    behavior_value=value,
                    behavior_source_sequences=sorted(aggregate["behavior_sequences"]),
                    risk_category_id=category_id,
                    risk_depth=int(aggregate["risk_depth"]),
                    risk_recognizers=sorted(aggregate["risk_recognizers"]),
                    risk_evidence_sequences=sorted(aggregate["risk_sequences"]),
                    behavior_new=behavior_new,
                    risk_new=risk_new,
                    risk_depth_improved=category_id in improved_risk_categories,
                    novelty_class=novelty_class,
                )
            )
        return links
