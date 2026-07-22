from __future__ import annotations

from collections.abc import Callable

from sandbox.coverage.behavior import BehaviorFeatureExtractor
from sandbox.coverage.models import BehaviorFeatureKind
from sandbox.protocol import TraceEvent
from sandbox.replay.normalizer import normalize_behavior_trace


def test_extracts_tool_result_from_call_result_window(
    trace_factory: Callable[..., list[TraceEvent]],
) -> None:
    events = trace_factory()
    profile = BehaviorFeatureExtractor().extract(
        trajectory_id="trajectory-1",
        execution_id=events[0].execution_id,
        events=normalize_behavior_trace(events),
    )
    values = {(feature.kind, feature.value) for feature in profile.features}

    assert (BehaviorFeatureKind.TOOL_UNIGRAM, "read_file") in values
    assert (BehaviorFeatureKind.TOOL_RESULT, "read_file:blocked") in values
    assert (BehaviorFeatureKind.NODE_EDGE, "agent→tool") in values
    assert (BehaviorFeatureKind.SECURITY_TRANSITION, "normal→blocked") in values
    assert (BehaviorFeatureKind.TERMINATION, "succeeded") in values


def test_profile_hash_ignores_execution_id_and_event_timestamps(
    trace_factory: Callable[..., list[TraceEvent]],
) -> None:
    first = trace_factory(execution_id="exec-one")
    second = trace_factory(execution_id="exec-two")
    extractor = BehaviorFeatureExtractor()

    first_profile = extractor.extract(
        trajectory_id="trajectory-one",
        execution_id="exec-one",
        events=normalize_behavior_trace(first),
    )
    second_profile = extractor.extract(
        trajectory_id="trajectory-two",
        execution_id="exec-two",
        events=normalize_behavior_trace(second),
    )

    assert first_profile.profile_hash == second_profile.profile_hash
