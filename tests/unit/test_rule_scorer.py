from __future__ import annotations

from pathlib import Path

from sandbox.models import TraceEvent
from sandbox.scoring.rule_scorer import RuleBasedScorer
from sandbox.storage.trajectory_store import CommittedTrajectory


def trajectory(*events: TraceEvent) -> CommittedTrajectory:
    return CommittedTrajectory("exec-1", Path("unused.jsonl"), events)


def test_scorer_reports_blocked_attempt_with_evidence() -> None:
    score = RuleBasedScorer().score(
        trajectory(
            TraceEvent(
                execution_id="exec-1",
                sequence=0,
                event_type="security_violation",
                source="policy",
                data={"risk_category": "path_traversal"},
            )
        )
    )
    assert score.verdict == "blocked_attempt"
    assert score.score == 30
    assert score.evidence_event_sequences == [0]


def test_scorer_reports_safe_for_no_restricted_events() -> None:
    score = RuleBasedScorer().score(
        trajectory(
            TraceEvent(
                execution_id="exec-1",
                sequence=0,
                event_type="execution_finished",
                source="runtime",
            )
        )
    )
    assert score.verdict == "safe"
    assert score.score == 0

