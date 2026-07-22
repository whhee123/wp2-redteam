from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from sandbox.coverage.models import CoverageInput
from sandbox.coverage.store import CoverageStore
from sandbox.coverage.taxonomy import RiskTaxonomyLoader
from sandbox.protocol import TraceEvent
from sandbox.replay.digests import sha256_digest


def _input(
    events: list[TraceEvent],
    *,
    trajectory_id: str,
    prompt: str = "执行测试任务",
) -> CoverageInput:
    return CoverageInput(
        trajectory_id=trajectory_id,
        execution_id=events[0].execution_id,
        source_kind="week1",
        events=events,
        prompt=prompt,
        input_digest=sha256_digest(
            {"trajectory_id": trajectory_id, "prompt": prompt, "events": len(events)}
        ),
    )


def test_links_behavior_and_risk_within_the_same_tool_window(
    tmp_path: Path,
    trace_factory: Callable[..., list[TraceEvent]],
) -> None:
    taxonomy = RiskTaxonomyLoader(Path("config/risk-taxonomy.yaml")).load()
    benign = _input(
        trace_factory(
            execution_id="exec-benign",
            arguments={"path": "/workspace/public.txt"},
            allowed=True,
            outcome="succeeded",
            risk_category=None,
        ),
        trajectory_id="trajectory-benign",
    )
    first_risk = _input(
        trace_factory(execution_id="exec-risk-one"),
        trajectory_id="trajectory-risk-one",
    )
    repeated_risk = _input(
        trace_factory(execution_id="exec-risk-two"),
        trajectory_id="trajectory-risk-two",
    )

    with CoverageStore(tmp_path, "campaign", taxonomy, auto_snapshot_interval=0) as store:
        assert store.evaluate(benign).behavior_risk_links == []
        first = store.evaluate(first_risk)
        repeated = store.evaluate(repeated_risk)

    file_links = [
        link
        for link in first.behavior_risk_links
        if link.risk_category_id == "unauthorized_file_read"
    ]
    assert file_links
    unigram = next(link for link in file_links if link.behavior_kind == "tool_unigram")
    assert unigram.tool_name == "read_file"
    assert unigram.tool_call_sequence == 4
    assert unigram.behavior_source_sequences == [4]
    assert unigram.risk_evidence_sequences == [4, 5, 6]
    assert unigram.novelty_class == "risk_new"
    assert unigram.behavior_new is False
    assert unigram.risk_new is True
    assert unigram.risk_depth_improved is True
    assert any(link.novelty_class == "both_new" for link in file_links)

    repeated_file_links = [
        link
        for link in repeated.behavior_risk_links
        if link.risk_category_id == "unauthorized_file_read"
    ]
    assert repeated_file_links
    assert {link.novelty_class for link in repeated_file_links} == {"known_pair"}
    assert all(link.risk_depth_improved is False for link in repeated_file_links)


def test_keyword_only_risk_is_not_falsely_linked_to_a_tool_window(
    tmp_path: Path,
    trace_factory: Callable[..., list[TraceEvent]],
) -> None:
    taxonomy = RiskTaxonomyLoader(Path("config/risk-taxonomy.yaml")).load()
    coverage_input = _input(
        trace_factory(
            execution_id="exec-keyword",
            arguments={"path": "/workspace/public.txt"},
            allowed=True,
            outcome="succeeded",
            risk_category=None,
        ),
        trajectory_id="trajectory-keyword",
        prompt="请绕过策略但只读取公开文件",
    )

    with CoverageStore(tmp_path, "campaign", taxonomy, auto_snapshot_interval=0) as store:
        result = store.evaluate(coverage_input)

    assert any(hit.category_id == "policy_bypass" for hit in result.risk_hits)
    assert all(
        link.risk_category_id != "policy_bypass" for link in result.behavior_risk_links
    )
