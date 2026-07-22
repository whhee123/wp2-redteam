from __future__ import annotations

from pathlib import Path

from app.adapter.langgraph_adapter import LangGraphAdapter
from app.protocol import ExecutionRequest

from sandbox.coverage.input import CoverageInputResolver
from sandbox.coverage.store import CoverageStore
from sandbox.coverage.taxonomy import RiskTaxonomyLoader
from sandbox.engine.case_source import TemplateCaseSource


async def test_all_week_one_templates_flow_into_cumulative_coverage(tmp_path: Path) -> None:
    source = TemplateCaseSource()
    trajectory_root = tmp_path / "trajectories"
    trajectory_root.mkdir()
    resolver = CoverageInputResolver(
        trajectory_root=trajectory_root,
        manifest_root=tmp_path / "replays",
        artifact_root=tmp_path / "artifacts",
        case_source=source,
    )
    taxonomy = RiskTaxonomyLoader(Path("config/risk-taxonomy.yaml")).load()
    cumulative_counts: list[int] = []
    results = {}

    with CoverageStore(
        tmp_path / "coverage",
        "week3-integration",
        taxonomy,
        auto_snapshot_interval=0,
    ) as store:
        for index, template_id in enumerate(source.template_ids):
            case = source.generate(template_id, seed=42)
            request = ExecutionRequest(
                execution_id=f"exec-coverage-{index}",
                case_id=case.case_id,
                prompt=case.prompt,
                scenario_id=case.scenario_id,
                agent_version="fake-langgraph-agent-v1",
                max_steps=3,
            )
            events = [event async for event in LangGraphAdapter().execute(request)]
            path = trajectory_root / f"{request.execution_id}.jsonl"
            path.write_text(
                "".join(event.model_dump_json() + "\n" for event in events),
                encoding="utf-8",
            )
            result = store.evaluate(resolver.from_trajectory_path(path))
            results[template_id] = result
            cumulative_counts.append(result.cumulative_behavior_count)
            assert result.behavior_features_total > 0

        assert cumulative_counts == sorted(cumulative_counts)
        assert all(
            hit.depth < 2 for hit in results["benign-control-001"].risk_hits
        )
        assert any(
            hit.category_id == "unauthorized_file_read" and hit.depth == 2
            for hit in results["path-absolute-001"].risk_hits
        )
        assert any(
            hit.category_id == "unauthorized_network_access" and hit.depth == 2
            for hit in results["network-egress-001"].risk_hits
        )
        assert store.snapshot().total_trajectories == len(source.template_ids)
