from __future__ import annotations

import os
from pathlib import Path

import docker
import pytest

from sandbox.client.runtime_client import RuntimeClient
from sandbox.config import SandboxConfig, TraceConfig, WeekOneConfig
from sandbox.coverage.heatmap import HeatmapGenerator
from sandbox.coverage.input import CoverageInputResolver
from sandbox.coverage.risk_scope import CampaignRiskScopeLoader
from sandbox.coverage.store import CoverageStore
from sandbox.coverage.taxonomy import RiskTaxonomyLoader
from sandbox.engine.case_source import TemplateCaseSource
from sandbox.engine.execution_engine import RedTeamExecutionEngine
from sandbox.scheduler.docker_scheduler import DockerSandboxScheduler
from sandbox.scoring.rule_scorer import RuleBasedScorer

pytestmark = pytest.mark.skipif(
    os.getenv("TRACE_G_RUN_DOCKER_E2E") != "1",
    reason="set TRACE_G_RUN_DOCKER_E2E=1 to run Docker coverage tests",
)


async def test_all_templates_produce_cumulative_coverage_in_real_containers(
    tmp_path: Path,
) -> None:
    image = os.getenv("TRACE_G_COVERAGE_IMAGE", "trace-redteam-agent:week3")
    source = TemplateCaseSource()
    trajectory_root = tmp_path / "trajectories"
    config = WeekOneConfig(
        sandbox=SandboxConfig(image=image, execution_timeout_seconds=30),
        tracing=TraceConfig(output_dir=trajectory_root, pull_interval_seconds=0.05),
    )
    docker_client = docker.from_env()
    scheduler = DockerSandboxScheduler(config.sandbox, client=docker_client)
    engine = RedTeamExecutionEngine(
        config,
        scheduler,
        RuntimeClient(config.tracing, docker_client=docker_client),
        RuleBasedScorer(),
        source,
    )
    taxonomy = RiskTaxonomyLoader(Path("config/risk-taxonomy.yaml")).load()
    risk_scope = CampaignRiskScopeLoader(
        Path("config/risk-scope-week3.yaml"), taxonomy
    ).load()
    resolver = CoverageInputResolver(
        trajectory_root=trajectory_root,
        manifest_root=tmp_path / "replays",
        artifact_root=tmp_path / "artifacts",
        case_source=source,
    )

    with CoverageStore(
        tmp_path / "coverage",
        "docker-week3",
        taxonomy,
        risk_scope=risk_scope,
        auto_snapshot_interval=0,
    ) as store:
        linked_categories: set[str] = set()
        for template_id in source.template_ids:
            outcome = await engine.run_case(template_id, seed=42)
            assert outcome.container_removed is True
            assert outcome.trajectory_path is not None
            coverage_input = resolver.from_trajectory_path(outcome.trajectory_path)
            result = store.evaluate(coverage_input)
            assert result.behavior_features_total > 0
            linked_categories.update(
                link.risk_category_id for link in result.behavior_risk_links
            )

        snapshot = store.snapshot()
        assert snapshot.total_trajectories == len(source.template_ids)
        assert snapshot.total_features > 0
        assert snapshot.behavior_coverage > 0
        assert set(snapshot.risk_depths) == set(taxonomy.leaf_ids)
        assert all(0 <= depth <= 3 for depth in snapshot.risk_depths.values())
        assert snapshot.risk_depths["unauthorized_file_read"] == 2
        assert snapshot.applicable_intent_coverage == 1.0
        assert snapshot.applicable_behavior_coverage == 1.0
        assert snapshot.applicable_impact_coverage is None
        assert len(snapshot.not_applicable_risk_categories) == 14
        assert snapshot.uncovered_intent_categories == []
        assert snapshot.uncovered_behavior_categories == []
        assert snapshot.scope_exceeded_categories == {}
        assert "unauthorized_file_read" in linked_categories
        assert "destructive_command" in linked_categories

        pretty = HeatmapGenerator(taxonomy).generate_pretty(
            "docker-week3",
            store.all_profiles(),
            store.all_hits(),
        )
        assert pretty.rows
        assert pretty.columns
        assert pretty.cells
        assert all(row.trajectory_ids for row in pretty.rows)
        assert all(cell.risk_category_label for cell in pretty.cells)

    leftovers = docker_client.containers.list(
        all=True,
        filters={"label": "trace-g.component=agent-sandbox"},
    )
    assert leftovers == []
