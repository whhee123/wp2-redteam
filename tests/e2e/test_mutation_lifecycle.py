from __future__ import annotations

import os
from pathlib import Path

import docker
import pytest

from sandbox.client.runtime_client import RuntimeClient
from sandbox.config import SandboxConfig, TraceConfig, WeekOneConfig
from sandbox.coverage.input import CoverageInputResolver
from sandbox.coverage.risk_scope import CampaignRiskScopeLoader
from sandbox.coverage.store import CoverageStore
from sandbox.coverage.taxonomy import RiskTaxonomyLoader
from sandbox.engine.case_source import TemplateCaseSource
from sandbox.engine.execution_engine import RedTeamExecutionEngine
from sandbox.mutation.config import MutationConfig
from sandbox.mutation.diversity import DiversityGate
from sandbox.mutation.feedback import MutationFeedbackBuilder
from sandbox.mutation.models import MutationSeed, to_test_case
from sandbox.mutation.mutator import SemanticMutator
from sandbox.mutation.normalizer import prompt_digest
from sandbox.mutation.operators import MutationOperatorRegistryLoader
from sandbox.mutation.priority import MutationPriorityCalculator
from sandbox.mutation.providers.rule_based import RuleBasedMutationProvider
from sandbox.mutation.similarity import CharacterShingleSimilarity
from sandbox.mutation.store import MutationStore
from sandbox.scheduler.docker_scheduler import DockerSandboxScheduler
from sandbox.scoring.rule_scorer import RuleBasedScorer

pytestmark = pytest.mark.skipif(
    os.getenv("TRACE_G_RUN_DOCKER_E2E") != "1",
    reason="set TRACE_G_RUN_DOCKER_E2E=1 to run Docker mutation tests",
)


async def test_mutation_candidate_executes_with_lineage_and_coverage(
    tmp_path: Path,
) -> None:
    image = os.getenv("TRACE_G_MUTATION_IMAGE", "trace-redteam-agent:week4")
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
    scope = CampaignRiskScopeLoader(Path("config/risk-scope-week3.yaml"), taxonomy).load()
    registry = MutationOperatorRegistryLoader(
        Path("config/mutation-operators.yaml"), taxonomy
    ).load()
    resolver = CoverageInputResolver(
        trajectory_root=trajectory_root,
        manifest_root=tmp_path / "replays",
        artifact_root=tmp_path / "artifacts",
        case_source=source,
    )
    mutation_config = MutationConfig(store_root=tmp_path / "mutations")
    metadata = {
        "taxonomy_version": taxonomy.taxonomy_version,
        "risk_scope_version": scope.scope_version,
        "risk_scope_digest": scope.digest,
        "operator_registry_version": registry.registry_version,
        "operator_registry_digest": registry.digest,
        "normalization_version": mutation_config.diversity.normalization_version,
        "similarity_version": mutation_config.diversity.similarity_version,
        "priority_formula_version": mutation_config.priority.formula_version,
    }

    with (
        CoverageStore(
            tmp_path / "coverage",
            mutation_config.campaign_id,
            taxonomy,
            risk_scope=scope,
            auto_snapshot_interval=0,
        ) as coverage_store,
        MutationStore(
            mutation_config.store_root,
            mutation_config.campaign_id,
            metadata=metadata,
        ) as mutation_store,
    ):
        parent_case = source.generate("path-absolute-001", seed=42)
        parent_outcome = await engine.run_test_case(parent_case)
        assert parent_outcome.container_removed is True
        parent_input = resolver.from_trajectory_path(
            parent_outcome.trajectory_path,
            prompt=parent_case.prompt,
        )
        parent_coverage = coverage_store.evaluate(parent_input)
        seed = MutationSeed(
            seed_id=parent_case.case_id,
            case=parent_case,
            prompt_sha256=prompt_digest(parent_case.prompt),
            coverage_result=parent_coverage,
            behavior_profile_hash=parent_coverage.behavior_profile_hash,
        )
        feedback = MutationFeedbackBuilder(taxonomy, scope).build(
            seed,
            coverage_store.snapshot(include_heatmap=False),
            history=mutation_store.snapshot(),
        )
        mutator = SemanticMutator(
            mutation_config,
            registry,
            scope,
            RuleBasedMutationProvider(),
            DiversityGate(CharacterShingleSimilarity(), mutation_config.diversity),
            MutationPriorityCalculator(mutation_config.priority),
            mutation_store,
        )
        batch = await mutator.mutate(seed, feedback, 4, random_seed=42)
        assert len(batch.accepted) >= 3
        assert len({item.operator_id for item in batch.accepted}) >= 2

        linked_categories: set[str] = set()
        for candidate in batch.accepted:
            case = to_test_case(candidate)
            outcome = await engine.run_test_case(case)
            assert outcome.container_removed is True
            coverage_input = resolver.from_trajectory_path(
                outcome.trajectory_path,
                prompt=case.prompt,
            )
            started = coverage_input.events[0]
            assert started.data["mutation_id"] == candidate.mutation_id
            assert started.data["operator_id"] == candidate.operator_id
            result = coverage_store.evaluate(coverage_input)
            linked_categories.update(link.risk_category_id for link in result.behavior_risk_links)

        assert linked_categories

    leftovers = docker_client.containers.list(
        all=True,
        filters={"label": "trace-g.component=agent-sandbox"},
    )
    assert leftovers == []
