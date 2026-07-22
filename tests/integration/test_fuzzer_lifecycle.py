from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from sandbox.coverage.models import CoverageInput
from sandbox.coverage.risk_scope import CampaignRiskScopeLoader
from sandbox.coverage.store import CoverageStore
from sandbox.coverage.taxonomy import RiskTaxonomyLoader
from sandbox.engine.case_source import TemplateCaseSource
from sandbox.fuzzer.config import FuzzerConfig
from sandbox.fuzzer.engine import FuzzingEngine
from sandbox.fuzzer.models import (
    CampaignManifest,
    CandidateExecutionOutcome,
    WorkItemStatus,
    fuzzer_digest,
)
from sandbox.fuzzer.store import FuzzerStore
from sandbox.models import ScoreResult, TraceEvent
from sandbox.mutation.config import MutationConfig
from sandbox.mutation.feedback import MutationFeedbackBuilder
from sandbox.mutation.models import MutationBatch
from sandbox.mutation.operators import MutationOperatorRegistryLoader
from sandbox.mutation.store import MutationStore
from sandbox.replay.digests import sha256_digest


class SyntheticResolver:
    def from_trajectory_path(self, _path: Path, *, prompt: str | None = None, **_kwargs):
        execution_id = "fuzz-" + "a" * 24
        events = [
            TraceEvent(
                execution_id=execution_id,
                sequence=0,
                event_type="execution_started",
                source="runtime",
            ),
            TraceEvent(
                execution_id=execution_id,
                sequence=1,
                event_type="execution_finished",
                source="runtime",
                data={"final_answer": "blocked"},
            ),
        ]
        return CoverageInput(
            trajectory_id=sha256_digest({"execution_id": execution_id, "prompt": prompt}),
            execution_id=execution_id,
            events=events,
            prompt=prompt,
            final_answer="blocked",
            input_digest=sha256_digest(events),
        )


class SyntheticExecutor:
    def __init__(self, source: TemplateCaseSource) -> None:
        self.case_source = source
        self.coverage_resolver = SyntheticResolver()

    def resolve_case(self, work):
        return self.case_source.generate(work.source.case_id, seed=42)

    async def execute(self, work):
        now = datetime.now(UTC)
        return CandidateExecutionOutcome(
            work_item_id=work.work_item_id,
            attempt=work.attempt,
            source=work.source,
            coverage_source_kind="week1",
            execution_id=work.execution_id,
            trajectory_id=work.execution_id,
            trajectory_path="synthetic.jsonl",
            execution_status="succeeded",
            score=ScoreResult(
                execution_id=work.execution_id,
                score=100,
                verdict="safe",
                rationale="synthetic deterministic execution",
            ),
            container_removed=True,
            started_at=now,
            finished_at=now,
            duration_ms=1,
        )


class NeverMutator:
    async def mutate(self, *_args, **_kwargs):
        return MutationBatch(
            batch_id="sha256:" + "8" * 64,
            campaign_id="week5-integration",
            request_digest="sha256:" + "9" * 64,
            requested_count=1,
            generated_count=0,
            exhausted=True,
        )


def _manifest(config: FuzzerConfig, taxonomy, scope, registry):
    return CampaignManifest(
        campaign_id=config.campaign_id,
        config_digest=fuzzer_digest(config),
        taxonomy_version=taxonomy.taxonomy_version,
        taxonomy_digest=fuzzer_digest(taxonomy.taxonomy),
        risk_scope_version=scope.scope_version,
        risk_scope_digest=scope.digest,
        mutation_registry_version=registry.registry_version,
        mutation_registry_digest=registry.digest,
        mutation_provider="rule_based",
        mutation_provider_version="rule-mutator-v1",
        agent_model_name="fake-chat-model",
        agent_image="trace-redteam-agent:week2",
        target_profile_id="standard-fake",
        energy_formula_version=config.energy.formula_version,
        corpus_policy_version=config.corpus.policy_version,
        scheduler_policy_version="single-host-v1",
        random_seed=config.random_seed,
    )


@pytest.mark.parametrize(
    "scheduling",
    [
        {"mode": "deterministic_rounds", "max_feedback_lag_work_items": 0},
        {"mode": "throughput", "max_feedback_lag_work_items": 1},
    ],
)
async def test_bootstrap_runs_through_persistent_campaign_and_budget_stop(
    tmp_path: Path,
    scheduling: dict[str, object],
) -> None:
    campaign_id = "week5-integration"
    config = FuzzerConfig.model_validate(
        {
            "campaign_id": campaign_id,
            "store_root": tmp_path / "fuzzing",
            "budget": {
                "max_executions": 1,
                "max_duration_seconds": None,
                "max_generated_candidates": None,
                "max_corpus_entries": None,
                "stagnation_window": 2,
            },
            "concurrency": {
                "sandbox_workers": 1,
                "execution_queue_size": 1,
                "result_queue_size": 1,
                "max_pending_work_items": 1,
            },
            "scheduling": scheduling,
        }
    )
    taxonomy = RiskTaxonomyLoader(Path("config/risk-taxonomy.yaml")).load()
    scope = CampaignRiskScopeLoader(Path("config/risk-scope-week3.yaml"), taxonomy).load()
    registry = MutationOperatorRegistryLoader(
        Path("config/mutation-operators.yaml"), taxonomy
    ).load()
    source = TemplateCaseSource()
    mutation_config = MutationConfig(campaign_id=campaign_id, store_root=tmp_path / "mutations")
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
        FuzzerStore(config.store_root, campaign_id) as fuzzer_store,
        MutationStore(mutation_config.store_root, campaign_id, metadata=metadata) as mutation_store,
        CoverageStore(
            tmp_path / "coverage",
            campaign_id,
            taxonomy,
            risk_scope=scope,
            auto_snapshot_interval=0,
        ) as coverage_store,
    ):
        engine = FuzzingEngine(
            config,
            store=fuzzer_store,
            mutation_store=mutation_store,
            coverage_store=coverage_store,
            mutator=NeverMutator(),
            feedback_builder=MutationFeedbackBuilder(taxonomy, scope),
            executor=SyntheticExecutor(source),
            case_source=source,
        )
        engine.create(
            _manifest(config, taxonomy, scope, registry),
            ["path-absolute-001"],
        )
        status = await engine.run()
        assert status.value == "completed"
        assert fuzzer_store.stop_reason().value == "budget_exhausted"
        assert len(fuzzer_store.list_work(WorkItemStatus.COMMITTED)) == 1
        assert fuzzer_store.list_seeds()[0].status.value == "active"
        assert len(fuzzer_store.observations()) == 1
        assert coverage_store.total_trajectories() == 1
