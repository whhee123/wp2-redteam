from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from sandbox.coverage.models import CoverageResult, CoverageSnapshot
from sandbox.engine.case_source import TemplateCaseSource
from sandbox.fuzzer.config import FuzzerConfig
from sandbox.fuzzer.corpus import CorpusPolicy
from sandbox.fuzzer.energy import EnergyScheduler
from sandbox.fuzzer.models import (
    CampaignManifest,
    CampaignStatus,
    CampaignStopReason,
    CorpusReason,
    SeedOrigin,
    SeedRecord,
    SeedStatus,
    WorkItem,
    WorkSourceKind,
    WorkSourceRef,
    execution_id_for,
    seed_id_for,
    work_item_id_for,
)
from sandbox.fuzzer.store import FuzzerStore
from sandbox.mutation.models import MutationFeedback, RiskGap
from sandbox.mutation.normalizer import prompt_digest


def _manifest(campaign_id: str = "week5-test") -> CampaignManifest:
    return CampaignManifest(
        campaign_id=campaign_id,
        config_digest="sha256:" + "1" * 64,
        taxonomy_version="taxonomy-v1",
        taxonomy_digest="sha256:" + "2" * 64,
        risk_scope_version="scope-v1",
        risk_scope_digest="sha256:" + "3" * 64,
        mutation_registry_version="registry-v1",
        mutation_registry_digest="sha256:" + "4" * 64,
        mutation_provider="rule_based",
        mutation_provider_version="rule-v1",
        agent_model_name="fake",
        agent_image="image:test",
        target_profile_id="standard-fake",
        energy_formula_version="energy-v1",
        corpus_policy_version="coverage-corpus-v1",
        scheduler_policy_version="single-host-v1",
        random_seed=42,
    )


def _seed() -> SeedRecord:
    case = TemplateCaseSource().generate("path-absolute-001", seed=42)
    return SeedRecord(
        seed_id=seed_id_for(case, origin=SeedOrigin.TEMPLATE),
        origin=SeedOrigin.TEMPLATE,
        case=case,
        mutation_depth=0,
        prompt_sha256=prompt_digest(case.prompt),
    )


def test_work_source_union_and_config_invariants() -> None:
    with pytest.raises(ValidationError):
        WorkSourceRef(kind=WorkSourceKind.MUTATION, case_id="wrong")
    with pytest.raises(ValidationError):
        FuzzerConfig.model_validate(
            {
                "campaign_id": "bad/path",
                "budget": {"max_executions": 1},
            }
        )
    with pytest.raises(ValidationError):
        FuzzerConfig.model_validate(
            {
                "campaign_id": "test",
                "concurrency": {"sandbox_workers": 3, "execution_queue_size": 2},
            }
        )


def test_ids_are_stable_and_fuzz_execution_id_is_safe() -> None:
    source = WorkSourceRef(kind=WorkSourceKind.INITIAL_CASE, case_id="path-absolute-001")
    first = work_item_id_for("week5-test", source)
    assert first == work_item_id_for("week5-test", source)
    assert execution_id_for("week5-test", first, 1).startswith("fuzz-")
    assert len(execution_id_for("week5-test", first, 1)) == 29


def test_store_lease_sequence_retry_and_token_ownership(tmp_path: Path) -> None:
    with FuzzerStore(tmp_path, "week5-test") as store:
        store.initialize(_manifest())
        seed = _seed()
        store.save_seed(seed)
        source = WorkSourceRef(kind=WorkSourceKind.INITIAL_CASE, case_id="path-absolute-001")
        work = WorkItem(
            work_item_id=work_item_id_for("week5-test", source),
            campaign_id="week5-test",
            source=source,
            priority=1,
            created_iteration=0,
        )
        store.create_work(work)
        leased, token = store.lease_next("worker-1", lease_seconds=30) or (None, None)
        assert leased is not None and token is not None
        assert leased.dispatch_sequence == 1
        assert leased.attempt == 1
        with pytest.raises(Exception, match="lease token"):
            store.renew_lease(leased.work_item_id, "wrong", lease_seconds=30)
        renewed = store.renew_lease(leased.work_item_id, token, lease_seconds=30)
        assert renewed.dispatch_sequence == 1


def test_energy_uses_real_coverage_rarity_and_stagnation(tmp_path: Path) -> None:
    with FuzzerStore(tmp_path, "week5-test") as store:
        store.initialize(_manifest())
        seed = _seed().model_copy(update={"status": SeedStatus.ACTIVE, "consecutive_no_gain": 6})
        store.save_seed(seed)
        config = FuzzerConfig(campaign_id="week5-test")
        feedback = MutationFeedback(
            campaign_id="week5-test",
            taxonomy_version="taxonomy-v1",
            risk_scope_version="scope-v1",
            coverage_snapshot_digest="sha256:" + "5" * 64,
            parent_combined_delta=0.5,
            risk_gaps=[
                RiskGap(
                    category_id="unauthorized_file_read",
                    label="read",
                    observed_depth=1,
                    max_reachable_depth=3,
                    next_target_depth=2,
                    gap_ratio=2 / 3,
                    report_weight=1,
                    schedule_weight=1,
                )
            ],
        )
        snapshot = CoverageSnapshot(
            campaign_id="week5-test",
            taxonomy_version="taxonomy-v1",
            risk_scope_version="scope-v1",
        )
        decision = EnergyScheduler(config.energy, store, "week5-test").assign(
            seed, feedback, snapshot, iteration=1
        )
        assert decision.novelty_factor > 1
        assert decision.risk_gap_factor > 1
        assert decision.rarity_factor > 1
        assert decision.stagnation_factor < 1
        assert config.energy.min_energy <= decision.assigned_energy <= config.energy.max_energy


def test_corpus_policy_requires_real_execution_signal() -> None:
    coverage = CoverageResult(
        trajectory_id="trajectory",
        execution_id="execution",
        input_digest="sha256:" + "6" * 64,
        behavior_profile_hash="sha256:" + "7" * 64,
    )
    decision = CorpusPolicy().evaluate(coverage, None)
    assert decision.retain is False
    changed = coverage.model_copy(update={"new_behavior_count": 1})
    decision = CorpusPolicy().evaluate(changed, None)
    assert decision.retain is True
    assert decision.reasons == (CorpusReason.NEW_BEHAVIOR,)

def test_completed_campaign_can_record_shutdown_cleanup_failure(tmp_path: Path) -> None:
    with FuzzerStore(tmp_path, "week5-test") as store:
        store.initialize(_manifest())
        store.transition_campaign(CampaignStatus.BOOTSTRAPPING)
        store.transition_campaign(CampaignStatus.RUNNING)
        store.transition_campaign(CampaignStatus.COMPLETED)
        store.transition_campaign(
            CampaignStatus.FAILED,
            reason=CampaignStopReason.SYSTEMIC_INFRASTRUCTURE_FAILURE,
            audit_data={"phase": "shutdown_cleanup"},
        )
        assert store.status() == CampaignStatus.FAILED
        assert store.stop_reason() == CampaignStopReason.SYSTEMIC_INFRASTRUCTURE_FAILURE
