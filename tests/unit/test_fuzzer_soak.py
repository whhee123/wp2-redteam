from __future__ import annotations

import argparse
from datetime import UTC, datetime
from pathlib import Path

from sandbox.fuzzer.cli import add_campaign_parser
from sandbox.fuzzer.models import (
    CampaignManifest,
    CandidateExecutionOutcome,
    WorkItemStatus,
    WorkSourceKind,
)
from sandbox.fuzzer.soak import SoakRunner
from sandbox.fuzzer.store import FuzzerStore
from sandbox.models import ScoreResult


def _manifest() -> CampaignManifest:
    return CampaignManifest(
        campaign_id="week5-soak",
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


class NoopRecovery:
    async def reconcile(self):
        return [], None


class SuccessfulExecutor:
    def __init__(self) -> None:
        self.sources = []

    async def execute(self, work):
        self.sources.append(work.source)
        now = datetime.now(UTC)
        return CandidateExecutionOutcome(
            work_item_id=work.work_item_id,
            attempt=work.attempt,
            source=work.source,
            coverage_source_kind="week1",
            execution_id=work.execution_id,
            trajectory_id=work.execution_id,
            trajectory_path=f"{work.execution_id}.jsonl",
            execution_status="succeeded",
            score=ScoreResult(
                execution_id=work.execution_id,
                score=0,
                verdict="safe",
                rationale="soak control succeeded",
            ),
            container_removed=True,
            started_at=now,
            finished_at=now,
            duration_ms=1,
        )


def test_soak_command_is_registered() -> None:
    parser = argparse.ArgumentParser()
    add_campaign_parser(parser.add_subparsers(dest="command", required=True))
    args = parser.parse_args(
        [
            "campaign",
            "soak",
            "--campaign-id",
            "week5-soak",
            "--duration-hours",
            "24",
        ]
    )
    assert args.campaign_command == "soak"
    assert args.duration_hours == 24


async def test_soak_probes_are_persistent_but_do_not_pollute_fuzzing_state(
    tmp_path: Path,
) -> None:
    executor = SuccessfulExecutor()
    with FuzzerStore(tmp_path, "week5-soak") as store:
        store.initialize(_manifest())
        runner = SoakRunner(
            store,
            executor,
            NoopRecovery(),
            lease_seconds=3,
            heartbeat_seconds=1,
        )
        status = await runner.run(
            duration_seconds=60,
            probe_interval_seconds=0.001,
            max_probes=2,
        )

        assert status.value == "completed"
        committed = store.list_work(WorkItemStatus.COMMITTED)
        assert len(committed) == 2
        assert all(item.source.kind == WorkSourceKind.SOAK_PROBE for item in committed)
        assert len({item.source.probe_id for item in committed}) == 2
        assert store.list_seeds() == []
        assert store.observations() == []
        assert store.corpus_entries() == []
        assert len(executor.sources) == 2
