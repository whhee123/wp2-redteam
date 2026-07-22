from __future__ import annotations

import asyncio
from pathlib import Path

from sandbox.fuzzer.config import FuzzerConfig
from sandbox.fuzzer.engine import FuzzingEngine
from sandbox.fuzzer.models import (
    CampaignManifest,
    WorkItem,
    WorkItemStatus,
    WorkSourceKind,
    WorkSourceRef,
    work_item_id_for,
)
from sandbox.fuzzer.recovery import RecoveryManager
from sandbox.fuzzer.store import FuzzerStore
from sandbox.models import TraceEvent
from sandbox.storage.trajectory_store import TrajectoryStore


def _manifest() -> CampaignManifest:
    return CampaignManifest(
        campaign_id="week5-recovery",
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


def _work() -> WorkItem:
    source = WorkSourceRef(
        kind=WorkSourceKind.INITIAL_CASE,
        case_id="path-absolute-001",
    )
    return WorkItem(
        work_item_id=work_item_id_for("week5-recovery", source),
        campaign_id="week5-recovery",
        source=source,
        priority=1,
        created_iteration=0,
    )


async def test_heartbeat_renews_active_wave_until_stopped() -> None:
    class RecordingStore:
        def __init__(self) -> None:
            self.renewals = 0

        def renew_lease(self, *_args, **_kwargs) -> None:
            self.renewals += 1

    engine = object.__new__(FuzzingEngine)
    engine.config = FuzzerConfig.model_validate(
        {
            "campaign_id": "week5-recovery",
            "leases": {"lease_seconds": 3, "heartbeat_seconds": 1},
        }
    )
    engine.store = RecordingStore()
    stop = asyncio.Event()
    task = asyncio.create_task(engine._heartbeat_leases([(_work(), "token")], stop))
    await asyncio.sleep(1.05)
    stop.set()
    await task
    assert engine.store.renewals == 1


async def test_recovery_commits_complete_trajectory_without_waiting_for_lease_expiry(
    tmp_path: Path,
) -> None:
    trajectory_root = tmp_path / "trajectories"
    with FuzzerStore(tmp_path / "fuzzing", "week5-recovery") as store:
        store.initialize(_manifest())
        store.create_work(_work())
        leased, _token = store.lease_next("worker-1", lease_seconds=240) or (None, None)
        assert leased is not None and leased.execution_id is not None

        trajectory_store = TrajectoryStore(trajectory_root, leased.execution_id)
        trajectory_store.append(
            [
                TraceEvent(
                    execution_id=leased.execution_id,
                    sequence=0,
                    event_type="execution_started",
                    source="runtime",
                ),
                TraceEvent(
                    execution_id=leased.execution_id,
                    sequence=1,
                    event_type="execution_finished",
                    source="runtime",
                    data={"final_answer": "safe"},
                ),
            ]
        )
        trajectory_store.commit(final_sequence=1, trace_count=2)

        recovered, cleanup = await RecoveryManager(
            store,
            trajectory_root=trajectory_root,
        ).reconcile()

        assert cleanup is None
        assert [item.work_item_id for item in recovered] == [leased.work_item_id]
        assert store.get_work(leased.work_item_id).status == WorkItemStatus.EXECUTED
        outcome = store.latest_outcome(leased.work_item_id)
        assert outcome is not None
        assert outcome.execution_status == "succeeded"
        assert outcome.score is not None and outcome.score.verdict == "safe"


async def test_recovery_does_not_treat_partial_trajectory_as_complete(tmp_path: Path) -> None:
    trajectory_root = tmp_path / "trajectories"
    with FuzzerStore(tmp_path / "fuzzing", "week5-recovery") as store:
        store.initialize(_manifest())
        store.create_work(_work())
        leased, _token = store.lease_next("worker-1", lease_seconds=240) or (None, None)
        assert leased is not None and leased.execution_id is not None

        trajectory_store = TrajectoryStore(trajectory_root, leased.execution_id)
        trajectory_store.append(
            [
                TraceEvent(
                    execution_id=leased.execution_id,
                    sequence=0,
                    event_type="execution_started",
                    source="runtime",
                )
            ]
        )

        recovered, _cleanup = await RecoveryManager(
            store,
            trajectory_root=trajectory_root,
        ).reconcile()

        assert recovered == []
        assert store.get_work(leased.work_item_id).status == WorkItemStatus.LEASED
        assert store.latest_outcome(leased.work_item_id) is None
