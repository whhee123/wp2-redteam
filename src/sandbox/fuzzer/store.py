"""SQLite persistence and state transitions for one fuzzing campaign."""

# ruff: noqa: E501  # SQL statements remain readable as complete clauses.

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sandbox.fuzzer.exceptions import FuzzerIntegrityError
from sandbox.fuzzer.models import (
    CampaignManifest,
    CampaignStatus,
    CampaignStopReason,
    CandidateExecutionOutcome,
    CorpusEntry,
    EnergyDecision,
    FailureKind,
    Observation,
    SeedRecord,
    SeedStatus,
    WorkItem,
    WorkItemStatus,
    execution_id_for,
    fuzzer_digest,
)

CAMPAIGN_TRANSITIONS: dict[CampaignStatus, set[CampaignStatus]] = {
    CampaignStatus.CREATED: {CampaignStatus.BOOTSTRAPPING, CampaignStatus.PAUSED},
    CampaignStatus.BOOTSTRAPPING: {
        CampaignStatus.RUNNING,
        CampaignStatus.PAUSE_REQUESTED,
        CampaignStatus.FAILED,
    },
    CampaignStatus.RUNNING: {
        CampaignStatus.PAUSE_REQUESTED,
        CampaignStatus.STOP_REQUESTED,
        CampaignStatus.COMPLETED,
        CampaignStatus.FAILED,
    },
    CampaignStatus.PAUSE_REQUESTED: {CampaignStatus.PAUSED, CampaignStatus.FAILED},
    CampaignStatus.PAUSED: {
        CampaignStatus.RUNNING,
        CampaignStatus.STOP_REQUESTED,
        CampaignStatus.FAILED,
    },
    CampaignStatus.STOP_REQUESTED: {CampaignStatus.COMPLETED, CampaignStatus.FAILED},
    # Completion is provisional until shutdown resource cleanup succeeds.
    CampaignStatus.COMPLETED: {CampaignStatus.FAILED},
    CampaignStatus.FAILED: set(),
}

WORK_TRANSITIONS: dict[WorkItemStatus, set[WorkItemStatus]] = {
    WorkItemStatus.QUEUED: {WorkItemStatus.LEASED, WorkItemStatus.SKIPPED},
    WorkItemStatus.LEASED: {
        WorkItemStatus.EXECUTED,
        WorkItemStatus.RETRY_WAIT,
        WorkItemStatus.FAILED,
        WorkItemStatus.DEAD_LETTER,
        WorkItemStatus.SKIPPED,
    },
    WorkItemStatus.EXECUTED: {
        WorkItemStatus.COMMITTED,
        WorkItemStatus.DEAD_LETTER,
    },
    WorkItemStatus.RETRY_WAIT: {WorkItemStatus.QUEUED, WorkItemStatus.DEAD_LETTER},
    WorkItemStatus.COMMITTED: set(),
    WorkItemStatus.FAILED: set(),
    WorkItemStatus.DEAD_LETTER: set(),
    WorkItemStatus.SKIPPED: set(),
}


class FuzzerStore:
    schema_version = "1.0"

    def __init__(
        self,
        root: Path,
        campaign_id: str,
        *,
        busy_timeout_ms: int = 5_000,
    ) -> None:
        if (
            not campaign_id
            or campaign_id in {".", ".."}
            or any(character in campaign_id for character in "/\\:")
        ):
            raise FuzzerIntegrityError("invalid fuzzer campaign_id")
        base = root.resolve()
        base.mkdir(parents=True, exist_ok=True)
        self.root = (base / campaign_id).resolve()
        if base not in self.root.parents:
            raise FuzzerIntegrityError("fuzzer campaign path escapes root")
        self.root.mkdir(parents=True, exist_ok=True)
        self.snapshot_root = self.root / "snapshots"
        self.snapshot_root.mkdir(exist_ok=True)
        self.export_root = self.root / "exports"
        self.export_root.mkdir(exist_ok=True)
        self.campaign_id = campaign_id
        self.database_path = self.root / "fuzzer.db"
        self.manifest_path = self.root / "manifest.json"
        self._connection = sqlite3.connect(
            self.database_path,
            timeout=busy_timeout_ms / 1_000,
            isolation_level=None,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._create_schema()
        self._validate_metadata()

    def __enter__(self) -> FuzzerStore:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def close(self) -> None:
        self._connection.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            yield self._connection
        except Exception:
            self._connection.rollback()
            raise
        else:
            self._connection.commit()

    def initialize(self, manifest: CampaignManifest) -> None:
        if manifest.campaign_id != self.campaign_id:
            raise FuzzerIntegrityError("manifest campaign_id mismatch")
        payload = manifest.model_dump_json(indent=2).encode("utf-8") + b"\n"
        with self.transaction() as connection:
            existing = connection.execute(
                "SELECT manifest_digest FROM campaign_state WHERE singleton = 1"
            ).fetchone()
            digest = fuzzer_digest(manifest)
            if existing is not None:
                if existing["manifest_digest"] != digest:
                    raise FuzzerIntegrityError("campaign manifest digest mismatch")
                return
            connection.execute(
                """
                INSERT INTO campaign_state(
                    singleton, status, stop_reason, iteration, active_runtime_seconds,
                    manifest_digest, next_dispatch_sequence, generation_no_progress,
                    execution_attempts, retry_count, created_at, updated_at
                ) VALUES (1, ?, NULL, 0, 0, ?, 1, 0, 0, 0, ?, ?)
                """,
                (
                    CampaignStatus.CREATED.value,
                    digest,
                    manifest.created_at.isoformat(),
                    manifest.created_at.isoformat(),
                ),
            )
            self._audit(connection, "campaign_created", {"manifest_digest": digest})
        self._atomic_write(self.manifest_path, payload)

    def load_manifest(self) -> CampaignManifest:
        if not self.manifest_path.is_file():
            raise FuzzerIntegrityError("campaign manifest is missing")
        manifest = CampaignManifest.model_validate_json(self.manifest_path.read_bytes())
        row = self._campaign_row()
        if row["manifest_digest"] != fuzzer_digest(manifest):
            raise FuzzerIntegrityError("campaign manifest does not match database")
        return manifest

    def status(self) -> CampaignStatus:
        return CampaignStatus(self._campaign_row()["status"])

    def stop_reason(self) -> CampaignStopReason | None:
        value = self._campaign_row()["stop_reason"]
        return CampaignStopReason(value) if value else None

    def iteration(self) -> int:
        return int(self._campaign_row()["iteration"])

    def is_initialized(self) -> bool:
        row = self._connection.execute(
            "SELECT 1 FROM campaign_state WHERE singleton = 1"
        ).fetchone()
        return row is not None

    def campaign_values(self) -> dict[str, Any]:
        return dict(self._campaign_row())

    def transition_campaign(
        self,
        target: CampaignStatus,
        *,
        reason: CampaignStopReason | None = None,
        audit_data: dict[str, Any] | None = None,
    ) -> None:
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT status FROM campaign_state WHERE singleton = 1"
            ).fetchone()
            if row is None:
                raise FuzzerIntegrityError("campaign is not initialized")
            current = CampaignStatus(row["status"])
            if current == target:
                return
            if target not in CAMPAIGN_TRANSITIONS[current]:
                raise FuzzerIntegrityError(
                    f"illegal campaign transition: {current.value} -> {target.value}"
                )
            if (
                current == CampaignStatus.COMPLETED
                and target == CampaignStatus.FAILED
                and reason != CampaignStopReason.SYSTEMIC_INFRASTRUCTURE_FAILURE
            ):
                raise FuzzerIntegrityError(
                    "completed campaign can only fail during shutdown cleanup correction"
                )
            connection.execute(
                """
                UPDATE campaign_state SET status = ?, stop_reason = ?, updated_at = ?
                WHERE singleton = 1
                """,
                (target.value, reason.value if reason else None, self._now().isoformat()),
            )
            self._audit(
                connection,
                f"campaign_{target.value}",
                {
                    "from": current.value,
                    "reason": reason.value if reason else None,
                    **(audit_data or {}),
                },
            )

    def advance_iteration(self, target: int | None = None) -> int:
        with self.transaction() as connection:
            current = int(
                connection.execute(
                    "SELECT iteration FROM campaign_state WHERE singleton = 1"
                ).fetchone()["iteration"]
            )
            next_value = current + 1 if target is None else target
            if next_value <= current:
                raise FuzzerIntegrityError("campaign iteration must increase")
            connection.execute(
                "UPDATE campaign_state SET iteration = ?, updated_at = ? WHERE singleton = 1",
                (next_value, self._now().isoformat()),
            )
            return next_value

    def save_seed(self, seed: SeedRecord) -> SeedRecord:
        digest = fuzzer_digest(seed)
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT seed_json FROM seeds WHERE seed_id = ?", (seed.seed_id,)
            ).fetchone()
            if row is not None:
                existing = SeedRecord.model_validate_json(row["seed_json"])
                if existing != seed:
                    raise FuzzerIntegrityError("seed_id conflicts with existing payload")
                return existing
            connection.execute(
                """
                INSERT INTO seeds(seed_id, status, seed_digest, seed_json, created_order)
                VALUES (?, ?, ?, ?, (SELECT COUNT(*) FROM seeds))
                """,
                (seed.seed_id, seed.status.value, digest, seed.model_dump_json()),
            )
            self._audit(connection, "seed_created", {"seed_id": seed.seed_id})
        return seed

    def get_seed(self, seed_id: str) -> SeedRecord:
        row = self._connection.execute(
            "SELECT seed_json FROM seeds WHERE seed_id = ?", (seed_id,)
        ).fetchone()
        if row is None:
            raise FuzzerIntegrityError(f"seed not found: {seed_id}")
        return SeedRecord.model_validate_json(row["seed_json"])

    def list_seeds(self, status: SeedStatus | None = None) -> list[SeedRecord]:
        if status is None:
            rows = self._connection.execute(
                "SELECT seed_json FROM seeds ORDER BY created_order, seed_id"
            )
        else:
            rows = self._connection.execute(
                "SELECT seed_json FROM seeds WHERE status = ? ORDER BY created_order, seed_id",
                (status.value,),
            )
        return [SeedRecord.model_validate_json(row["seed_json"]) for row in rows]

    def update_seed(self, seed: SeedRecord, *, event: str = "seed_updated") -> None:
        with self.transaction() as connection:
            if not connection.execute(
                "SELECT 1 FROM seeds WHERE seed_id = ?", (seed.seed_id,)
            ).fetchone():
                raise FuzzerIntegrityError(f"seed not found: {seed.seed_id}")
            connection.execute(
                "UPDATE seeds SET status = ?, seed_digest = ?, seed_json = ? WHERE seed_id = ?",
                (seed.status.value, fuzzer_digest(seed), seed.model_dump_json(), seed.seed_id),
            )
            self._audit(connection, event, {"seed_id": seed.seed_id, "status": seed.status.value})

    def save_energy_decision(self, decision: EnergyDecision) -> EnergyDecision:
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT decision_json FROM energy_decisions WHERE decision_id = ?",
                (decision.decision_id,),
            ).fetchone()
            if row:
                existing = EnergyDecision.model_validate_json(row["decision_json"])
                if existing != decision:
                    raise FuzzerIntegrityError("energy decision identity conflict")
                return existing
            connection.execute(
                "INSERT INTO energy_decisions(decision_id, seed_id, iteration, decision_json) VALUES (?, ?, ?, ?)",
                (
                    decision.decision_id,
                    decision.seed_id,
                    decision.iteration,
                    decision.model_dump_json(),
                ),
            )
            self._audit(
                connection,
                "energy_assigned",
                {
                    "decision_id": decision.decision_id,
                    "seed_id": decision.seed_id,
                    "energy": decision.assigned_energy,
                },
            )
        return decision

    def create_work(self, work: WorkItem) -> tuple[WorkItem, bool]:
        if work.campaign_id != self.campaign_id or work.status != WorkItemStatus.QUEUED:
            raise FuzzerIntegrityError("new work must be queued for this campaign")
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT work_json FROM work_items WHERE work_item_id = ?", (work.work_item_id,)
            ).fetchone()
            if row:
                return WorkItem.model_validate_json(row["work_json"]), False
            connection.execute(
                """
                INSERT INTO work_items(
                    work_item_id, status, priority, dispatch_sequence, source_candidate_id,
                    work_digest, work_json, created_order
                ) VALUES (?, ?, ?, NULL, ?, ?, ?, (SELECT COUNT(*) FROM work_items))
                """,
                (
                    work.work_item_id,
                    work.status.value,
                    work.priority,
                    work.source.candidate_id,
                    fuzzer_digest(work),
                    work.model_dump_json(),
                ),
            )
            self._audit(connection, "work_enqueued", {"work_item_id": work.work_item_id})
        return work, True

    def get_work(self, work_item_id: str) -> WorkItem:
        row = self._connection.execute(
            "SELECT work_json FROM work_items WHERE work_item_id = ?", (work_item_id,)
        ).fetchone()
        if row is None:
            raise FuzzerIntegrityError(f"work item not found: {work_item_id}")
        return WorkItem.model_validate_json(row["work_json"])

    def list_work(self, status: WorkItemStatus | None = None) -> list[WorkItem]:
        if status is None:
            rows = self._connection.execute(
                "SELECT work_json FROM work_items ORDER BY COALESCE(dispatch_sequence, 2147483647), created_order"
            )
        else:
            rows = self._connection.execute(
                "SELECT work_json FROM work_items WHERE status = ? ORDER BY COALESCE(dispatch_sequence, 2147483647), created_order",
                (status.value,),
            )
        return [WorkItem.model_validate_json(row["work_json"]) for row in rows]

    def lease_next(self, worker_id: str, *, lease_seconds: int) -> tuple[WorkItem, str] | None:
        now = self._now()
        with self.transaction() as connection:
            row = connection.execute(
                """
                SELECT work_json FROM work_items
                WHERE status = ? AND (retry_not_before IS NULL OR retry_not_before <= ?)
                ORDER BY priority DESC, created_order, work_item_id LIMIT 1
                """,
                (WorkItemStatus.QUEUED.value, now.isoformat()),
            ).fetchone()
            if row is None:
                return None
            work = WorkItem.model_validate_json(row["work_json"])
            sequence = work.dispatch_sequence
            if sequence is None:
                state = connection.execute(
                    "SELECT next_dispatch_sequence FROM campaign_state WHERE singleton = 1"
                ).fetchone()
                sequence = int(state["next_dispatch_sequence"])
                connection.execute(
                    "UPDATE campaign_state SET next_dispatch_sequence = ? WHERE singleton = 1",
                    (sequence + 1,),
                )
            attempt = work.attempt + 1
            token = fuzzer_digest(
                {
                    "work_item_id": work.work_item_id,
                    "attempt": attempt,
                    "worker": worker_id,
                    "now": now,
                }
            )
            expires = now + timedelta(seconds=lease_seconds)
            leased = work.model_copy(
                update={
                    "status": WorkItemStatus.LEASED,
                    "dispatch_sequence": sequence,
                    "attempt": attempt,
                    "execution_id": execution_id_for(self.campaign_id, work.work_item_id, attempt),
                    "lease_owner": worker_id,
                    "lease_token_digest": token,
                    "lease_expires_at": expires,
                    "retry_not_before": None,
                }
            )
            self._replace_work(connection, work, leased)
            connection.execute(
                """
                INSERT INTO work_attempts(work_item_id, attempt, execution_id, lease_token_digest, started_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (leased.work_item_id, attempt, leased.execution_id, token, now.isoformat()),
            )
            connection.execute(
                "UPDATE campaign_state SET execution_attempts = execution_attempts + 1 WHERE singleton = 1"
            )
            self._audit(
                connection,
                "work_leased",
                {
                    "work_item_id": leased.work_item_id,
                    "attempt": attempt,
                    "dispatch_sequence": sequence,
                },
            )
            return leased, token

    def renew_lease(self, work_item_id: str, token: str, *, lease_seconds: int) -> WorkItem:
        with self.transaction() as connection:
            work = self._get_work(connection, work_item_id)
            self._require_lease(work, token)
            renewed = work.model_copy(
                update={"lease_expires_at": self._now() + timedelta(seconds=lease_seconds)}
            )
            self._replace_work(connection, work, renewed)
            return renewed

    def record_outcome(
        self,
        outcome: CandidateExecutionOutcome,
        *,
        lease_token: str,
    ) -> WorkItem:
        with self.transaction() as connection:
            work = self._get_work(connection, outcome.work_item_id)
            self._require_lease(work, lease_token)
            if outcome.attempt != work.attempt or outcome.execution_id != work.execution_id:
                raise FuzzerIntegrityError("execution outcome does not match active lease")
            executed = work.model_copy(
                update={
                    "status": WorkItemStatus.EXECUTED,
                    "trajectory_id": outcome.trajectory_id,
                    "trajectory_path": outcome.trajectory_path,
                    "replay_id": outcome.replay_id,
                    "error_code": outcome.error_code,
                    "lease_owner": None,
                    "lease_token_digest": None,
                    "lease_expires_at": None,
                }
            )
            self._replace_work(connection, work, executed)
            connection.execute(
                "UPDATE work_attempts SET outcome_json = ?, finished_at = ? WHERE work_item_id = ? AND attempt = ?",
                (
                    outcome.model_dump_json(),
                    outcome.finished_at.isoformat(),
                    work.work_item_id,
                    work.attempt,
                ),
            )
            self._audit(
                connection,
                "execution_finished",
                {"work_item_id": work.work_item_id, "attempt": work.attempt},
            )
            return executed

    def schedule_retry(
        self,
        work_item_id: str,
        *,
        failure_kind: FailureKind,
        error_code: str,
        delay_seconds: int,
    ) -> WorkItem:
        with self.transaction() as connection:
            work = self._get_work(connection, work_item_id)
            if work.status not in {WorkItemStatus.LEASED, WorkItemStatus.EXECUTED}:
                raise FuzzerIntegrityError("only leased or executed work can retry")
            retry = work.model_copy(
                update={
                    "status": WorkItemStatus.RETRY_WAIT,
                    "failure_kind": failure_kind,
                    "error_code": error_code,
                    "lease_owner": None,
                    "lease_token_digest": None,
                    "lease_expires_at": None,
                    "retry_not_before": self._now() + timedelta(seconds=delay_seconds),
                }
            )
            self._replace_work(connection, work, retry)
            connection.execute(
                "UPDATE campaign_state SET retry_count = retry_count + 1 WHERE singleton = 1"
            )
            self._audit(
                connection, "work_retry", {"work_item_id": work_item_id, "attempt": work.attempt}
            )
            return retry

    def release_due_retries(self, *, now: datetime | None = None) -> int:
        current = now or self._now()
        changed = 0
        for work in self.list_work(WorkItemStatus.RETRY_WAIT):
            if work.retry_not_before and work.retry_not_before > current:
                continue
            queued = work.model_copy(
                update={"status": WorkItemStatus.QUEUED, "retry_not_before": None}
            )
            with self.transaction() as connection:
                fresh = self._get_work(connection, work.work_item_id)
                if fresh.status != WorkItemStatus.RETRY_WAIT:
                    continue
                self._replace_work(connection, fresh, queued)
                changed += 1
        return changed

    def finish_work(
        self,
        work_item_id: str,
        target: WorkItemStatus,
        *,
        failure_kind: FailureKind | None = None,
        error_code: str | None = None,
    ) -> WorkItem:
        with self.transaction() as connection:
            work = self._get_work(connection, work_item_id)
            updated = work.model_copy(
                update={
                    "status": target,
                    "failure_kind": failure_kind,
                    "error_code": error_code,
                    "lease_owner": None,
                    "lease_token_digest": None,
                    "lease_expires_at": None,
                }
            )
            self._replace_work(connection, work, updated)
            self._audit(connection, f"work_{target.value}", {"work_item_id": work_item_id})
            return updated

    def commit_observation(
        self,
        work_item_id: str,
        observation: Observation,
        *,
        corpus_entry: CorpusEntry | None = None,
        parent_seed: SeedRecord | None = None,
        promoted_seed: SeedRecord | None = None,
    ) -> WorkItem:
        with self.transaction() as connection:
            work = self._get_work(connection, work_item_id)
            if work.status == WorkItemStatus.COMMITTED:
                return work
            if work.status != WorkItemStatus.EXECUTED:
                raise FuzzerIntegrityError("observation requires executed work")
            existing = connection.execute(
                "SELECT observation_digest FROM observations WHERE work_item_id = ?",
                (work_item_id,),
            ).fetchone()
            digest = fuzzer_digest(observation)
            if existing and existing["observation_digest"] != digest:
                raise FuzzerIntegrityError("work observation payload conflict")
            connection.execute(
                """
                INSERT OR IGNORE INTO observations(
                    observation_id, work_item_id, profile_hash, observation_digest, observation_json
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    observation.observation_id,
                    work_item_id,
                    observation.behavior_profile_hash,
                    digest,
                    observation.model_dump_json(),
                ),
            )
            if not existing:
                connection.execute(
                    """
                    INSERT INTO profile_outcomes(profile_hash, execution_count, verdicts_json)
                    VALUES (?, 1, ?)
                    ON CONFLICT(profile_hash) DO UPDATE SET
                        execution_count = execution_count + 1,
                        verdicts_json = excluded.verdicts_json
                    """,
                    (
                        observation.behavior_profile_hash,
                        json.dumps(sorted({observation.score_verdict} - {None})),
                    ),
                )
            corpus_id = None
            if corpus_entry is not None:
                connection.execute(
                    "INSERT OR IGNORE INTO corpus_entries(corpus_entry_id, work_item_id, entry_json) VALUES (?, ?, ?)",
                    (corpus_entry.corpus_entry_id, work_item_id, corpus_entry.model_dump_json()),
                )
                corpus_id = corpus_entry.corpus_entry_id
            for seed, event in (
                (parent_seed, "parent_seed_observed"),
                (promoted_seed, "seed_promoted"),
            ):
                if seed is None:
                    continue
                if promoted_seed is seed:
                    connection.execute(
                        "INSERT OR IGNORE INTO seeds(seed_id, status, seed_digest, seed_json, created_order) VALUES (?, ?, ?, ?, (SELECT COUNT(*) FROM seeds))",
                        (
                            seed.seed_id,
                            seed.status.value,
                            fuzzer_digest(seed),
                            seed.model_dump_json(),
                        ),
                    )
                else:
                    connection.execute(
                        "UPDATE seeds SET status = ?, seed_digest = ?, seed_json = ? WHERE seed_id = ?",
                        (
                            seed.status.value,
                            fuzzer_digest(seed),
                            seed.model_dump_json(),
                            seed.seed_id,
                        ),
                    )
                self._audit(connection, event, {"seed_id": seed.seed_id})
            committed = work.model_copy(
                update={
                    "status": WorkItemStatus.COMMITTED,
                    "coverage_result_digest": observation.coverage_result_digest,
                    "corpus_entry_id": corpus_id,
                }
            )
            self._replace_work(connection, work, committed)
            self._audit(connection, "coverage_committed", {"work_item_id": work_item_id})
            return committed

    def profile_execution_count(self, profile_hash: str | None) -> int:
        if not profile_hash:
            return 1
        row = self._connection.execute(
            "SELECT execution_count FROM profile_outcomes WHERE profile_hash = ?",
            (profile_hash,),
        ).fetchone()
        return int(row["execution_count"]) if row else 1

    def observed_verdicts(self, profile_hash: str) -> set[str]:
        rows = self._connection.execute(
            "SELECT observation_json FROM observations WHERE profile_hash = ?", (profile_hash,)
        )
        return {
            observation.score_verdict
            for row in rows
            if (
                observation := Observation.model_validate_json(row["observation_json"])
            ).score_verdict
        }

    def corpus_entries(self) -> list[CorpusEntry]:
        return [
            CorpusEntry.model_validate_json(row["entry_json"])
            for row in self._connection.execute(
                "SELECT entry_json FROM corpus_entries ORDER BY rowid"
            )
        ]

    def observations(self) -> list[Observation]:
        return [
            Observation.model_validate_json(row["observation_json"])
            for row in self._connection.execute(
                "SELECT observation_json FROM observations ORDER BY rowid"
            )
        ]

    def counts(self, table: str, column: str) -> dict[str, int]:
        allowed = {"seeds": "status", "work_items": "status"}
        if allowed.get(table) != column:
            raise FuzzerIntegrityError("unsupported count query")
        return {
            str(row["value"]): int(row["count"])
            for row in self._connection.execute(
                f"SELECT {column} AS value, COUNT(*) AS count FROM {table} GROUP BY {column}"
            )
        }

    def save_metric_snapshot(self, snapshot_json: str, snapshot_digest: str) -> None:
        with self.transaction() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO metric_snapshots(snapshot_digest, snapshot_json, created_at) VALUES (?, ?, ?)",
                (snapshot_digest, snapshot_json, self._now().isoformat()),
            )

    def update_executed_trajectory(
        self,
        work_item_id: str,
        *,
        trajectory_id: str,
        trajectory_path: str | None,
    ) -> WorkItem:
        with self.transaction() as connection:
            work = self._get_work(connection, work_item_id)
            if work.status != WorkItemStatus.EXECUTED:
                raise FuzzerIntegrityError("trajectory resolution requires executed work")
            updated = work.model_copy(
                update={
                    "trajectory_id": trajectory_id,
                    "trajectory_path": trajectory_path,
                }
            )
            self._replace_work(connection, work, updated)
            return updated

    def latest_outcome(self, work_item_id: str) -> CandidateExecutionOutcome | None:
        row = self._connection.execute(
            "SELECT outcome_json FROM work_attempts WHERE work_item_id = ? AND outcome_json IS NOT NULL ORDER BY attempt DESC LIMIT 1",
            (work_item_id,),
        ).fetchone()
        return CandidateExecutionOutcome.model_validate_json(row["outcome_json"]) if row else None

    def execution_durations_ms(self) -> list[float]:
        rows = self._connection.execute(
            "SELECT outcome_json FROM work_attempts WHERE outcome_json IS NOT NULL ORDER BY rowid"
        )
        return [
            float(CandidateExecutionOutcome.model_validate_json(row["outcome_json"]).duration_ms)
            for row in rows
        ]

    def record_generation_progress(self, *, created_count: int) -> int:
        with self.transaction() as connection:
            if created_count:
                connection.execute(
                    "UPDATE campaign_state SET generation_no_progress = 0 WHERE singleton = 1"
                )
                return 0
            connection.execute(
                "UPDATE campaign_state SET generation_no_progress = generation_no_progress + 1 WHERE singleton = 1"
            )
            value = int(
                connection.execute(
                    "SELECT generation_no_progress FROM campaign_state WHERE singleton = 1"
                ).fetchone()["generation_no_progress"]
            )
            return value

    def add_active_runtime(self, seconds: float) -> None:
        if seconds < 0:
            raise FuzzerIntegrityError("active runtime cannot decrease")
        with self.transaction() as connection:
            connection.execute(
                "UPDATE campaign_state SET active_runtime_seconds = active_runtime_seconds + ? WHERE singleton = 1",
                (seconds,),
            )

    def audit_events(self) -> list[dict[str, Any]]:
        return [
            {**json.loads(row["event_json"]), "sequence": int(row["sequence"])}
            for row in self._connection.execute(
                "SELECT sequence, event_json FROM campaign_audit ORDER BY sequence"
            )
        ]

    def _get_work(self, connection: sqlite3.Connection, work_item_id: str) -> WorkItem:
        row = connection.execute(
            "SELECT work_json FROM work_items WHERE work_item_id = ?", (work_item_id,)
        ).fetchone()
        if row is None:
            raise FuzzerIntegrityError(f"work item not found: {work_item_id}")
        return WorkItem.model_validate_json(row["work_json"])

    def _replace_work(
        self,
        connection: sqlite3.Connection,
        previous: WorkItem,
        updated: WorkItem,
    ) -> None:
        if (
            updated.status != previous.status
            and updated.status not in WORK_TRANSITIONS[previous.status]
        ):
            raise FuzzerIntegrityError(
                f"illegal work transition: {previous.status.value} -> {updated.status.value}"
            )
        if (
            previous.dispatch_sequence is not None
            and updated.dispatch_sequence != previous.dispatch_sequence
        ):
            raise FuzzerIntegrityError("dispatch_sequence is immutable")
        connection.execute(
            """
            UPDATE work_items SET status = ?, priority = ?, dispatch_sequence = ?,
                retry_not_before = ?, work_digest = ?, work_json = ?
            WHERE work_item_id = ?
            """,
            (
                updated.status.value,
                updated.priority,
                updated.dispatch_sequence,
                updated.retry_not_before.isoformat() if updated.retry_not_before else None,
                fuzzer_digest(updated),
                updated.model_dump_json(),
                updated.work_item_id,
            ),
        )

    @staticmethod
    def _require_lease(work: WorkItem, token: str) -> None:
        if work.status != WorkItemStatus.LEASED or work.lease_token_digest != token:
            raise FuzzerIntegrityError("lease token does not own work item")

    def _campaign_row(self) -> sqlite3.Row:
        row = self._connection.execute(
            "SELECT * FROM campaign_state WHERE singleton = 1"
        ).fetchone()
        if row is None:
            raise FuzzerIntegrityError("campaign is not initialized")
        return row

    def _audit(
        self,
        connection: sqlite3.Connection,
        event_type: str,
        data: dict[str, Any],
    ) -> None:
        event = {
            "campaign_id": self.campaign_id,
            "event_type": event_type,
            "created_at": self._now().isoformat(),
            "data": data,
        }
        connection.execute(
            "INSERT INTO campaign_audit(event_json) VALUES (?)",
            (json.dumps(event, ensure_ascii=False, sort_keys=True),),
        )

    def _validate_metadata(self) -> None:
        expected = {"campaign_id": self.campaign_id, "schema_version": self.schema_version}
        with self.transaction() as connection:
            for key, value in expected.items():
                row = connection.execute(
                    "SELECT value FROM metadata WHERE key = ?", (key,)
                ).fetchone()
                if row is not None and row["value"] != value:
                    raise FuzzerIntegrityError(f"fuzzer database {key} mismatch")
                connection.execute(
                    "INSERT OR IGNORE INTO metadata(key, value) VALUES (?, ?)", (key, value)
                )

    def _create_schema(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS campaign_state(
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                status TEXT NOT NULL, stop_reason TEXT, iteration INTEGER NOT NULL,
                active_runtime_seconds REAL NOT NULL, manifest_digest TEXT NOT NULL,
                next_dispatch_sequence INTEGER NOT NULL, generation_no_progress INTEGER NOT NULL,
                execution_attempts INTEGER NOT NULL, retry_count INTEGER NOT NULL,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS campaign_audit(
                sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS seeds(
                seed_id TEXT PRIMARY KEY, status TEXT NOT NULL, seed_digest TEXT NOT NULL,
                seed_json TEXT NOT NULL, created_order INTEGER NOT NULL UNIQUE
            );
            CREATE TABLE IF NOT EXISTS energy_decisions(
                decision_id TEXT PRIMARY KEY, seed_id TEXT NOT NULL REFERENCES seeds(seed_id),
                iteration INTEGER NOT NULL, decision_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS work_items(
                work_item_id TEXT PRIMARY KEY, status TEXT NOT NULL, priority REAL NOT NULL,
                dispatch_sequence INTEGER UNIQUE, source_candidate_id TEXT UNIQUE,
                retry_not_before TEXT, work_digest TEXT NOT NULL, work_json TEXT NOT NULL,
                created_order INTEGER NOT NULL UNIQUE
            );
            CREATE TABLE IF NOT EXISTS work_attempts(
                work_item_id TEXT NOT NULL REFERENCES work_items(work_item_id),
                attempt INTEGER NOT NULL, execution_id TEXT NOT NULL UNIQUE,
                lease_token_digest TEXT NOT NULL, started_at TEXT NOT NULL,
                finished_at TEXT, outcome_json TEXT,
                PRIMARY KEY(work_item_id, attempt)
            );
            CREATE TABLE IF NOT EXISTS observations(
                observation_id TEXT PRIMARY KEY, work_item_id TEXT NOT NULL UNIQUE REFERENCES work_items(work_item_id),
                profile_hash TEXT NOT NULL, observation_digest TEXT NOT NULL, observation_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS corpus_entries(
                corpus_entry_id TEXT PRIMARY KEY, work_item_id TEXT NOT NULL UNIQUE REFERENCES work_items(work_item_id),
                entry_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS profile_outcomes(
                profile_hash TEXT PRIMARY KEY, execution_count INTEGER NOT NULL, verdicts_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS metric_snapshots(
                snapshot_digest TEXT PRIMARY KEY, snapshot_json TEXT NOT NULL, created_at TEXT NOT NULL
            );
            """
        )

    @staticmethod
    def _now() -> datetime:
        return datetime.now(UTC)

    @staticmethod
    def _atomic_write(destination: Path, payload: bytes) -> None:
        fd, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}-", dir=destination.parent
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
