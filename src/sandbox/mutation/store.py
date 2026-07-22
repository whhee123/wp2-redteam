"""Transactional mutation history and candidate storage."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sandbox.mutation.exceptions import MutationIntegrityError
from sandbox.mutation.models import (
    MutationBatch,
    MutationCandidate,
    MutationHistorySnapshot,
)


class MutationStore:
    def __init__(
        self,
        root: Path,
        campaign_id: str,
        *,
        metadata: dict[str, str],
        busy_timeout_ms: int = 5_000,
    ) -> None:
        if (
            not campaign_id
            or campaign_id in {".", ".."}
            or any(character in campaign_id for character in "/\\:")
        ):
            raise MutationIntegrityError("invalid mutation campaign_id")
        base = root.resolve()
        base.mkdir(parents=True, exist_ok=True)
        self.root = (base / campaign_id).resolve()
        if base not in self.root.parents:
            raise MutationIntegrityError("mutation campaign path escapes root")
        self.root.mkdir(parents=True, exist_ok=True)
        self.campaign_id = campaign_id
        self.database_path = self.root / "mutation.db"
        self._connection = sqlite3.connect(
            self.database_path,
            timeout=busy_timeout_ms / 1_000,
            isolation_level=None,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA foreign_keys=ON")
        try:
            self._create_schema()
            self._validate_metadata({"campaign_id": campaign_id, **metadata})
        except Exception:
            self._connection.close()
            raise

    def __enter__(self) -> MutationStore:
        return self

    def __exit__(self, *_args) -> None:
        self.close()

    def close(self) -> None:
        self._connection.close()

    def get_batch(self, batch_id: str) -> MutationBatch | None:
        row = self._connection.execute(
            "SELECT batch_json FROM batches WHERE batch_id = ?",
            (batch_id,),
        ).fetchone()
        return MutationBatch.model_validate_json(row["batch_json"]) if row else None

    def get_candidate(self, mutation_id: str) -> MutationCandidate:
        row = self._connection.execute(
            "SELECT candidate_json FROM candidates WHERE mutation_id = ?",
            (mutation_id,),
        ).fetchone()
        if row is None:
            raise MutationIntegrityError(f"mutation candidate not found: {mutation_id}")
        return MutationCandidate.model_validate_json(row["candidate_json"])

    def dedupe_keys(self) -> set[str]:
        return {
            str(row["dedupe_key"])
            for row in self._connection.execute("SELECT dedupe_key FROM candidates")
        }

    def all_candidates(self) -> list[MutationCandidate]:
        return [
            MutationCandidate.model_validate_json(row["candidate_json"])
            for row in self._connection.execute(
                "SELECT candidate_json FROM candidates ORDER BY created_order, mutation_id"
            )
        ]

    def recent_prompts(self, target_risks: list[str], *, limit: int) -> list[str]:
        if limit <= 0:
            return []
        requested = set(target_risks)
        output = []
        rows = self._connection.execute(
            "SELECT candidate_json FROM candidates ORDER BY created_order DESC LIMIT ?",
            (limit * 4,),
        )
        for row in rows:
            candidate = MutationCandidate.model_validate_json(row["candidate_json"])
            if requested.isdisjoint(candidate.target_risks):
                continue
            text = candidate.prompt or (candidate.fork.content if candidate.fork else "")
            output.append(text)
            if len(output) >= limit:
                break
        return output

    def snapshot(self) -> MutationHistorySnapshot:
        operator_counts = {
            str(row["operator_id"]): int(row["accepted_count"])
            for row in self._connection.execute(
                "SELECT operator_id, accepted_count FROM operator_stats"
            )
        }
        target_counts = {
            str(row["category_id"]): int(row["accepted_count"])
            for row in self._connection.execute(
                "SELECT category_id, accepted_count FROM target_stats"
            )
        }
        path_counts = {
            str(row["path_signature"]): int(row["accepted_count"])
            for row in self._connection.execute(
                "SELECT path_signature, accepted_count FROM path_stats"
            )
        }
        totals = self._connection.execute(
            """
            SELECT
              (SELECT COUNT(*) FROM batches) AS batches,
              (SELECT COUNT(*) FROM candidates) AS accepted,
              (SELECT COUNT(*) FROM rejections) AS rejected
            """
        ).fetchone()
        return MutationHistorySnapshot(
            campaign_id=self.campaign_id,
            total_batches=int(totals["batches"]),
            total_accepted=int(totals["accepted"]),
            total_rejected=int(totals["rejected"]),
            operator_counts=operator_counts,
            target_counts=target_counts,
            path_counts=path_counts,
        )

    def commit_batch(self, batch: MutationBatch) -> MutationBatch:
        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT request_digest, batch_json FROM batches WHERE batch_id = ?",
                (batch.batch_id,),
            ).fetchone()
            if existing is not None:
                if existing["request_digest"] != batch.request_digest:
                    raise MutationIntegrityError(
                        "batch_id already exists with a different request digest"
                    )
                restored = MutationBatch.model_validate_json(existing["batch_json"])
                return restored.model_copy(update={"already_generated": True})
            order = int(
                connection.execute("SELECT COUNT(*) AS count FROM batches").fetchone()["count"]
            )
            connection.execute(
                """
                INSERT INTO batches(
                    batch_id, parent_seed_id, request_digest, requested_count,
                    generated_count, exhausted, batch_json, created_order
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    batch.batch_id,
                    self._batch_parent(batch),
                    batch.request_digest,
                    batch.requested_count,
                    batch.generated_count,
                    int(batch.exhausted),
                    batch.model_dump_json(),
                    order,
                ),
            )
            for candidate in batch.accepted:
                connection.execute(
                    """
                    INSERT INTO candidates(
                        mutation_id, batch_id, parent_seed_id, operator_id,
                        dedupe_key, candidate_json, created_order
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        candidate.mutation_id,
                        batch.batch_id,
                        candidate.parent_seed_id,
                        candidate.operator_id,
                        candidate.dedupe_key,
                        candidate.model_dump_json(),
                        order,
                    ),
                )
                self._increment_operator(connection, candidate.operator_id, accepted=1)
                for category_id in candidate.target_risks:
                    connection.execute(
                        """
                        INSERT INTO target_stats(category_id, accepted_count)
                        VALUES (?, 1)
                        ON CONFLICT(category_id) DO UPDATE SET
                            accepted_count = accepted_count + 1
                        """,
                        (category_id,),
                    )
                if candidate.path_signature is None:
                    raise MutationIntegrityError(
                        "accepted mutation candidate is missing its path signature"
                    )
                connection.execute(
                    """
                    INSERT INTO path_stats(path_signature, accepted_count)
                    VALUES (?, 1)
                    ON CONFLICT(path_signature) DO UPDATE SET
                        accepted_count = accepted_count + 1
                    """,
                    (candidate.path_signature,),
                )
            for rejection in batch.rejected:
                connection.execute(
                    """
                    INSERT OR IGNORE INTO rejections(
                        attempt_id, batch_id, reason, rejection_json
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        rejection.attempt_id,
                        batch.batch_id,
                        rejection.reason.value,
                        rejection.model_dump_json(),
                    ),
                )
                if rejection.operator_id:
                    self._increment_operator(connection, rejection.operator_id, rejected=1)
        return batch

    @staticmethod
    def _batch_parent(batch: MutationBatch) -> str:
        if batch.accepted:
            return batch.accepted[0].parent_seed_id
        if batch.rejected:
            return batch.rejected[0].parent_seed_id
        return "unknown"


    @staticmethod
    def _increment_operator(
        connection: sqlite3.Connection,
        operator_id: str,
        *,
        accepted: int = 0,
        rejected: int = 0,
    ) -> None:
        connection.execute(
            """
            INSERT INTO operator_stats(operator_id, accepted_count, rejected_count)
            VALUES (?, ?, ?)
            ON CONFLICT(operator_id) DO UPDATE SET
                accepted_count = accepted_count + excluded.accepted_count,
                rejected_count = rejected_count + excluded.rejected_count
            """,
            (operator_id, accepted, rejected),
        )

    def _create_schema(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS metadata(
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS batches(
                batch_id TEXT PRIMARY KEY,
                parent_seed_id TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                requested_count INTEGER NOT NULL,
                generated_count INTEGER NOT NULL,
                exhausted INTEGER NOT NULL,
                batch_json TEXT NOT NULL,
                created_order INTEGER NOT NULL UNIQUE
            );
            CREATE TABLE IF NOT EXISTS candidates(
                mutation_id TEXT PRIMARY KEY,
                batch_id TEXT NOT NULL REFERENCES batches(batch_id),
                parent_seed_id TEXT NOT NULL,
                operator_id TEXT NOT NULL,
                dedupe_key TEXT NOT NULL UNIQUE,
                candidate_json TEXT NOT NULL,
                created_order INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_candidates_operator
                ON candidates(operator_id);
            CREATE TABLE IF NOT EXISTS rejections(
                attempt_id TEXT PRIMARY KEY,
                batch_id TEXT NOT NULL REFERENCES batches(batch_id),
                reason TEXT NOT NULL,
                rejection_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS operator_stats(
                operator_id TEXT PRIMARY KEY,
                accepted_count INTEGER NOT NULL,
                rejected_count INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS target_stats(
                category_id TEXT PRIMARY KEY,
                accepted_count INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS path_stats(
                path_signature TEXT PRIMARY KEY,
                accepted_count INTEGER NOT NULL
            );
            """
        )

    def _validate_metadata(self, expected: dict[str, str]) -> None:
        with self._transaction() as connection:
            for key, value in expected.items():
                row = connection.execute(
                    "SELECT value FROM metadata WHERE key = ?",
                    (key,),
                ).fetchone()
                if row is not None and row["value"] != value:
                    raise MutationIntegrityError(
                        f"mutation database {key} mismatch: {row['value']!r} != {value!r}"
                    )
                connection.execute(
                    "INSERT OR IGNORE INTO metadata(key, value) VALUES (?, ?)",
                    (key, value),
                )

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            yield self._connection
        except Exception:
            self._connection.rollback()
            raise
        else:
            self._connection.commit()
