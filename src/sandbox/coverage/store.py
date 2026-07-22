"""Transactional cumulative coverage persistence."""

from __future__ import annotations

import os
import sqlite3
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sandbox.coverage.behavior import BehaviorFeatureExtractor
from sandbox.coverage.correlation import BehaviorRiskCorrelator
from sandbox.coverage.exceptions import CoverageIntegrityError
from sandbox.coverage.heatmap import HeatmapGenerator
from sandbox.coverage.models import (
    BehaviorProfile,
    CoverageInput,
    CoverageResult,
    CoverageSnapshot,
    RiskDepthChange,
    RiskHit,
)
from sandbox.coverage.risk import RiskRecognizer
from sandbox.coverage.risk_scope import CampaignRiskScopeIndex
from sandbox.coverage.taxonomy import RiskTaxonomyIndex
from sandbox.replay.normalizer import normalize_behavior_trace


class CoverageStore:
    def __init__(
        self,
        root: Path,
        campaign_id: str,
        taxonomy: RiskTaxonomyIndex,
        *,
        risk_scope: CampaignRiskScopeIndex | None = None,
        extractor: BehaviorFeatureExtractor | None = None,
        recognizer: RiskRecognizer | None = None,
        correlator: BehaviorRiskCorrelator | None = None,
        behavior_delta_weight: float = 0.5,
        risk_delta_weight: float = 0.5,
        auto_snapshot_interval: int = 10,
        busy_timeout_ms: int = 5_000,
    ) -> None:
        if not campaign_id or campaign_id in {".", ".."} or any(
            character in campaign_id for character in "/\\:"
        ):
            raise CoverageIntegrityError("invalid campaign_id")
        if behavior_delta_weight < 0 or risk_delta_weight < 0:
            raise CoverageIntegrityError("coverage delta weights must be non-negative")
        self.campaign_id = campaign_id
        self.taxonomy = taxonomy
        self.risk_scope = risk_scope or CampaignRiskScopeIndex.all_reachable(taxonomy)
        self.extractor = extractor or BehaviorFeatureExtractor()
        self.recognizer = recognizer or RiskRecognizer(taxonomy)
        self.correlator = correlator or BehaviorRiskCorrelator()
        self.behavior_delta_weight = behavior_delta_weight
        self.risk_delta_weight = risk_delta_weight
        self.auto_snapshot_interval = auto_snapshot_interval
        base = root.resolve()
        base.mkdir(parents=True, exist_ok=True)
        self.root = (base / campaign_id).resolve()
        if base not in self.root.parents:
            raise CoverageIntegrityError("campaign path escapes coverage root")
        self.root.mkdir(parents=True, exist_ok=True)
        self.snapshot_root = self.root / "snapshots"
        self.snapshot_root.mkdir(parents=True, exist_ok=True)
        self.database_path = self.root / "coverage.db"
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
            self._validate_metadata()
        except Exception:
            self._connection.close()
            raise

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> CoverageStore:
        return self

    def __exit__(self, *_args) -> None:
        self.close()

    def evaluate(self, coverage_input: CoverageInput) -> CoverageResult:
        normalized = normalize_behavior_trace(coverage_input.events)
        profile = self.extractor.extract(
            trajectory_id=coverage_input.trajectory_id,
            execution_id=coverage_input.execution_id,
            events=normalized,
        )
        hits = self.recognizer.recognize(coverage_input)
        created = False

        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT input_digest, result_json FROM evaluations WHERE trajectory_id = ?",
                (coverage_input.trajectory_id,),
            ).fetchone()
            if existing is not None:
                if existing["input_digest"] != coverage_input.input_digest:
                    raise CoverageIntegrityError(
                        "trajectory_id already exists with a different input_digest"
                    )
                result = CoverageResult.model_validate_json(existing["result_json"])
                result = result.model_copy(update={"already_evaluated": True})
            else:
                result = self._calculate_result(connection, coverage_input, profile, hits)
                self._ingest(connection, coverage_input, profile, result)
                created = True

        if created and self.auto_snapshot_interval > 0:
            total = self.total_trajectories()
            if total % self.auto_snapshot_interval == 0:
                self.write_snapshot(self.snapshot())
        return result

    def snapshot(self, *, include_heatmap: bool = True) -> CoverageSnapshot:
        depths = self.all_max_depths()
        leaf_ids = self.taxonomy.leaf_ids

        def ratio(minimum: int) -> float:
            return sum(depths.get(category_id, 0) >= minimum for category_id in leaf_ids) / max(
                1, len(leaf_ids)
            )

        def applicable_ratio(minimum: int) -> float | None:
            eligible = self.risk_scope.eligible_ids(minimum)
            if not eligible:
                return None
            return sum(depths.get(category_id, 0) >= minimum for category_id in eligible) / len(
                eligible
            )

        def uncovered(minimum: int) -> list[str]:
            return [
                category_id
                for category_id in self.risk_scope.eligible_ids(minimum)
                if depths.get(category_id, 0) < minimum
            ]

        scope_exceeded = {
            category_id: depth
            for category_id, depth in depths.items()
            if (
                self.risk_scope.max_reachable_depth(category_id) is None
                or depth > self.risk_scope.max_reachable_depth(category_id)
            )
        }

        heatmap = (
            HeatmapGenerator(self.taxonomy).generate(self.all_profiles(), self.all_hits())
            if include_heatmap
            else []
        )
        return CoverageSnapshot(
            campaign_id=self.campaign_id,
            taxonomy_version=self.taxonomy.taxonomy_version,
            total_trajectories=self.total_trajectories(),
            total_features=len(self.global_features()),
            total_risk_categories=sum(
                depths.get(category_id, 0) >= 1 for category_id in leaf_ids
            ),
            unique_behavior_profiles=len(self.unique_profiles()),
            intent_coverage=ratio(1),
            behavior_coverage=ratio(2),
            impact_coverage=ratio(3),
            risk_depths={
                category_id: depths.get(category_id, 0) for category_id in leaf_ids
            },
            risk_scope_version=self.risk_scope.scope_version,
            applicable_risk_categories=len(self.risk_scope.category_ids),
            applicable_intent_coverage=applicable_ratio(1),
            applicable_behavior_coverage=applicable_ratio(2),
            applicable_impact_coverage=applicable_ratio(3),
            not_applicable_risk_categories=sorted(
                set(leaf_ids) - set(self.risk_scope.category_ids)
            ),
            uncovered_intent_categories=uncovered(1),
            uncovered_behavior_categories=uncovered(2),
            uncovered_impact_categories=uncovered(3),
            scope_exceeded_categories=scope_exceeded,
            heatmap_data=[cell.model_dump(mode="json") for cell in heatmap],
        )

    def write_snapshot(self, snapshot: CoverageSnapshot) -> Path:
        destination = self.snapshot_root / f"snapshot-{snapshot.total_trajectories:06d}.json"
        payload = snapshot.model_dump_json(indent=2).encode("utf-8") + b"\n"
        fd, temporary_name = tempfile.mkstemp(prefix=".snapshot-", dir=self.snapshot_root)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
        return destination

    def total_trajectories(self) -> int:
        row = self._connection.execute("SELECT COUNT(*) AS count FROM evaluations").fetchone()
        return int(row["count"])

    def global_features(
        self,
        connection: sqlite3.Connection | None = None,
    ) -> set[tuple[str, str]]:
        active = connection or self._connection
        return {
            (str(row["kind"]), str(row["value"]))
            for row in active.execute("SELECT kind, value FROM features")
        }

    def unique_profiles(self) -> set[str]:
        return {
            str(row["profile_hash"])
            for row in self._connection.execute("SELECT profile_hash FROM profiles")
        }

    def all_max_depths(
        self,
        connection: sqlite3.Connection | None = None,
    ) -> dict[str, int]:
        active = connection or self._connection
        return {
            str(row["category_id"]): int(row["max_depth"])
            for row in active.execute("SELECT category_id, max_depth FROM risk_depths")
        }

    def max_depth(self, category_id: str) -> int:
        return self.all_max_depths().get(category_id, 0)

    def set_schedule_weight(self, category_id: str, weight: float) -> None:
        if category_id not in self.taxonomy.leaf_ids:
            raise CoverageIntegrityError("schedule weights may only target leaf categories")
        if weight < 0:
            raise CoverageIntegrityError("schedule weight must be non-negative")
        with self._transaction() as connection:
            connection.execute(
                """
                INSERT INTO campaign_weights(category_id, schedule_weight)
                VALUES (?, ?)
                ON CONFLICT(category_id) DO UPDATE SET
                    schedule_weight = excluded.schedule_weight
                """,
                (category_id, weight),
            )

    def schedule_weights(self) -> dict[str, float]:
        return {
            str(row["category_id"]): float(row["schedule_weight"])
            for row in self._connection.execute(
                "SELECT category_id, schedule_weight FROM campaign_weights"
            )
        }

    def all_profiles(self) -> list[BehaviorProfile]:
        return [
            BehaviorProfile.model_validate_json(row["profile_json"])
            for row in self._connection.execute(
                "SELECT profile_json FROM trajectory_profiles ORDER BY rowid"
            )
        ]

    def all_hits(self, category_id: str | None = None) -> list[RiskHit]:
        if category_id is None:
            rows = self._connection.execute("SELECT hit_json FROM risk_hits ORDER BY id")
        else:
            rows = self._connection.execute(
                "SELECT hit_json FROM risk_hits WHERE category_id = ? ORDER BY id",
                (category_id,),
            )
        return [RiskHit.model_validate_json(row["hit_json"]) for row in rows]

    def all_results(self) -> list[CoverageResult]:
        return [
            CoverageResult.model_validate_json(row["result_json"])
            for row in self._connection.execute(
                "SELECT result_json FROM evaluations ORDER BY created_order"
            )
        ]

    def _calculate_result(
        self,
        connection: sqlite3.Connection,
        coverage_input: CoverageInput,
        profile: BehaviorProfile,
        hits: list[RiskHit],
    ) -> CoverageResult:
        previous_features = self.global_features(connection)
        current_features = {
            (feature.kind.value, feature.value) for feature in profile.features
        }
        new_feature_keys = current_features - previous_features
        next_features = previous_features | current_features

        previous_depths = self.all_max_depths(connection)
        next_depths = dict(previous_depths)
        leaf_ids = set(self.taxonomy.leaf_ids)
        for hit in hits:
            if hit.category_id not in leaf_ids:
                raise CoverageIntegrityError(f"risk hit is not a leaf category: {hit.category_id}")
            next_depths[hit.category_id] = max(
                next_depths.get(hit.category_id, 0),
                hit.depth,
            )

        new_categories = sorted(
            category_id
            for category_id, depth in next_depths.items()
            if depth >= 1 and previous_depths.get(category_id, 0) == 0
        )
        improved_depths = {
            category_id: depth
            for category_id, depth in next_depths.items()
            if depth > previous_depths.get(category_id, 0)
        }
        depth_changes = [
            RiskDepthChange(
                category_id=category_id,
                previous_depth=previous_depths.get(category_id, 0),
                current_depth=depth,
                depth_gain=depth - previous_depths.get(category_id, 0),
            )
            for category_id, depth in sorted(improved_depths.items())
        ]
        scope_exceeded = sorted(
            category_id
            for category_id, depth in next_depths.items()
            if (
                self.risk_scope.max_reachable_depth(category_id) is None
                or depth > self.risk_scope.max_reachable_depth(category_id)
            )
        )
        total_leaves = len(leaf_ids)

        def cumulative_ratio(minimum: int) -> float:
            return sum(
                next_depths.get(category_id, 0) >= minimum for category_id in leaf_ids
            ) / max(1, total_leaves)

        previous_count = len(previous_features)
        new_count = len(new_feature_keys)
        behavior_growth_rate = (
            0.0
            if new_count == 0
            else 1.0
            if previous_count == 0
            else new_count / previous_count
        )
        behavior_delta = new_count / max(1, len(current_features))
        risk_delta = len(new_categories) / max(1, total_leaves)
        scope_weight_total = sum(
            self.taxonomy.report_weight(category_id)
            for category_id in self.risk_scope.category_ids
        )
        risk_progress_delta = 0.0
        if scope_weight_total > 0:
            progress = 0.0
            for change in depth_changes:
                max_reachable = self.risk_scope.max_reachable_depth(change.category_id)
                if max_reachable is None:
                    continue
                previous_effective = min(change.previous_depth, max_reachable)
                current_effective = min(change.current_depth, max_reachable)
                effective_gain = current_effective - previous_effective
                progress += (
                    self.taxonomy.report_weight(change.category_id)
                    * effective_gain
                    / max_reachable
                )
            risk_progress_delta = min(1.0, progress / scope_weight_total)
        risk_seed_delta = max(risk_delta, risk_progress_delta)
        behavior_risk_links = self.correlator.correlate(
            coverage_input,
            profile,
            hits,
            new_behavior_keys=new_feature_keys,
            new_risk_categories=set(new_categories),
            improved_risk_categories=set(improved_depths),
        )
        return CoverageResult(
            trajectory_id=coverage_input.trajectory_id,
            execution_id=coverage_input.execution_id,
            input_digest=coverage_input.input_digest,
            behavior_profile_hash=profile.profile_hash,
            behavior_features_total=profile.feature_count,
            new_behavior_features=sorted(
                f"{kind}:{value}" for kind, value in new_feature_keys
            ),
            new_behavior_count=new_count,
            cumulative_behavior_count=len(next_features),
            behavior_growth_rate=behavior_growth_rate,
            risk_hits=hits,
            new_risk_categories=new_categories,
            new_risk_count=len(new_categories),
            improved_risk_depths=improved_depths,
            risk_depth_changes=depth_changes,
            risk_progress_delta=risk_progress_delta,
            risk_seed_delta=risk_seed_delta,
            risk_scope_exceeded=scope_exceeded,
            behavior_risk_links=behavior_risk_links,
            cumulative_risk_count=sum(
                next_depths.get(category_id, 0) >= 1 for category_id in leaf_ids
            ),
            intent_coverage=cumulative_ratio(1),
            behavior_coverage=cumulative_ratio(2),
            impact_coverage=cumulative_ratio(3),
            behavior_delta=behavior_delta,
            risk_delta=risk_delta,
            combined_delta=(
                self.behavior_delta_weight * behavior_delta
                + self.risk_delta_weight * risk_seed_delta
            ),
        )

    def _ingest(
        self,
        connection: sqlite3.Connection,
        coverage_input: CoverageInput,
        profile: BehaviorProfile,
        result: CoverageResult,
    ) -> None:
        created_order = int(
            connection.execute("SELECT COUNT(*) AS count FROM evaluations").fetchone()["count"]
        )
        connection.execute(
            """
            INSERT INTO evaluations(
                trajectory_id, execution_id, input_digest, result_json, created_order
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                coverage_input.trajectory_id,
                coverage_input.execution_id,
                coverage_input.input_digest,
                result.model_dump_json(),
                created_order,
            ),
        )
        for feature in profile.features:
            connection.execute(
                "INSERT OR IGNORE INTO features(kind, value, first_trajectory_id) VALUES (?, ?, ?)",
                (feature.kind.value, feature.value, coverage_input.trajectory_id),
            )
        connection.execute(
            "INSERT OR IGNORE INTO profiles(profile_hash, profile_json) VALUES (?, ?)",
            (profile.profile_hash, profile.model_dump_json()),
        )
        connection.execute(
            """
            INSERT INTO trajectory_profiles(trajectory_id, profile_hash, profile_json)
            VALUES (?, ?, ?)
            """,
            (coverage_input.trajectory_id, profile.profile_hash, profile.model_dump_json()),
        )
        for hit in result.risk_hits:
            connection.execute(
                """
                INSERT INTO risk_hits(trajectory_id, category_id, depth, hit_json)
                VALUES (?, ?, ?, ?)
                """,
                (
                    coverage_input.trajectory_id,
                    hit.category_id,
                    hit.depth,
                    hit.model_dump_json(),
                ),
            )
            connection.execute(
                """
                INSERT INTO risk_depths(category_id, max_depth)
                VALUES (?, ?)
                ON CONFLICT(category_id) DO UPDATE SET
                    max_depth = MAX(max_depth, excluded.max_depth)
                """,
                (hit.category_id, hit.depth),
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

    def _create_schema(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS metadata(
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS evaluations(
                trajectory_id TEXT PRIMARY KEY,
                execution_id TEXT NOT NULL,
                input_digest TEXT NOT NULL,
                result_json TEXT NOT NULL,
                created_order INTEGER NOT NULL UNIQUE
            );
            CREATE TABLE IF NOT EXISTS features(
                kind TEXT NOT NULL,
                value TEXT NOT NULL,
                first_trajectory_id TEXT NOT NULL,
                PRIMARY KEY(kind, value)
            );
            CREATE TABLE IF NOT EXISTS profiles(
                profile_hash TEXT PRIMARY KEY,
                profile_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS trajectory_profiles(
                trajectory_id TEXT PRIMARY KEY REFERENCES evaluations(trajectory_id),
                profile_hash TEXT NOT NULL REFERENCES profiles(profile_hash),
                profile_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS risk_hits(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                trajectory_id TEXT NOT NULL REFERENCES evaluations(trajectory_id),
                category_id TEXT NOT NULL,
                depth INTEGER NOT NULL CHECK(depth BETWEEN 1 AND 3),
                hit_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS risk_depths(
                category_id TEXT PRIMARY KEY,
                max_depth INTEGER NOT NULL CHECK(max_depth BETWEEN 1 AND 3)
            );
            CREATE TABLE IF NOT EXISTS campaign_weights(
                category_id TEXT PRIMARY KEY,
                schedule_weight REAL NOT NULL CHECK(schedule_weight >= 0)
            );
            """
        )

    def _validate_metadata(self) -> None:
        expected = {
            "campaign_id": self.campaign_id,
            "taxonomy_version": self.taxonomy.taxonomy_version,
            "risk_scope_version": self.risk_scope.scope_version,
            "risk_scope_digest": self.risk_scope.digest,
            "schema_version": "1.0",
        }
        with self._transaction() as connection:
            for key, value in expected.items():
                row = connection.execute(
                    "SELECT value FROM metadata WHERE key = ?",
                    (key,),
                ).fetchone()
                if row is not None and row["value"] != value:
                    raise CoverageIntegrityError(
                        f"coverage database {key} mismatch: {row['value']!r} != {value!r}"
                    )
                connection.execute(
                    "INSERT OR IGNORE INTO metadata(key, value) VALUES (?, ?)",
                    (key, value),
                )
