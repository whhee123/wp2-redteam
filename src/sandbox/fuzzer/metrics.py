"""Campaign metric aggregation and atomic snapshot output."""

from __future__ import annotations

import math
import os
import tempfile
from pathlib import Path

from sandbox.coverage.models import CoverageSnapshot
from sandbox.fuzzer.models import CampaignSnapshot, fuzzer_digest
from sandbox.fuzzer.store import FuzzerStore


def percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, math.ceil(quantile * len(ordered)) - 1)
    return float(ordered[index])


class CampaignMetrics:
    def __init__(self, store: FuzzerStore) -> None:
        self.store = store

    def snapshot(
        self,
        coverage: CoverageSnapshot,
        *,
        active_runtime_seconds: float,
        queue_length: int = 0,
        active_workers: int = 0,
        uncleared_containers: int = 0,
    ) -> CampaignSnapshot:
        observations = self.store.observations()
        attempts = [
            event
            for event in self.store.audit_events()
            if event["event_type"] == "execution_finished"
        ]
        durations = self.store.execution_durations_ms()
        hours = active_runtime_seconds / 3600
        return CampaignSnapshot(
            campaign_id=self.store.campaign_id,
            status=self.store.status(),
            stop_reason=self.store.stop_reason(),
            iteration=self.store.iteration(),
            active_runtime_seconds=active_runtime_seconds,
            seed_counts=self.store.counts("seeds", "status"),
            work_counts=self.store.counts("work_items", "status"),
            corpus_size=len(self.store.corpus_entries()),
            successful_executions=sum(
                1 for item in observations if item.score_verdict != "infrastructure_error"
            ),
            case_failures=sum(1 for item in observations if item.score_verdict is None),
            infrastructure_failures=max(0, len(attempts) - len(observations)),
            retries=int(self.store.campaign_values()["retry_count"]),
            uncleared_containers=uncleared_containers,
            behavior_features=coverage.total_features,
            behavior_profiles=coverage.unique_behavior_profiles,
            risk_categories=coverage.total_risk_categories,
            applicable_intent_coverage=coverage.applicable_intent_coverage,
            applicable_behavior_coverage=coverage.applicable_behavior_coverage,
            applicable_impact_coverage=coverage.applicable_impact_coverage,
            new_behavior_per_hour=(
                sum(item.behavior_delta > 0 for item in observations) / hours if hours else 0
            ),
            risk_depth_gain_per_hour=(
                sum(item.risk_delta for item in observations) / hours if hours else 0
            ),
            execution_p50_ms=percentile(durations, 0.50),
            execution_p95_ms=percentile(durations, 0.95),
            queue_length=queue_length,
            active_workers=active_workers,
        )

    def write(self, snapshot: CampaignSnapshot) -> Path:
        destination = self.store.snapshot_root / f"snapshot-{snapshot.iteration:08d}.json"
        payload = snapshot.model_dump_json(indent=2).encode("utf-8") + b"\n"
        fd, name = tempfile.mkstemp(prefix=".campaign-snapshot-", dir=destination.parent)
        temporary = Path(name)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
        self.store.save_metric_snapshot(snapshot.model_dump_json(), fuzzer_digest(snapshot))
        return destination
