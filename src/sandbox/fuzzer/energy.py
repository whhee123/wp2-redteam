"""Deterministic, explainable energy assignment."""

from __future__ import annotations

import math

from sandbox.coverage.models import CoverageSnapshot
from sandbox.fuzzer.config import EnergyConfig
from sandbox.fuzzer.models import EnergyDecision, SeedRecord, fuzzer_digest
from sandbox.fuzzer.store import FuzzerStore
from sandbox.mutation.models import MutationFeedback


class EnergyScheduler:
    def __init__(self, config: EnergyConfig, store: FuzzerStore, campaign_id: str) -> None:
        self.config = config
        self.store = store
        self.campaign_id = campaign_id

    def assign(
        self,
        seed: SeedRecord,
        feedback: MutationFeedback,
        snapshot: CoverageSnapshot,
        *,
        iteration: int,
    ) -> EnergyDecision:
        novelty = 1 + self.config.novelty_weight * _clamp(feedback.parent_combined_delta)
        relevant = [gap for gap in feedback.risk_gaps if gap.category_id in seed.case.target_risks]
        gaps = relevant or feedback.risk_gaps
        denominator = sum(gap.report_weight * gap.schedule_weight for gap in gaps)
        weighted_gap = (
            sum(gap.gap_ratio * gap.report_weight * gap.schedule_weight for gap in gaps)
            / max(1e-12, denominator)
            if gaps
            else 0.0
        )
        risk_gap = 1 + self.config.risk_gap_weight * _clamp(weighted_gap)
        frequency = self.store.profile_execution_count(seed.behavior_profile_hash)
        rarity = 1 + self.config.rarity_weight / math.sqrt(max(1, frequency))
        attempts = seed.successful_executions + seed.failed_executions
        stability = (
            1.0 if attempts == 0 else _clamp(seed.successful_executions / attempts, 0.25, 1.0)
        )
        stagnation = max(
            self.config.minimum_stagnation_factor,
            self.config.stagnation_decay
            ** (seed.consecutive_no_gain // self.config.stagnation_decay_interval),
        )
        depth = max(0.25, 1 - seed.mutation_depth / self.config.max_mutation_depth)
        raw = self.config.base_energy * novelty * risk_gap * rarity * stability * stagnation * depth
        assigned = min(self.config.max_energy, max(self.config.min_energy, round(raw)))
        snapshot_digest = fuzzer_digest(snapshot)
        seed_digest = fuzzer_digest(seed)
        identity = {
            "campaign_id": self.campaign_id,
            "seed_id": seed.seed_id,
            "iteration": iteration,
            "formula_version": self.config.formula_version,
            "coverage_snapshot_digest": snapshot_digest,
            "seed_state_digest": seed_digest,
            "factors": [novelty, risk_gap, rarity, stability, stagnation, depth],
            "assigned_energy": assigned,
        }
        decision = EnergyDecision(
            decision_id=fuzzer_digest(identity),
            campaign_id=self.campaign_id,
            seed_id=seed.seed_id,
            iteration=iteration,
            base_energy=self.config.base_energy,
            novelty_factor=novelty,
            risk_gap_factor=risk_gap,
            rarity_factor=rarity,
            stability_factor=stability,
            stagnation_factor=stagnation,
            depth_factor=depth,
            assigned_energy=assigned,
            formula_version=self.config.formula_version,
            coverage_snapshot_digest=snapshot_digest,
            seed_state_digest=seed_digest,
        )
        return self.store.save_energy_decision(decision)


def _clamp(value: float, minimum: float = 0.0, maximum: float = 1.0) -> float:
    return min(maximum, max(minimum, value))
