"""Honest, capability-aware mutation priority calculation."""

from __future__ import annotations

import math

from sandbox.mutation.config import MutationPriorityConfig
from sandbox.mutation.models import MutationFeedback, MutationSeed


class MutationPriorityCalculator:
    def __init__(self, config: MutationPriorityConfig | None = None) -> None:
        self.config = config or MutationPriorityConfig()

    @staticmethod
    def _link_novelty(feedback: MutationFeedback) -> float:
        novelty = feedback.link_novelty
        if novelty.both_new:
            return 1.0
        if novelty.risk_new:
            return 0.8
        if novelty.behavior_new:
            return 0.55
        if novelty.known_pair:
            return 0.1
        return 0.0

    def parent_case_value(self, seed: MutationSeed, feedback: MutationFeedback) -> float:
        if seed.coverage_result is None:
            return self.config.cold_start_parent_value
        value = (
            0.35 * min(1.0, feedback.parent_risk_seed_delta)
            + 0.30 * min(1.0, feedback.parent_behavior_delta)
            + 0.20 * min(1.0, feedback.parent_combined_delta)
            + 0.15 * self._link_novelty(feedback)
        )
        return max(0.0, min(1.0, value))

    def score(
        self,
        *,
        seed: MutationSeed,
        feedback: MutationFeedback,
        target_risks: list[str],
        operator_id: str,
        similarity: float,
    ) -> tuple[dict[str, float], float]:
        gaps = {gap.category_id: gap for gap in feedback.risk_gaps}
        selected = [gaps[item] for item in target_risks if item in gaps]
        weighted_total = sum(item.report_weight * item.schedule_weight for item in selected)
        target_gap = (
            sum(item.gap_ratio * item.report_weight * item.schedule_weight for item in selected)
            / weighted_total
            if weighted_total
            else 0.0
        )
        operator_counts = feedback.recent_operator_counts
        maximum_operator_count = max(operator_counts.values(), default=0)
        operator_underuse = 1.0 - operator_counts.get(operator_id, 0) / max(
            1, maximum_operator_count
        )
        path_key = self.path_signature(seed, operator_id, target_risks)
        maximum_path_count = max(feedback.recent_path_counts.values(), default=0)
        path_frequency = (
            math.log1p(feedback.recent_path_counts.get(path_key, 0))
            / math.log1p(maximum_path_count)
            if maximum_path_count
            else 0.0
        )
        parent_value = self.parent_case_value(seed, feedback)
        components = {
            "target_risk_gap": target_gap,
            "parent_case_value": parent_value,
            "operator_underuse": operator_underuse,
            "similarity": similarity,
            "path_frequency": path_frequency,
        }
        score = (
            self.config.target_risk_gap_weight * target_gap
            + self.config.parent_case_value_weight * parent_value
            + self.config.operator_underuse_weight * operator_underuse
            - self.config.similarity_penalty * similarity
            - self.config.path_frequency_penalty * path_frequency
        )
        return components, max(0.0, min(1.0, score))

    @staticmethod
    def path_signature(seed: MutationSeed, operator_id: str, target_risks: list[str]) -> str:
        profile = seed.behavior_profile_hash or f"cold-start:{seed.seed_id}"
        return f"{profile}|{operator_id}|{','.join(sorted(target_risks))}"
