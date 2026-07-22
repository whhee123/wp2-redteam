"""Project cumulative coverage into mutation-facing feedback."""

from __future__ import annotations

from collections import Counter

from sandbox.coverage.models import CoverageSnapshot
from sandbox.coverage.risk_scope import CampaignRiskScopeIndex
from sandbox.coverage.taxonomy import RiskTaxonomyIndex
from sandbox.mutation.exceptions import MutationTargetError
from sandbox.mutation.models import (
    LinkNoveltySummary,
    MutationFeedback,
    MutationHistorySnapshot,
    MutationSeed,
    RiskGap,
)
from sandbox.replay.digests import sha256_digest


class MutationFeedbackBuilder:
    def __init__(
        self,
        taxonomy: RiskTaxonomyIndex,
        risk_scope: CampaignRiskScopeIndex,
    ) -> None:
        self.taxonomy = taxonomy
        self.risk_scope = risk_scope

    def build(
        self,
        seed: MutationSeed,
        snapshot: CoverageSnapshot,
        *,
        schedule_weights: dict[str, float] | None = None,
        history: MutationHistorySnapshot | None = None,
    ) -> MutationFeedback:
        if snapshot.taxonomy_version != self.taxonomy.taxonomy_version:
            raise MutationTargetError("coverage snapshot taxonomy version mismatch")
        if snapshot.risk_scope_version != self.risk_scope.scope_version:
            raise MutationTargetError("coverage snapshot risk scope version mismatch")
        leaf_ids = set(self.taxonomy.leaf_ids)
        if set(snapshot.risk_depths) != leaf_ids:
            raise MutationTargetError(
                "coverage snapshot must contain explicit risk_depths for every leaf"
            )
        weights = schedule_weights or {}
        gaps = []
        for category_id in self.risk_scope.category_ids:
            reachable = self.risk_scope.max_reachable_depth(category_id)
            assert reachable is not None
            observed = snapshot.risk_depths[category_id]
            gap = max(0, reachable - observed) / reachable
            gaps.append(
                RiskGap(
                    category_id=category_id,
                    label=self.taxonomy.get(category_id).label,
                    observed_depth=observed,
                    max_reachable_depth=reachable,
                    next_target_depth=min(observed + 1, reachable),
                    gap_ratio=gap,
                    report_weight=self.taxonomy.report_weight(category_id),
                    schedule_weight=weights.get(category_id, 1.0),
                )
            )
        gaps.sort(
            key=lambda item: (
                -(item.gap_ratio * item.report_weight * item.schedule_weight),
                item.category_id,
            )
        )
        result = seed.coverage_result
        links = result.behavior_risk_links if result else []
        link_counts = Counter(link.novelty_class for link in links)
        linked_categories = sorted({link.risk_category_id for link in links})
        resolved_history = history or MutationHistorySnapshot(campaign_id=snapshot.campaign_id)
        return MutationFeedback(
            campaign_id=snapshot.campaign_id,
            taxonomy_version=snapshot.taxonomy_version,
            risk_scope_version=snapshot.risk_scope_version,
            coverage_snapshot_digest=sha256_digest(snapshot),
            parent_coverage_digest=sha256_digest(result) if result else None,
            behavior_profile_hash=seed.behavior_profile_hash,
            risk_gaps=gaps,
            parent_behavior_delta=result.behavior_delta if result else 0.0,
            parent_risk_seed_delta=result.risk_seed_delta if result else 0.0,
            parent_combined_delta=result.combined_delta if result else 0.0,
            link_novelty=LinkNoveltySummary(
                both_new=link_counts["both_new"],
                behavior_new=link_counts["behavior_new"],
                risk_new=link_counts["risk_new"],
                known_pair=link_counts["known_pair"],
                linked_risk_categories=linked_categories,
            ),
            recent_operator_counts=resolved_history.operator_counts,
            recent_target_counts=resolved_history.target_counts,
            recent_path_counts=resolved_history.path_counts,
        )
