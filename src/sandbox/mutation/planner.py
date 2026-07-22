"""Deterministic target and operator planning."""

from __future__ import annotations

from collections import defaultdict

from sandbox.coverage.risk_scope import CampaignRiskScopeIndex
from sandbox.mutation.exceptions import MutationTargetError
from sandbox.mutation.models import (
    MutationCandidateKind,
    MutationFeedback,
    MutationPlan,
    MutationProviderKind,
    MutationSeed,
    PlannedMutation,
)
from sandbox.mutation.normalizer import stable_digest
from sandbox.mutation.operators import MutationOperatorRegistryIndex


class MutationPlanner:
    def __init__(
        self,
        registry: MutationOperatorRegistryIndex,
        risk_scope: CampaignRiskScopeIndex,
        *,
        oversample_factor: int = 3,
    ) -> None:
        self.registry = registry
        self.risk_scope = risk_scope
        self.oversample_factor = oversample_factor

    def plan(
        self,
        seed: MutationSeed,
        feedback: MutationFeedback,
        count: int,
        *,
        provider: MutationProviderKind,
        target_risk: str | None = None,
        operator_id: str | None = None,
    ) -> MutationPlan:
        if count < 1:
            raise MutationTargetError("mutation count must be positive")
        gaps = [gap for gap in feedback.risk_gaps if gap.gap_ratio > 0]
        if target_risk is not None:
            gaps = [gap for gap in feedback.risk_gaps if gap.category_id == target_risk]
            if not gaps:
                raise MutationTargetError(f"target risk is not reachable: {target_risk}")
        if not gaps:
            gaps = list(feedback.risk_gaps)
        if not gaps:
            raise MutationTargetError("campaign risk scope contains no mutation targets")

        allocations: dict[tuple[str, str, int], int] = defaultdict(int)
        for index in range(count):
            gap = gaps[index % len(gaps)]
            candidate_kind = (
                MutationCandidateKind.FORK
                if operator_id == "branch_prompt_injection"
                else MutationCandidateKind.PROMPT
            )
            compatible = self.registry.compatible(
                category_id=gap.category_id,
                target_depth=gap.next_target_depth,
                provider=provider,
                candidate_kind=candidate_kind,
                scope=self.risk_scope,
            )
            if operator_id is not None:
                compatible = tuple(item for item in compatible if item.operator_id == operator_id)
            if candidate_kind == MutationCandidateKind.FORK and not (
                seed.replay_id and seed.checkpoint_id
            ):
                compatible = ()
            if not compatible:
                if operator_id is not None:
                    raise MutationTargetError(
                        f"operator {operator_id} is incompatible with {gap.category_id}"
                    )
                continue
            chosen = min(
                compatible,
                key=lambda item: (
                    feedback.recent_operator_counts.get(item.operator_id, 0)
                    + sum(
                        amount
                        for (known_operator, _target, _depth), amount in allocations.items()
                        if known_operator == item.operator_id
                    ),
                    item.operator_id,
                ),
            )
            allocations[(chosen.operator_id, gap.category_id, gap.next_target_depth)] += 1
        if not allocations:
            raise MutationTargetError("no compatible mutation operator allocation")
        items = [
            PlannedMutation(
                operator_id=operator,
                target_risks=[target],
                target_depths={target: depth},
                requested_count=amount,
                initial_priority=next(
                    gap.gap_ratio for gap in feedback.risk_gaps if gap.category_id == target
                ),
            )
            for (operator, target, depth), amount in sorted(allocations.items())
        ]
        feedback_digest = stable_digest(feedback)
        plan_payload = {
            "seed_id": seed.seed_id,
            "feedback_digest": feedback_digest,
            "provider": provider.value,
            "items": [item.model_dump(mode="json") for item in items],
        }
        return MutationPlan(
            plan_id=stable_digest(plan_payload),
            feedback_digest=feedback_digest,
            items=items,
            oversample_count=min(count * self.oversample_factor, 96),
        )
