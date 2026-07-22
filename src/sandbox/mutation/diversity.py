"""Exact, near-duplicate, and batch diversity checks."""

from __future__ import annotations

import math
from dataclasses import dataclass

from sandbox.mutation.config import MutationDiversityConfig
from sandbox.mutation.models import MutationCandidate, MutationRejectionReason
from sandbox.mutation.similarity import SimilarityBackend


@dataclass(frozen=True)
class DiversityDecision:
    accepted: bool
    reason: MutationRejectionReason | None = None
    detail: str = ""
    maximum_similarity: float = 0.0


class DiversityGate:
    def __init__(
        self,
        backend: SimilarityBackend,
        config: MutationDiversityConfig | None = None,
    ) -> None:
        self.backend = backend
        self.config = config or MutationDiversityConfig()

    async def check(
        self,
        candidate: MutationCandidate,
        *,
        parent_prompt: str,
        accepted: list[MutationCandidate],
        historical_prompts: list[str],
        historical_dedupe_keys: set[str],
        requested_count: int,
    ) -> DiversityDecision:
        if candidate.dedupe_key in historical_dedupe_keys or any(
            item.dedupe_key == candidate.dedupe_key for item in accepted
        ):
            return DiversityDecision(
                accepted=False,
                reason=MutationRejectionReason.EXACT_DUPLICATE,
                detail="candidate dedupe key already exists",
                maximum_similarity=1.0,
            )
        text = candidate.prompt or (candidate.fork.content if candidate.fork else "")
        comparison_prompts = [parent_prompt, *historical_prompts]
        comparison_prompts.extend(
            item.prompt or (item.fork.content if item.fork else "") for item in accepted
        )
        maximum_similarity = 0.0
        for known in comparison_prompts:
            maximum_similarity = max(
                maximum_similarity,
                await self.backend.similarity(text, known),
            )
        if maximum_similarity >= self.config.near_duplicate_threshold:
            return DiversityDecision(
                accepted=False,
                reason=MutationRejectionReason.NEAR_DUPLICATE,
                detail=(
                    f"maximum {self.backend.capability} similarity "
                    f"{maximum_similarity:.4f} exceeds threshold"
                ),
                maximum_similarity=maximum_similarity,
            )
        operator_limit = max(1, math.ceil(requested_count * self.config.max_operator_share))
        if sum(item.operator_id == candidate.operator_id for item in accepted) >= operator_limit:
            return DiversityDecision(
                accepted=False,
                reason=MutationRejectionReason.BATCH_OPERATOR_QUOTA,
                detail=f"operator share exceeds {self.config.max_operator_share:.2f}",
                maximum_similarity=maximum_similarity,
            )
        target_limit = max(1, math.ceil(requested_count * self.config.max_target_share))
        primary_target = candidate.target_risks[0]
        if sum(primary_target in item.target_risks for item in accepted) >= target_limit:
            return DiversityDecision(
                accepted=False,
                reason=MutationRejectionReason.BATCH_TARGET_QUOTA,
                detail=f"target share exceeds {self.config.max_target_share:.2f}",
                maximum_similarity=maximum_similarity,
            )
        return DiversityDecision(accepted=True, maximum_similarity=maximum_similarity)
