"""Coverage-guided semantic mutation orchestration."""

from __future__ import annotations

from sandbox.coverage.risk_scope import CampaignRiskScopeIndex
from sandbox.mutation.config import MutationConfig
from sandbox.mutation.diversity import DiversityGate
from sandbox.mutation.exceptions import MutationTargetError
from sandbox.mutation.models import (
    ForkMutationSpec,
    MutationBatch,
    MutationCandidate,
    MutationCandidateKind,
    MutationFeedback,
    MutationPlan,
    MutationRejectionReason,
    MutationSeed,
    RawMutationCandidate,
    RejectedMutation,
)
from sandbox.mutation.normalizer import (
    fork_dedupe_key,
    normalized_prompt_digest,
    prompt_dedupe_key,
    prompt_digest,
    stable_digest,
)
from sandbox.mutation.operators import MutationOperatorRegistryIndex
from sandbox.mutation.planner import MutationPlanner
from sandbox.mutation.priority import MutationPriorityCalculator
from sandbox.mutation.providers.base import MutationProvider
from sandbox.mutation.store import MutationStore


class SemanticMutator:
    def __init__(
        self,
        config: MutationConfig,
        registry: MutationOperatorRegistryIndex,
        risk_scope: CampaignRiskScopeIndex,
        provider: MutationProvider,
        diversity_gate: DiversityGate,
        priority: MutationPriorityCalculator,
        store: MutationStore,
    ) -> None:
        self.config = config
        self.registry = registry
        self.risk_scope = risk_scope
        self.provider = provider
        self.diversity_gate = diversity_gate
        self.priority = priority
        self.store = store
        self.planner = MutationPlanner(
            registry,
            risk_scope,
            oversample_factor=config.generation.oversample_factor,
        )

    async def mutate(
        self,
        seed: MutationSeed,
        feedback: MutationFeedback,
        count: int,
        *,
        random_seed: int,
        target_risk: str | None = None,
        operator_id: str | None = None,
    ) -> MutationBatch:
        if seed.mutation_depth >= self.config.generation.max_mutation_depth:
            raise MutationTargetError("seed reached maximum mutation depth")
        if count < 1 or count > self.config.generation.max_count:
            raise MutationTargetError("requested mutation count is outside configured bounds")
        request_digest = stable_digest(
            {
                "campaign_id": self.config.campaign_id,
                "seed_id": seed.seed_id,
                "feedback": feedback,
                "count": count,
                "provider": self.config.provider,
                "registry_digest": self.registry.digest,
                "random_seed": random_seed,
                "target_risk": target_risk,
                "operator_id": operator_id,
            }
        )
        batch_id = stable_digest(
            {
                "campaign_id": self.config.campaign_id,
                "seed_id": seed.seed_id,
                "request_digest": request_digest,
            }
        )
        existing = self.store.get_batch(batch_id)
        if existing is not None:
            if existing.request_digest != request_digest:
                raise MutationTargetError("batch identity conflicts with request digest")
            return existing.model_copy(update={"already_generated": True})

        plan = self.planner.plan(
            seed,
            feedback,
            count,
            provider=self.provider.kind,
            target_risk=target_risk,
            operator_id=operator_id,
        )
        accepted: list[MutationCandidate] = []
        rejected: list[RejectedMutation] = []
        historical_dedupe_keys = self.store.dedupe_keys()
        generated_count = 0
        raw_budget = self.config.generation.max_raw_candidates_per_batch

        for attempt in range(self.config.generation.max_generation_attempts):
            if len(accepted) >= count or generated_count >= raw_budget:
                break
            attempt_seed = int(
                stable_digest(
                    {"random_seed": random_seed, "attempt": attempt, "batch_id": batch_id}
                ).removeprefix("sha256:")[:16],
                16,
            )
            raw_count = min(plan.oversample_count, raw_budget - generated_count)
            raw_candidates = await self.provider.generate(
                seed,
                plan,
                count=raw_count,
                random_seed=attempt_seed,
            )
            for raw_index, raw in enumerate(raw_candidates):
                if len(accepted) >= count or generated_count >= raw_budget:
                    break
                generated_count += 1
                attempt_id = stable_digest(
                    {
                        "batch_id": batch_id,
                        "attempt": attempt,
                        "raw_index": raw_index,
                        "raw": raw,
                    }
                )
                planned = self._planned_item(raw, plan)
                if planned is None:
                    rejected.append(
                        self._rejection(
                            attempt_id,
                            seed,
                            raw,
                            MutationRejectionReason.INCOMPATIBLE_OPERATOR,
                            "candidate operator and targets do not match the plan",
                        )
                    )
                    continue
                try:
                    candidate = self._materialize(
                        seed,
                        feedback,
                        raw,
                        planned.target_depths,
                        attempt_seed,
                    )
                except (ValueError, MutationTargetError) as exc:
                    rejected.append(
                        self._rejection(
                            attempt_id,
                            seed,
                            raw,
                            MutationRejectionReason.INVALID_SCHEMA,
                            str(exc),
                        )
                    )
                    continue
                historical_prompts = self.store.recent_prompts(
                    candidate.target_risks,
                    limit=self.config.diversity.similarity_history_limit,
                )
                diversity = await self.diversity_gate.check(
                    candidate,
                    parent_prompt=seed.case.prompt,
                    accepted=accepted,
                    historical_prompts=historical_prompts,
                    historical_dedupe_keys=historical_dedupe_keys,
                    requested_count=count,
                )
                if not diversity.accepted:
                    rejected.append(
                        self._rejection(
                            attempt_id,
                            seed,
                            raw,
                            diversity.reason or MutationRejectionReason.NEAR_DUPLICATE,
                            diversity.detail,
                        )
                    )
                    continue
                components, score = self.priority.score(
                    seed=seed,
                    feedback=feedback,
                    target_risks=candidate.target_risks,
                    operator_id=candidate.operator_id,
                    similarity=diversity.maximum_similarity,
                )
                accepted.append(
                    candidate.model_copy(
                        update={
                            "priority_components": components,
                            "mutation_priority": score,
                        }
                    )
                )

        accepted.sort(key=lambda item: (-item.mutation_priority, item.mutation_id))
        batch = MutationBatch(
            batch_id=batch_id,
            campaign_id=self.config.campaign_id,
            request_digest=request_digest,
            requested_count=count,
            generated_count=generated_count,
            accepted=accepted[:count],
            rejected=rejected,
            exhausted=len(accepted) < count,
        )
        return self.store.commit_batch(batch)

    @staticmethod
    def _planned_item(raw: RawMutationCandidate, plan: MutationPlan):
        targets = sorted(raw.target_risks)
        return next(
            (
                item
                for item in plan.items
                if item.operator_id == raw.operator_id and sorted(item.target_risks) == targets
            ),
            None,
        )

    def _materialize(
        self,
        seed: MutationSeed,
        feedback: MutationFeedback,
        raw: RawMutationCandidate,
        target_depths: dict[str, int],
        random_seed: int,
    ) -> MutationCandidate:
        operator = self.registry.get(raw.operator_id)
        target_risks = sorted(set(raw.target_risks))
        for category_id in target_risks:
            reachable = self.risk_scope.max_reachable_depth(category_id)
            if reachable is None:
                raise MutationTargetError(f"target is outside campaign scope: {category_id}")
            if target_depths[category_id] > reachable:
                raise MutationTargetError(f"target depth exceeds campaign scope: {category_id}")
        candidate_kind = operator.candidate_kinds[0]
        fork = None
        prompt = raw.prompt
        if candidate_kind == MutationCandidateKind.FORK:
            if not (seed.replay_id and seed.checkpoint_id):
                raise MutationTargetError("fork mutation requires replay and checkpoint")
            fork = ForkMutationSpec(
                parent_replay_id=seed.replay_id,
                checkpoint_id=seed.checkpoint_id,
                injection_type="prompt_append",
                content=raw.prompt,
            )
            prompt = None
            dedupe_key = fork_dedupe_key(
                parent_replay_id=seed.replay_id,
                checkpoint_id=seed.checkpoint_id,
                injection_type=fork.injection_type,
                content=fork.content,
            )
        else:
            dedupe_key = prompt_dedupe_key(raw.prompt)
        feedback_digest = stable_digest(feedback)
        identity = {
            "parent_seed_id": seed.seed_id,
            "parent_mutation_id": seed.parent_mutation_id,
            "mutation_depth": seed.mutation_depth + 1,
            "operator_id": operator.operator_id,
            "operator_version": operator.version,
            "target_risks": target_risks,
            "target_depths": target_depths,
            "candidate_kind": candidate_kind.value,
            "fork": fork,
            "normalized_prompt_sha256": normalized_prompt_digest(raw.prompt),
            "dedupe_key": dedupe_key,
            "provider": self.provider.kind.value,
            "provider_version": self.provider.version,
            "model_digest": self.provider.model_digest,
            "generation_prompt_version": self.provider.generation_prompt_version,
            "random_seed": random_seed,
            "feedback_digest": feedback_digest,
        }
        path_signature = self.priority.path_signature(
            seed,
            operator.operator_id,
            target_risks,
        )
        return MutationCandidate(
            mutation_id=stable_digest(identity),
            candidate_kind=candidate_kind,
            parent_seed_id=seed.seed_id,
            parent_mutation_id=seed.parent_mutation_id,
            mutation_depth=seed.mutation_depth + 1,
            operator_id=operator.operator_id,
            operator_version=operator.version,
            target_risks=target_risks,
            target_depths=target_depths,
            prompt=prompt,
            fork=fork,
            prompt_sha256=prompt_digest(raw.prompt),
            normalized_prompt_sha256=normalized_prompt_digest(raw.prompt),
            dedupe_key=dedupe_key,
            provider=self.provider.kind,
            provider_version=self.provider.version,
            model_name=self.provider.model_name,
            model_digest=self.provider.model_digest,
            generation_prompt_version=self.provider.generation_prompt_version,
            random_seed=random_seed,
            expected_novelty=raw.expected_novelty,
            constraints_preserved=raw.constraints_preserved,
            path_signature=path_signature,
            mutation_priority=0.0,
            feedback_digest=feedback_digest,
        )

    @staticmethod
    def _rejection(
        attempt_id: str,
        seed: MutationSeed,
        raw: RawMutationCandidate,
        reason: MutationRejectionReason,
        detail: str,
    ) -> RejectedMutation:
        return RejectedMutation(
            attempt_id=attempt_id,
            parent_seed_id=seed.seed_id,
            operator_id=raw.operator_id,
            target_risks=sorted(set(raw.target_risks)),
            prompt_sha256=prompt_digest(raw.prompt),
            reason=reason,
            detail=detail[:500],
        )
