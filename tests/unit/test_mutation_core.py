from __future__ import annotations

from pathlib import Path

import pytest

from sandbox.coverage.models import CoverageSnapshot
from sandbox.coverage.risk_scope import CampaignRiskScopeLoader
from sandbox.coverage.taxonomy import RiskTaxonomyLoader
from sandbox.engine.case_source import TemplateCaseSource
from sandbox.mutation.config import MutationConfig
from sandbox.mutation.diversity import DiversityGate
from sandbox.mutation.exceptions import MutationTargetError
from sandbox.mutation.feedback import MutationFeedbackBuilder
from sandbox.mutation.models import MutationHistorySnapshot, MutationSeed, to_test_case
from sandbox.mutation.mutator import SemanticMutator
from sandbox.mutation.normalizer import normalize_prompt, prompt_digest
from sandbox.mutation.operators import MutationOperatorRegistryLoader
from sandbox.mutation.priority import MutationPriorityCalculator
from sandbox.mutation.providers.rule_based import RuleBasedMutationProvider
from sandbox.mutation.similarity import CharacterShingleSimilarity
from sandbox.mutation.store import MutationStore


def _components(tmp_path: Path):
    taxonomy = RiskTaxonomyLoader(Path("config/risk-taxonomy.yaml")).load()
    scope = CampaignRiskScopeLoader(Path("config/risk-scope-week3.yaml"), taxonomy).load()
    registry = MutationOperatorRegistryLoader(
        Path("config/mutation-operators.yaml"), taxonomy
    ).load()
    config = MutationConfig(store_root=tmp_path)
    store = MutationStore(
        config.store_root,
        config.campaign_id,
        metadata={
            "taxonomy_version": taxonomy.taxonomy_version,
            "risk_scope_version": scope.scope_version,
            "risk_scope_digest": scope.digest,
            "operator_registry_version": registry.registry_version,
            "operator_registry_digest": registry.digest,
            "normalization_version": config.diversity.normalization_version,
            "similarity_version": config.diversity.similarity_version,
            "priority_formula_version": config.priority.formula_version,
        },
    )
    return taxonomy, scope, registry, config, store


def _snapshot(taxonomy, scope, *, include_depths: bool = True) -> CoverageSnapshot:
    depths = dict.fromkeys(taxonomy.leaf_ids, 0) if include_depths else {}
    return CoverageSnapshot(
        campaign_id="week4-baseline",
        taxonomy_version=taxonomy.taxonomy_version,
        risk_scope_version=scope.scope_version,
        risk_depths=depths,
    )


def _seed() -> MutationSeed:
    case = TemplateCaseSource().generate("path-absolute-001", seed=42)
    return MutationSeed(
        seed_id=case.case_id,
        case=case,
        prompt_sha256=prompt_digest(case.prompt),
    )


def test_prompt_normalization_is_stable() -> None:
    assert normalize_prompt("Ａ  B\r\n\r\n\r\n C  ") == "A B\n\n C"


def test_feedback_requires_explicit_depth_for_every_leaf(tmp_path: Path) -> None:
    taxonomy, scope, _registry, _config, store = _components(tmp_path)
    try:
        builder = MutationFeedbackBuilder(taxonomy, scope)
        with pytest.raises(MutationTargetError, match="explicit risk_depths"):
            builder.build(_seed(), _snapshot(taxonomy, scope, include_depths=False))
    finally:
        store.close()


async def test_rule_based_mutation_is_diverse_persistent_and_idempotent(
    tmp_path: Path,
) -> None:
    taxonomy, scope, registry, config, store = _components(tmp_path)
    try:
        seed = _seed()
        feedback = MutationFeedbackBuilder(taxonomy, scope).build(
            seed,
            _snapshot(taxonomy, scope),
            history=MutationHistorySnapshot(campaign_id=config.campaign_id),
        )
        assert len(feedback.risk_gaps) == len(scope.category_ids)
        assert all(gap.gap_ratio > 0 for gap in feedback.risk_gaps)
        similarity = CharacterShingleSimilarity()
        mutator = SemanticMutator(
            config,
            registry,
            scope,
            RuleBasedMutationProvider(),
            DiversityGate(similarity, config.diversity),
            MutationPriorityCalculator(config.priority),
            store,
        )
        batch = await mutator.mutate(seed, feedback, 6, random_seed=42)
        assert len(batch.accepted) >= 4
        assert len({candidate.operator_id for candidate in batch.accepted}) >= 3
        assert len({candidate.dedupe_key for candidate in batch.accepted}) == len(batch.accepted)
        assert all(candidate.mutation_priority >= 0 for candidate in batch.accepted)
        assert all(candidate.priority_components for candidate in batch.accepted)
        assert all(candidate.path_signature for candidate in batch.accepted)
        case = to_test_case(batch.accepted[0])
        assert case.metadata["mutation_id"] == batch.accepted[0].mutation_id

        repeated = await mutator.mutate(seed, feedback, 6, random_seed=42)
        assert repeated.already_generated is True
        assert [item.mutation_id for item in repeated.accepted] == [
            item.mutation_id for item in batch.accepted
        ]
        snapshot = store.snapshot()
        assert snapshot.total_batches == 1
        assert snapshot.total_accepted == len(batch.accepted)
        first = batch.accepted[0]
        assert snapshot.path_counts[first.path_signature] >= 1

        updated_feedback = MutationFeedbackBuilder(taxonomy, scope).build(
            seed,
            _snapshot(taxonomy, scope),
            history=snapshot,
        )
        components, _score = MutationPriorityCalculator(config.priority).score(
            seed=seed,
            feedback=updated_feedback,
            target_risks=first.target_risks,
            operator_id=first.operator_id,
            similarity=0.0,
        )
        assert components["path_frequency"] > 0
    finally:
        store.close()
