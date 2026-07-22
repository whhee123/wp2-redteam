"""Campaign-specific risk applicability and maximum reachable depths."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from sandbox.coverage.exceptions import CoverageIntegrityError
from sandbox.coverage.models import CampaignRiskScope, RiskReachability
from sandbox.coverage.taxonomy import RiskTaxonomyIndex
from sandbox.replay.digests import sha256_digest


class CampaignRiskScopeLoader:
    def __init__(self, path: Path, taxonomy: RiskTaxonomyIndex) -> None:
        self.path = path
        self.taxonomy = taxonomy

    def load(self) -> CampaignRiskScopeIndex:
        try:
            payload = yaml.safe_load(self.path.read_text(encoding="utf-8"))
            scope = CampaignRiskScope.model_validate(payload)
        except (OSError, yaml.YAMLError, ValidationError, ValueError) as exc:
            raise CoverageIntegrityError(f"invalid campaign risk scope: {self.path}") from exc
        return CampaignRiskScopeIndex(scope, self.taxonomy)


class CampaignRiskScopeIndex:
    def __init__(self, scope: CampaignRiskScope, taxonomy: RiskTaxonomyIndex) -> None:
        if scope.taxonomy_version != taxonomy.taxonomy_version:
            raise CoverageIntegrityError(
                "campaign risk scope taxonomy_version does not match the loaded taxonomy"
            )
        leaf_ids = set(taxonomy.leaf_ids)
        invalid = sorted(set(scope.categories) - leaf_ids)
        if invalid:
            raise CoverageIntegrityError(
                f"campaign risk scope contains non-leaf or unknown categories: {invalid}"
            )
        self.scope = scope
        self.taxonomy = taxonomy
        self.digest = sha256_digest(scope)

    @classmethod
    def all_reachable(cls, taxonomy: RiskTaxonomyIndex) -> CampaignRiskScopeIndex:
        return cls(
            CampaignRiskScope(
                scope_version=f"{taxonomy.taxonomy_version}-all-reachable",
                taxonomy_version=taxonomy.taxonomy_version,
                categories={
                    category_id: RiskReachability(max_reachable_depth=3)
                    for category_id in taxonomy.leaf_ids
                },
            ),
            taxonomy,
        )

    @property
    def scope_version(self) -> str:
        return self.scope.scope_version

    @property
    def category_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self.scope.categories))

    def max_reachable_depth(self, category_id: str) -> int | None:
        reachability = self.scope.categories.get(category_id)
        return reachability.max_reachable_depth if reachability is not None else None

    def eligible_ids(self, minimum_depth: int) -> tuple[str, ...]:
        return tuple(
            category_id
            for category_id in self.category_ids
            if self.scope.categories[category_id].max_reachable_depth >= minimum_depth
        )
