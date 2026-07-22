"""Load and validate the versioned mutation operator registry."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from sandbox.coverage.risk_scope import CampaignRiskScopeIndex
from sandbox.coverage.taxonomy import RiskTaxonomyIndex
from sandbox.mutation.exceptions import MutationConfigError
from sandbox.mutation.models import (
    MutationCandidateKind,
    MutationOperatorRegistry,
    MutationOperatorSpec,
    MutationProviderKind,
)
from sandbox.replay.digests import sha256_digest


class MutationOperatorRegistryIndex:
    def __init__(
        self,
        registry: MutationOperatorRegistry,
        taxonomy: RiskTaxonomyIndex,
    ) -> None:
        self.registry = registry
        self.taxonomy = taxonomy
        self._operators: dict[str, MutationOperatorSpec] = {}
        leaf_ids = set(taxonomy.leaf_ids)
        for operator in registry.operators:
            if operator.operator_id in self._operators:
                raise MutationConfigError(f"duplicate mutation operator: {operator.operator_id}")
            invalid = sorted(set(operator.compatible_risk_categories) - leaf_ids)
            if invalid:
                raise MutationConfigError(
                    f"operator {operator.operator_id} has unknown risk categories: {invalid}"
                )
            self._operators[operator.operator_id] = operator
        if not self._operators:
            raise MutationConfigError("mutation operator registry is empty")
        self.digest = sha256_digest(registry)

    @property
    def registry_version(self) -> str:
        return self.registry.registry_version

    @property
    def operator_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._operators))

    def get(self, operator_id: str) -> MutationOperatorSpec:
        try:
            return self._operators[operator_id]
        except KeyError as exc:
            raise MutationConfigError(f"unknown mutation operator: {operator_id}") from exc

    def compatible(
        self,
        *,
        category_id: str,
        target_depth: int,
        provider: MutationProviderKind,
        candidate_kind: MutationCandidateKind,
        scope: CampaignRiskScopeIndex,
    ) -> tuple[MutationOperatorSpec, ...]:
        if scope.max_reachable_depth(category_id) is None:
            return ()
        return tuple(
            operator
            for operator in (self._operators[item] for item in self.operator_ids)
            if provider in operator.provider_modes
            and candidate_kind in operator.candidate_kinds
            and target_depth in operator.supported_target_depths
            and (
                not operator.compatible_risk_categories
                or category_id in operator.compatible_risk_categories
            )
        )


class MutationOperatorRegistryLoader:
    def __init__(self, path: Path, taxonomy: RiskTaxonomyIndex) -> None:
        self.path = path
        self.taxonomy = taxonomy

    def load(self) -> MutationOperatorRegistryIndex:
        try:
            payload = yaml.safe_load(self.path.read_text(encoding="utf-8"))
            registry = MutationOperatorRegistry.model_validate(payload)
        except (OSError, yaml.YAMLError, ValidationError, ValueError) as exc:
            raise MutationConfigError(f"invalid mutation operator registry: {self.path}") from exc
        return MutationOperatorRegistryIndex(registry, self.taxonomy)
