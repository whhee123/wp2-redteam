"""Load and index the versioned risk taxonomy."""

from __future__ import annotations

import re
from pathlib import Path

import yaml
from pydantic import ValidationError

from sandbox.coverage.exceptions import TaxonomyError
from sandbox.coverage.models import RiskCategory, RiskTaxonomy


class RiskTaxonomyLoader:
    def __init__(
        self,
        path: Path,
        *,
        expected_version: str | None = None,
        default_report_weight: float = 1.0,
    ) -> None:
        self.path = path
        self.expected_version = expected_version
        self.default_report_weight = default_report_weight

    def load(self) -> RiskTaxonomyIndex:
        try:
            payload = yaml.safe_load(self.path.read_text(encoding="utf-8"))
            taxonomy = RiskTaxonomy.model_validate(payload)
        except (OSError, yaml.YAMLError, ValidationError, ValueError) as exc:
            raise TaxonomyError(f"invalid risk taxonomy: {self.path}") from exc
        if self.expected_version and taxonomy.taxonomy_version != self.expected_version:
            raise TaxonomyError(
                f"taxonomy version {taxonomy.taxonomy_version!r} does not match "
                f"{self.expected_version!r}"
            )
        return RiskTaxonomyIndex(taxonomy, self.default_report_weight)


class RiskTaxonomyIndex:
    def __init__(self, taxonomy: RiskTaxonomy, default_report_weight: float = 1.0) -> None:
        self.taxonomy = taxonomy
        self.default_report_weight = default_report_weight
        self._categories: dict[str, RiskCategory] = {}
        self._parents: dict[str, str | None] = {}
        self._weights: dict[str, float] = {}
        self._walk(taxonomy.categories, parent_id=None, inherited_weight=None)
        if not self._categories:
            raise TaxonomyError("risk taxonomy contains no categories")

    @property
    def taxonomy_version(self) -> str:
        return self.taxonomy.taxonomy_version

    @property
    def category_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._categories))

    @property
    def leaf_ids(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                category_id
                for category_id, category in self._categories.items()
                if not category.children
            )
        )

    @property
    def leaf_categories(self) -> tuple[RiskCategory, ...]:
        return tuple(self._categories[category_id] for category_id in self.leaf_ids)

    def get(self, category_id: str) -> RiskCategory:
        try:
            return self._categories[category_id]
        except KeyError as exc:
            raise TaxonomyError(f"unknown risk category: {category_id}") from exc

    def parent_id(self, category_id: str) -> str | None:
        self.get(category_id)
        return self._parents[category_id]

    def report_weight(self, category_id: str) -> float:
        self.get(category_id)
        return self._weights[category_id]

    def flattened(self) -> list[dict[str, object]]:
        return [
            {
                "id": category_id,
                "parent_id": self._parents[category_id],
                "label": self._categories[category_id].label,
                "leaf": not self._categories[category_id].children,
                "report_weight": self._weights[category_id],
            }
            for category_id in self.category_ids
        ]

    def _walk(
        self,
        categories: list[RiskCategory],
        *,
        parent_id: str | None,
        inherited_weight: float | None,
    ) -> None:
        sibling_ids: set[str] = set()
        for category in categories:
            if category.id in sibling_ids or category.id in self._categories:
                raise TaxonomyError(f"duplicate risk category id: {category.id}")
            sibling_ids.add(category.id)
            self._categories[category.id] = category
            self._parents[category.id] = parent_id
            for rule in [*category.evidence_rules, *category.impact_rules]:
                for field_name, pattern in rule.argument_patterns.items():
                    try:
                        re.compile(pattern)
                    except re.error as exc:
                        raise TaxonomyError(
                            f"invalid regex for {category.id}.{field_name}: {pattern!r}"
                        ) from exc
            weight = (
                category.report_weight
                if category.report_weight is not None
                else inherited_weight
                if inherited_weight is not None
                else self.default_report_weight
            )
            self._weights[category.id] = weight
            self._walk(category.children, parent_id=category.id, inherited_weight=weight)
