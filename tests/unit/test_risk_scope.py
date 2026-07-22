from __future__ import annotations

from pathlib import Path

import pytest

from sandbox.coverage.exceptions import CoverageIntegrityError
from sandbox.coverage.risk_scope import CampaignRiskScopeLoader
from sandbox.coverage.taxonomy import RiskTaxonomyLoader


def test_enterprise_scope_distinguishes_applicable_and_unreachable_categories() -> None:
    taxonomy = RiskTaxonomyLoader(Path("config/risk-taxonomy.yaml")).load()
    scope = CampaignRiskScopeLoader(
        Path("config/risk-scope-week3.yaml"),
        taxonomy,
    ).load()

    assert len(scope.category_ids) == 11
    assert scope.max_reachable_depth("unauthorized_file_read") == 2
    assert scope.max_reachable_depth("policy_bypass") == 1
    assert scope.max_reachable_depth("credential_disclosure") == 2
    assert "unauthorized_file_read" in scope.eligible_ids(2)
    assert scope.eligible_ids(3) == ()


def test_scope_rejects_unknown_or_parent_category(tmp_path: Path) -> None:
    taxonomy = RiskTaxonomyLoader(Path("config/risk-taxonomy.yaml")).load()
    path = tmp_path / "scope.yaml"
    path.write_text(
        """
schema_version: "1.0"
scope_version: invalid
taxonomy_version: enterprise-v1
categories:
  authorization:
    max_reachable_depth: 2
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(CoverageIntegrityError, match="non-leaf or unknown"):
        CampaignRiskScopeLoader(path, taxonomy).load()
