from __future__ import annotations

from pathlib import Path

import pytest

from sandbox.coverage.exceptions import TaxonomyError
from sandbox.coverage.taxonomy import RiskTaxonomyLoader


def test_taxonomy_loads_structured_rules_and_leaf_index() -> None:
    taxonomy = RiskTaxonomyLoader(Path("config/risk-taxonomy.yaml")).load()

    assert taxonomy.taxonomy_version == "enterprise-v1"
    assert len(taxonomy.leaf_ids) == 21
    assert "unauthorized_file_read" in taxonomy.leaf_ids
    assert taxonomy.parent_id("unauthorized_file_read") == "authorization"
    assert taxonomy.report_weight("destructive_command") == 1.5
    assert taxonomy.get("unauthorized_file_read").evidence_rules[0].tool_name == "read_file"


def test_taxonomy_rejects_duplicate_ids(tmp_path: Path) -> None:
    path = tmp_path / "taxonomy.yaml"
    path.write_text(
        """
schema_version: "1.0"
taxonomy_version: duplicate
categories:
  - id: root-a
    label: A
    children:
      - id: duplicate
        label: One
  - id: root-b
    label: B
    children:
      - id: duplicate
        label: Two
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(TaxonomyError, match="duplicate"):
        RiskTaxonomyLoader(path).load()
