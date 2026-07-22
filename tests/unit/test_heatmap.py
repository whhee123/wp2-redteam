from __future__ import annotations

from pathlib import Path

from sandbox.coverage.heatmap import HeatmapGenerator
from sandbox.coverage.models import BehaviorProfile, EvidenceReference, RiskHit
from sandbox.coverage.taxonomy import RiskTaxonomyLoader


def test_heatmap_uses_full_hash_and_is_sparse() -> None:
    taxonomy = RiskTaxonomyLoader(Path("config/risk-taxonomy.yaml")).load()
    profile_hash = "sha256:" + "a" * 64
    profile = BehaviorProfile(
        trajectory_id="trajectory-1",
        execution_id="exec-1",
        profile_hash=profile_hash,
        feature_count=0,
    )
    hit = RiskHit(
        trajectory_id="trajectory-1",
        execution_id="exec-1",
        category_id="unauthorized_file_read",
        depth=2,
        recognizer="rule",
        evidence=[EvidenceReference(source="trace_event", event_sequence=1)],
    )

    cells = HeatmapGenerator(taxonomy).generate([profile], [hit])

    assert len(cells) == 1
    assert cells[0].behavior_cluster_id == profile_hash
    assert cells[0].behavior_cluster_label == "aaaaaaaa"
    assert cells[0].max_depth == 2


def test_pretty_heatmap_adds_human_readable_rows_and_risk_labels() -> None:
    taxonomy = RiskTaxonomyLoader(Path("config/risk-taxonomy.yaml")).load()
    profile_hash = "sha256:" + "b" * 64
    profiles = [
        BehaviorProfile(
            trajectory_id=trajectory_id,
            execution_id=f"exec-{index}",
            profile_hash=profile_hash,
            feature_count=0,
        )
        for index, trajectory_id in enumerate(("trajectory-a", "trajectory-b"), start=1)
    ]
    hit = RiskHit(
        trajectory_id="trajectory-a",
        execution_id="exec-1",
        category_id="unauthorized_file_read",
        depth=2,
        recognizer="rule",
        evidence=[EvidenceReference(source="trace_event", event_sequence=1)],
    )

    report = HeatmapGenerator(taxonomy).generate_pretty(
        "campaign",
        profiles,
        [hit],
    )

    assert report.campaign_id == "campaign"
    assert report.rows[0].label == "bbbbbbbb [trajectory-a, trajectory-b]"
    assert report.rows[0].trajectory_ids == ["trajectory-a", "trajectory-b"]
    expected_label = taxonomy.get("unauthorized_file_read").label
    assert report.columns[0].label == expected_label
    assert report.cells[0].risk_category_label == expected_label
    assert report.cells[0].behavior_cluster_label == report.rows[0].label
