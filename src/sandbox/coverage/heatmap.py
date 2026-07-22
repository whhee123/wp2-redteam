"""Sparse behavior-profile by risk-category heatmap aggregation."""

from __future__ import annotations

from collections import defaultdict

from sandbox.coverage.models import (
    BehaviorProfile,
    HeatmapCell,
    PrettyHeatmapCell,
    PrettyHeatmapColumn,
    PrettyHeatmapReport,
    PrettyHeatmapRow,
    RiskHit,
)
from sandbox.coverage.taxonomy import RiskTaxonomyIndex


class HeatmapGenerator:
    def __init__(self, taxonomy: RiskTaxonomyIndex, *, label_prefix_length: int = 8) -> None:
        self.taxonomy = taxonomy
        self.label_prefix_length = label_prefix_length

    def generate(
        self,
        profiles: list[BehaviorProfile],
        hits: list[RiskHit],
        *,
        include_empty: bool = False,
    ) -> list[HeatmapCell]:
        profile_by_trajectory = {
            profile.trajectory_id: profile.profile_hash for profile in profiles
        }
        trajectory_counts: dict[str, set[str]] = defaultdict(set)
        hit_trajectories: dict[tuple[str, str], set[str]] = defaultdict(set)
        max_depths: dict[tuple[str, str], int] = defaultdict(int)
        improvement_depths: dict[tuple[str, str], set[int]] = defaultdict(set)

        for profile in profiles:
            trajectory_counts[profile.profile_hash].add(profile.trajectory_id)
        for hit in hits:
            profile_hash = profile_by_trajectory.get(hit.trajectory_id)
            if profile_hash is None or hit.category_id not in self.taxonomy.leaf_ids:
                continue
            key = (profile_hash, hit.category_id)
            hit_trajectories[key].add(hit.trajectory_id)
            max_depths[key] = max(max_depths[key], hit.depth)
            improvement_depths[key].add(hit.depth)

        profile_hashes = sorted(trajectory_counts)
        cells: list[HeatmapCell] = []
        for profile_hash in profile_hashes:
            for category_id in self.taxonomy.leaf_ids:
                key = (profile_hash, category_id)
                max_depth = max_depths.get(key, 0)
                if not include_empty and max_depth == 0:
                    continue
                cells.append(
                    HeatmapCell(
                        behavior_cluster_id=profile_hash,
                        behavior_cluster_label=profile_hash.removeprefix("sha256:")[
                            : self.label_prefix_length
                        ],
                        risk_category_id=category_id,
                        trajectory_count=len(hit_trajectories.get(key, set())),
                        max_depth=max_depth,
                        new_coverage_count=len(improvement_depths.get(key, set())),
                    )
                )
        return cells

    def generate_pretty(
        self,
        campaign_id: str,
        profiles: list[BehaviorProfile],
        hits: list[RiskHit],
        *,
        include_empty: bool = False,
    ) -> PrettyHeatmapReport:
        cells = self.generate(profiles, hits, include_empty=include_empty)
        trajectory_ids: dict[str, set[str]] = defaultdict(set)
        for profile in profiles:
            trajectory_ids[profile.profile_hash].add(profile.trajectory_id)

        row_labels: dict[str, str] = {}
        rows: list[PrettyHeatmapRow] = []
        for profile_hash, identifiers in sorted(trajectory_ids.items()):
            short_hash = profile_hash.removeprefix("sha256:")[: self.label_prefix_length]
            ordered_ids = sorted(identifiers)
            label = f"{short_hash} [{', '.join(ordered_ids)}]"
            row_labels[profile_hash] = label
            rows.append(
                PrettyHeatmapRow(
                    behavior_cluster_id=profile_hash,
                    label=label,
                    trajectory_ids=ordered_ids,
                )
            )

        category_ids = sorted({cell.risk_category_id for cell in cells})
        columns = [
            PrettyHeatmapColumn(
                risk_category_id=category_id,
                label=self.taxonomy.get(category_id).label,
            )
            for category_id in category_ids
        ]
        pretty_cells = [
            PrettyHeatmapCell(
                behavior_cluster_id=cell.behavior_cluster_id,
                behavior_cluster_label=row_labels[cell.behavior_cluster_id],
                risk_category_id=cell.risk_category_id,
                risk_category_label=self.taxonomy.get(cell.risk_category_id).label,
                trajectory_count=cell.trajectory_count,
                max_depth=cell.max_depth,
                new_coverage_count=cell.new_coverage_count,
                confirmed_vulnerabilities=cell.confirmed_vulnerabilities,
            )
            for cell in cells
        ]
        return PrettyHeatmapReport(
            campaign_id=campaign_id,
            taxonomy_version=self.taxonomy.taxonomy_version,
            rows=rows,
            columns=columns,
            cells=pretty_cells,
        )
