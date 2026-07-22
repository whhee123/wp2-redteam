from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path

from sandbox.cli import main
from sandbox.protocol import TraceEvent


def test_all_coverage_cli_subcommands(
    tmp_path: Path,
    trace_factory: Callable[..., list[TraceEvent]],
    monkeypatch,
    capsys,
) -> None:
    trajectory_root = tmp_path / "trajectories"
    trajectory_root.mkdir()
    trajectory_path = trajectory_root / "exec-coverage.jsonl"
    trajectory_path.write_text(
        "".join(event.model_dump_json() + "\n" for event in trace_factory()),
        encoding="utf-8",
    )
    coverage_root = tmp_path / "coverage"
    common = [
        "--campaign-id",
        "cli-campaign",
        "--coverage-root",
        str(coverage_root),
        "--taxonomy-path",
        "config/risk-taxonomy.yaml",
    ]

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "trace-redteam",
            "coverage",
            "evaluate",
            "--trajectory-path",
            str(trajectory_path),
            "--manifest-dir",
            str(tmp_path / "replays"),
            "--artifact-dir",
            str(tmp_path / "artifacts"),
            *common,
        ],
    )
    assert main() == 0
    evaluated = json.loads(capsys.readouterr().out)
    assert evaluated["new_behavior_count"] > 0

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "trace-redteam",
            "coverage",
            "compute",
            "--data-dir",
            str(trajectory_root),
            "--manifest-dir",
            str(tmp_path / "replays"),
            "--artifact-dir",
            str(tmp_path / "artifacts"),
            *common,
        ],
    )
    assert main() == 0
    assert json.loads(capsys.readouterr().out)["evaluated"] == 1

    monkeypatch.setattr(
        sys,
        "argv",
        ["trace-redteam", "coverage", "snapshot", *common],
    )
    assert main() == 0
    assert json.loads(capsys.readouterr().out)["total_trajectories"] == 1

    heatmap_path = tmp_path / "heatmap.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "trace-redteam",
            "coverage",
            "heatmap",
            "--output",
            str(heatmap_path),
            *common,
        ],
    )
    assert main() == 0
    capsys.readouterr()
    assert isinstance(json.loads(heatmap_path.read_text(encoding="utf-8")), list)

    pretty_heatmap_path = tmp_path / "heatmap-pretty.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "trace-redteam",
            "coverage",
            "heatmap",
            "--output",
            str(pretty_heatmap_path),
            "--pretty",
            *common,
        ],
    )
    assert main() == 0
    capsys.readouterr()
    pretty = json.loads(pretty_heatmap_path.read_text(encoding="utf-8"))
    assert pretty["campaign_id"] == "cli-campaign"
    assert pretty["rows"][0]["trajectory_ids"] == [evaluated["trajectory_id"]]
    assert pretty["columns"][0]["label"]
    assert pretty["cells"][0]["risk_category_label"]

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "trace-redteam",
            "coverage",
            "taxonomy",
            "--taxonomy-path",
            "config/risk-taxonomy.yaml",
        ],
    )
    assert main() == 0
    taxonomy = json.loads(capsys.readouterr().out)
    assert any(item["id"] == "unauthorized_file_read" for item in taxonomy)
