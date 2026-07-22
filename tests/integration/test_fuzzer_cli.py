from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

from sandbox.cli import main
from sandbox.fuzzer.config import FuzzerConfig


def test_campaign_create_status_and_redacted_export(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    config = FuzzerConfig.model_validate(
        {
            "campaign_id": "cli-campaign",
            "store_root": tmp_path / "fuzzing",
            "budget": {"max_executions": 2},
            "concurrency": {
                "sandbox_workers": 1,
                "execution_queue_size": 1,
                "result_queue_size": 1,
                "max_pending_work_items": 1,
            },
        }
    )
    config_path = tmp_path / "fuzzer.yaml"
    config_path.write_text(
        yaml.safe_dump({"fuzzer": config.model_dump(mode="json")}, sort_keys=False),
        encoding="utf-8",
    )
    common = [
        "--config",
        str(config_path),
        "--coverage-root",
        str(tmp_path / "coverage"),
        "--mutation-root",
        str(tmp_path / "mutations"),
        "--trajectory-dir",
        str(tmp_path / "trajectories"),
        "--artifact-dir",
        str(tmp_path / "artifacts"),
        "--manifest-dir",
        str(tmp_path / "replays"),
    ]
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "trace-redteam",
            "campaign",
            "create",
            *common,
            "--initial-case",
            "benign-control-001",
        ],
    )
    assert main() == 0
    created = json.loads(capsys.readouterr().out)
    assert created["status"] == "created"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "trace-redteam",
            "campaign",
            "status",
            "--campaign-id",
            "cli-campaign",
            "--store-root",
            str(tmp_path / "fuzzing"),
        ],
    )
    assert main() == 0
    assert json.loads(capsys.readouterr().out)["seed_counts"] == {"pending": 1}

    output = tmp_path / "campaign.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "trace-redteam",
            "campaign",
            "export",
            "--campaign-id",
            "cli-campaign",
            "--store-root",
            str(tmp_path / "fuzzing"),
            "--output",
            str(output),
        ],
    )
    assert main() == 0
    exported = json.loads(output.read_text(encoding="utf-8"))
    assert exported["seeds"][0]["case"]["prompt"] == "<redacted>"
