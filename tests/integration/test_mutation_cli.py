from __future__ import annotations

import json
import sys
from pathlib import Path

from sandbox.cli import main


def test_mutation_cli_generate_inspect_and_export(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    common = [
        "--campaign-id",
        "cli-mutation",
        "--coverage-root",
        str(tmp_path / "coverage"),
        "--mutation-root",
        str(tmp_path / "mutations"),
        "--taxonomy-path",
        "config/risk-taxonomy.yaml",
        "--risk-scope-path",
        "config/risk-scope-week3.yaml",
        "--operator-registry-path",
        "config/mutation-operators.yaml",
    ]

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "trace-redteam",
            "mutate",
            "operators",
            *common,
        ],
    )
    assert main() == 0
    operators = json.loads(capsys.readouterr().out)
    assert len(operators) == 10

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "trace-redteam",
            "mutate",
            "generate",
            "--case",
            "path-absolute-001",
            "--count",
            "4",
            "--seed",
            "42",
            *common,
        ],
    )
    assert main() == 0
    batch = json.loads(capsys.readouterr().out)
    assert batch["accepted"]
    assert batch["campaign_id"] == "cli-mutation"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "trace-redteam",
            "mutate",
            "batch",
            "--batch-id",
            batch["batch_id"],
            *common,
        ],
    )
    assert main() == 0
    restored = json.loads(capsys.readouterr().out)
    assert restored["batch_id"] == batch["batch_id"]

    monkeypatch.setattr(
        sys,
        "argv",
        ["trace-redteam", "mutate", "stats", *common],
    )
    assert main() == 0
    stats = json.loads(capsys.readouterr().out)
    assert stats["total_batches"] == 1

    output = tmp_path / "candidates.jsonl"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "trace-redteam",
            "mutate",
            "export",
            "--output",
            str(output),
            *common,
        ],
    )
    assert main() == 0
    capsys.readouterr()
    exported = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert len(exported) == len(batch["accepted"])
