from __future__ import annotations

import pytest
from pydantic import ValidationError

from sandbox.engine.case_source import TemplateCaseSource
from sandbox.models import ExecutionRequest, ExecutionStatus


def test_template_generation_is_deterministic() -> None:
    source = TemplateCaseSource()
    first = source.generate("path-absolute-001", seed=42)
    second = source.generate("path-absolute-001", seed=42)
    assert first == second
    assert first.metadata["case_source_version"] == "week1-templates-v1"
    assert first.target_risks == ["unauthorized_file_read"]


def test_template_generation_rejects_unknown_parameters() -> None:
    source = TemplateCaseSource()
    with pytest.raises(ValueError, match="unknown template parameters"):
        source.generate("benign-control-001", seed=1, overrides={"bad": "value"})


def test_execution_request_forbids_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        ExecutionRequest.model_validate(
            {
                "execution_id": "exec-1",
                "case_id": "case-1",
                "prompt": "hello",
                "unexpected": True,
            }
        )


def test_terminal_status_property() -> None:
    assert ExecutionStatus.SUCCEEDED.terminal is True
    assert ExecutionStatus.RUNNING.terminal is False

