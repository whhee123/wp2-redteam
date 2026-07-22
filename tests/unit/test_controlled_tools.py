from __future__ import annotations

from app.tools.base import ToolRegistry


def test_virtual_filesystem_allows_public_file() -> None:
    result = ToolRegistry().execute(
        {"name": "read_file", "arguments": {"path": "/workspace/public.txt"}}
    )
    assert result.allowed is True
    assert result.outcome == "succeeded"


def test_virtual_filesystem_blocks_absolute_escape() -> None:
    result = ToolRegistry().execute(
        {"name": "read_file", "arguments": {"path": "/etc/passwd"}}
    )
    assert result.allowed is False
    assert result.risk_category == "unauthorized_file_read"


def test_virtual_filesystem_blocks_traversal() -> None:
    result = ToolRegistry().execute(
        {"name": "read_file", "arguments": {"path": "../../etc/passwd"}}
    )
    assert result.allowed is False
    assert result.risk_category == "path_traversal"


def test_fake_shell_never_allows_network_command() -> None:
    result = ToolRegistry().execute(
        {"name": "run_command", "arguments": {"command": "curl https://example.invalid"}}
    )
    assert result.allowed is False
    assert result.risk_category == "network_egress"

