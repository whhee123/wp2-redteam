from __future__ import annotations

import pytest

from sandbox.client.jsonrpc import parse_response, request_envelope
from sandbox.errors import ProtocolError


def test_request_envelope_is_jsonrpc_20() -> None:
    assert request_envelope("id-1", "execution.get", {"execution_id": "exec"}) == {
        "jsonrpc": "2.0",
        "id": "id-1",
        "method": "execution.get",
        "params": {"execution_id": "exec"},
    }


def test_parse_response_returns_result() -> None:
    result = parse_response(
        {"jsonrpc": "2.0", "id": "id-1", "result": {"status": "running"}},
        "id-1",
    )
    assert result == {"status": "running"}


def test_parse_response_rejects_mismatched_id() -> None:
    with pytest.raises(ProtocolError, match="request id mismatch"):
        parse_response({"jsonrpc": "2.0", "id": "other", "result": {}}, "id-1")


def test_parse_response_surfaces_runtime_error() -> None:
    with pytest.raises(ProtocolError, match="-32003"):
        parse_response(
            {
                "jsonrpc": "2.0",
                "id": "id-1",
                "error": {"code": -32003, "message": "not found"},
            },
            "id-1",
        )

