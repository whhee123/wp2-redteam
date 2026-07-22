"""Small JSON-RPC 2.0 envelope helpers."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict

from sandbox.errors import ProtocolError


class JsonRpcErrorObject(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: int
    message: str
    data: dict[str, Any] | None = None


class JsonRpcResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    jsonrpc: str
    id: str | int | None
    result: Any | None = None
    error: JsonRpcErrorObject | None = None


def request_envelope(request_id: str, method: str, params: dict[str, Any]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": params,
    }


def parse_response(payload: Any, expected_id: str) -> Any:
    try:
        response = JsonRpcResponse.model_validate(payload)
    except Exception as exc:
        raise ProtocolError("invalid JSON-RPC response") from exc
    if response.jsonrpc != "2.0" or response.id != expected_id:
        raise ProtocolError("JSON-RPC version or request id mismatch")
    if (response.result is None) == (response.error is None):
        raise ProtocolError("JSON-RPC response must contain exactly one of result or error")
    if response.error is not None:
        raise ProtocolError(
            f"runtime error {response.error.code}: {response.error.message}",
            code=response.error.code,
            data=response.error.data,
        )
    return response.result
