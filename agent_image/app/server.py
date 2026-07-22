"""FastAPI transport for the single-execution Runtime."""

from __future__ import annotations

import json
import os

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.protocol import (
    EventsRequest,
    ExecutionIdRequest,
    ExecutionRequest,
    JsonRpcRequest,
    rpc_error,
    rpc_result,
)
from app.runtime import RuntimeRpcError, RuntimeState
from sandbox.replay.models import ReplayCheckpointsRequest, ReplayForkRequest, ReplayRequest

app = FastAPI(title="TRACE-G Agent Runtime", docs_url=None, redoc_url=None)
runtime = RuntimeState(expected_execution_id=os.environ.get("EXECUTION_ID"))
capability_token = os.environ.get("SANDBOX_TOKEN", "development-only-token")


@app.get("/health")
async def health() -> dict[str, str]:
    return {
        "status": "ok",
        "adapter": "langgraph",
        "runtime_version": "0.2.0",
        "protocol_version": "1",
    }


@app.post("/rpc")
async def rpc(request: Request) -> JSONResponse:
    body = await request.body()
    if len(body) > 64 * 1024:
        return JSONResponse(rpc_error(None, -32005, "request body too large"))
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return JSONResponse(rpc_error(None, -32700, "parse error"))

    request_id = _request_id(payload)
    if request.headers.get("X-Protocol-Version") != "1":
        return JSONResponse(rpc_error(request_id, -32600, "unsupported protocol version"))
    if request.headers.get("X-Sandbox-Token") != capability_token:
        return JSONResponse(rpc_error(request_id, -32001, "unauthorized"))

    try:
        envelope = JsonRpcRequest.model_validate(payload)
        if envelope.jsonrpc != "2.0":
            return JSONResponse(rpc_error(envelope.id, -32600, "invalid JSON-RPC version"))
        result = await _dispatch(envelope.method, envelope.params)
        return JSONResponse(rpc_result(envelope.id, result))
    except ValidationError:
        return JSONResponse(rpc_error(request_id, -32602, "invalid params"))
    except RuntimeRpcError as exc:
        return JSONResponse(rpc_error(request_id, exc.code, exc.message))
    except Exception:
        return JSONResponse(rpc_error(request_id, -32603, "internal error"))


def _request_id(payload: object) -> str | int | None:
    if not isinstance(payload, dict):
        return None
    request_id = payload.get("id")
    if isinstance(request_id, bool):
        return None
    return request_id if isinstance(request_id, (str, int)) else None


async def _dispatch(method: str, params: dict):
    if method == "execution.submit":
        return await runtime.submit(ExecutionRequest.model_validate(params))
    if method == "execution.get":
        parsed = ExecutionIdRequest.model_validate(params)
        return (await runtime.get(parsed.execution_id)).model_dump(mode="json")
    if method == "execution.events":
        parsed = EventsRequest.model_validate(params)
        return await runtime.events(parsed.execution_id, parsed.after_sequence, parsed.limit)
    if method == "execution.cancel":
        parsed = ExecutionIdRequest.model_validate(params)
        return await runtime.cancel(parsed.execution_id)
    if method == "replay.submit":
        return await runtime.submit_replay(ReplayRequest.model_validate(params))
    if method == "replay.checkpoints":
        return await runtime.checkpoints(ReplayCheckpointsRequest.model_validate(params))
    if method == "replay.fork":
        return await runtime.submit_fork(ReplayForkRequest.model_validate(params))
    raise RuntimeRpcError(-32601, "method not found")
