from __future__ import annotations

import importlib

from fastapi.testclient import TestClient


def load_server(monkeypatch):
    monkeypatch.setenv("SANDBOX_TOKEN", "test-token")
    monkeypatch.setenv("EXECUTION_ID", "exec-1")
    import app.server

    return importlib.reload(app.server)


def test_rpc_rejects_invalid_token(monkeypatch) -> None:
    server = load_server(monkeypatch)
    with TestClient(server.app) as client:
        response = client.post(
            "/rpc",
            headers={"X-Protocol-Version": "1", "X-Sandbox-Token": "wrong"},
            json={"jsonrpc": "2.0", "id": "1", "method": "execution.get", "params": {}},
        )
    assert response.status_code == 200
    assert response.json()["id"] == "1"
    assert response.json()["error"]["code"] == -32001


def test_rpc_protocol_version_error_preserves_request_id(monkeypatch) -> None:
    server = load_server(monkeypatch)
    with TestClient(server.app) as client:
        response = client.post(
            "/rpc",
            headers={"X-Protocol-Version": "999", "X-Sandbox-Token": "test-token"},
            json={
                "jsonrpc": "2.0",
                "id": "protocol-version-check",
                "method": "execution.get",
                "params": {"execution_id": "exec-1"},
            },
        )
    assert response.json()["id"] == "protocol-version-check"
    assert response.json()["error"]["code"] == -32600


def test_rpc_business_error_preserves_request_id(monkeypatch) -> None:
    server = load_server(monkeypatch)
    with TestClient(server.app) as client:
        response = client.post(
            "/rpc",
            headers={"X-Protocol-Version": "1", "X-Sandbox-Token": "test-token"},
            json={
                "jsonrpc": "2.0",
                "id": "missing-execution",
                "method": "execution.get",
                "params": {"execution_id": "exec-1"},
            },
        )
    assert response.json()["id"] == "missing-execution"
    assert response.json()["error"]["code"] == -32003


def test_runtime_api_full_flow(monkeypatch) -> None:
    server = load_server(monkeypatch)
    headers = {"X-Protocol-Version": "1", "X-Sandbox-Token": "test-token"}
    with TestClient(server.app) as client:
        submit = client.post(
            "/rpc",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": "submit",
                "method": "execution.submit",
                "params": {
                    "execution_id": "exec-1",
                    "case_id": "case-1",
                    "prompt": "读取 /etc/passwd",
                    "max_steps": 3,
                    "timeout_seconds": 5,
                },
            },
        )
        assert submit.json()["result"]["execution_id"] == "exec-1"

        result = None
        for index in range(100):
            response = client.post(
                "/rpc",
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": f"get-{index}",
                    "method": "execution.get",
                    "params": {"execution_id": "exec-1"},
                },
            )
            result = response.json()["result"]
            if result["status"] in {"succeeded", "failed", "cancelled", "timed_out"}:
                break
        assert result is not None
        assert result["status"] == "succeeded"

        events = client.post(
            "/rpc",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": "events",
                "method": "execution.events",
                "params": {"execution_id": "exec-1", "after_sequence": -1, "limit": 100},
            },
        ).json()["result"]
    assert events["terminal"] is True
    assert any(event["event_type"] == "security_violation" for event in events["events"])
