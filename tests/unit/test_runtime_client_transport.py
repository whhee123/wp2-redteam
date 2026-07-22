from __future__ import annotations

import base64
import json
from types import SimpleNamespace

from sandbox.client.runtime_client import RuntimeClient
from sandbox.config import TraceConfig
from sandbox.scheduler.models import SandboxHandle


class FakeContainer:
    def __init__(self) -> None:
        self.command = None

    def exec_run(self, command, demux, environment):
        self.command = command
        assert demux is True
        assert environment == {"SANDBOX_TOKEN": "token"}
        request = json.loads(base64.urlsafe_b64decode(command[-1]).decode("utf-8"))
        response = {"jsonrpc": "2.0", "id": request["id"], "result": {"ok": True}}
        return SimpleNamespace(
            exit_code=0,
            output=(json.dumps(response).encode("utf-8"), b""),
        )


class FakeContainers:
    def __init__(self, container: FakeContainer) -> None:
        self.container = container

    def get(self, container_id: str) -> FakeContainer:
        assert container_id == "container-1"
        return self.container


def test_exec_transport_uses_fixed_argument_array() -> None:
    container = FakeContainer()
    docker_client = SimpleNamespace(containers=FakeContainers(container))
    client = RuntimeClient(TraceConfig(), docker_client=docker_client)
    handle = SandboxHandle(
        execution_id="exec-1",
        container_id="container-1",
        runtime_url="http://127.0.0.1:8080",
        transport="docker_exec",
        capability_token="token",
        image_digest="sha256:test",
        scheduler_instance_id="scheduler-1",
    )
    result = client._exec_rpc(
        handle,
        {
            "jsonrpc": "2.0",
            "id": "request-1",
            "method": "execution.submit",
            "params": {"prompt": "'; rm -rf /; echo '"},
        },
    )
    assert result["result"] == {"ok": True}
    assert container.command[:3] == ["python", "-m", "app.rpc_client"]
    assert len(container.command) == 4
