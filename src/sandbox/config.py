"""Typed configuration for the first-week execution path."""

from __future__ import annotations

from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, Field, model_validator

from sandbox.protocol import ModelOptions, ModelProvider


class SandboxLimits(BaseModel):
    memory_limit: str = "512m"
    nano_cpus: int = 1_000_000_000
    pids_limit: int = 128
    tmpfs_size: str = "64m"


class SandboxConfig(BaseModel):
    image: str = "trace-redteam-agent:week1"
    transport: str = "docker_exec"
    network_mode: str = "none"
    runtime_container_port: int = 8080
    startup_timeout_seconds: float = 20.0
    execution_timeout_seconds: int = 120
    workspace_storage: Literal["tmpfs", "archive_volume"] = "tmpfs"
    ollama_endpoint: str | None = None
    model_network_name: str | None = None
    limits: SandboxLimits = Field(default_factory=SandboxLimits)

    @model_validator(mode="after")
    def validate_model_network(self) -> SandboxConfig:
        if self.ollama_endpoint is None and self.model_network_name is not None:
            raise ValueError("model_network_name requires ollama_endpoint")
        if self.ollama_endpoint is not None:
            parsed = urlparse(self.ollama_endpoint)
            if (
                parsed.scheme != "http"
                or parsed.hostname != "ollama"
                or parsed.port != 11434
                or parsed.path not in {"", "/"}
            ):
                raise ValueError(
                    "ollama_endpoint must use http://ollama:11434 on the internal model network"
                )
            if parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise ValueError("ollama_endpoint must not contain credentials or query data")
            if not self.model_network_name:
                raise ValueError("Ollama access requires a pre-created model_network_name")
        return self


class TraceConfig(BaseModel):
    output_dir: Path = Path("data/trajectories")
    max_events: int = 1_000
    page_size: int = 100
    pull_interval_seconds: float = 0.2


class ReplayConfig(BaseModel):
    artifact_dir: Path = Path("data/artifacts")
    manifest_dir: Path = Path("data/replays")


class WeekOneConfig(BaseModel):
    seed: int = 42
    max_steps: int = 20
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
    tracing: TraceConfig = Field(default_factory=TraceConfig)
    replay: ReplayConfig = Field(default_factory=ReplayConfig)
    model: ModelOptions = Field(default_factory=ModelOptions)

    @model_validator(mode="after")
    def model_and_network_must_match(self) -> WeekOneConfig:
        if self.model.provider == ModelProvider.OLLAMA:
            if self.model.endpoint != self.sandbox.ollama_endpoint:
                raise ValueError("model endpoint and sandbox Ollama endpoint must match")
        elif self.sandbox.ollama_endpoint is not None:
            raise ValueError("Ollama network cannot be enabled for the Fake model")
        return self
