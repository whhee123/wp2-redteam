"""Scheduler-owned container handle."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field


class SandboxHandle(BaseModel):
    execution_id: str
    container_id: str
    runtime_url: str
    transport: str = "docker_exec"
    capability_token: str = Field(repr=False)
    image_digest: str
    scheduler_instance_id: str
    workspace_volume_name: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
