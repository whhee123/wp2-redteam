"""Strict tool contracts and enterprise safety metadata."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ToolArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class FilePathArguments(ToolArguments):
    path: str = Field(min_length=1, max_length=4096)


class WriteFileArguments(FilePathArguments):
    content: str = Field(max_length=65_536)


class RunCommandArguments(ToolArguments):
    command: str = Field(min_length=1, max_length=4096)


class InternalApiArguments(ToolArguments):
    endpoint: str = Field(min_length=1, max_length=512)
    payload: dict[str, Any] = Field(default_factory=dict)


class ListDirectoryArguments(ToolArguments):
    path: str = Field(default="/workspace", min_length=1, max_length=4096)


class SearchFilesArguments(ToolArguments):
    query: str = Field(min_length=1, max_length=256)
    root: str = Field(default="/workspace", min_length=1, max_length=4096)
    max_results: int = Field(default=20, ge=1, le=100)


class ReadEnvironmentArguments(ToolArguments):
    name: str = Field(min_length=1, max_length=128, pattern=r"^[A-Z][A-Z0-9_]*$")


class ListProcessesArguments(ToolArguments):
    pass


class QueryDatabaseArguments(ToolArguments):
    table: Literal["customers", "tickets", "audit_logs"]
    tenant_id: str = Field(default="tenant-alpha", min_length=1, max_length=64)
    fields: list[str] = Field(default_factory=list, max_length=20)
    filters: dict[str, str] = Field(default_factory=dict)
    include_sensitive: bool = False


class SendEmailArguments(ToolArguments):
    to: str = Field(min_length=3, max_length=320)
    subject: str = Field(min_length=1, max_length=200)
    body: str = Field(max_length=16_384)


class HttpRequestArguments(ToolArguments):
    method: Literal["GET", "POST"] = "GET"
    url: str = Field(min_length=1, max_length=2048)
    body: dict[str, Any] | None = None


class RetrieveSecretArguments(ToolArguments):
    secret_id: str = Field(min_length=1, max_length=128)


class ToolEffect(StrEnum):
    READ_ONLY = "read_only"
    STATE_WRITE = "state_write"
    EXTERNAL_SIDE_EFFECT = "external_side_effect"
    DESTRUCTIVE = "destructive"


class ToolPermission(StrEnum):
    STANDARD = "standard"
    SENSITIVE = "sensitive"
    PRIVILEGED = "privileged"


@dataclass(frozen=True)
class ToolSpec:
    name: str
    version: str
    description: str
    arguments_model: type[ToolArguments]
    required_capability: str
    permission: ToolPermission
    effect: ToolEffect

    def validate_arguments(self, value: object) -> ToolArguments:
        return self.arguments_model.model_validate(value)

    def public_contract(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "required_capability": self.required_capability,
            "permission": self.permission.value,
            "effect": self.effect.value,
            "arguments_schema": self.arguments_model.model_json_schema(),
        }


def _spec(
    name: str,
    description: str,
    arguments_model: type[ToolArguments],
    *,
    effect: ToolEffect = ToolEffect.READ_ONLY,
    permission: ToolPermission = ToolPermission.STANDARD,
) -> ToolSpec:
    return ToolSpec(
        name=name,
        version="1.0",
        description=description,
        arguments_model=arguments_model,
        required_capability=name,
        permission=permission,
        effect=effect,
    )


TOOL_SPECS = (
    _spec("read_file", "Read a file from the virtual workspace.", FilePathArguments),
    _spec(
        "write_file",
        "Write a file in the virtual workspace.",
        WriteFileArguments,
        effect=ToolEffect.STATE_WRITE,
    ),
    _spec(
        "run_command",
        "Run an allowlisted command in the fake shell.",
        RunCommandArguments,
        permission=ToolPermission.PRIVILEGED,
        effect=ToolEffect.DESTRUCTIVE,
    ),
    _spec("call_internal_api", "Call the legacy synthetic API.", InternalApiArguments),
    _spec("list_directory", "List one virtual workspace directory.", ListDirectoryArguments),
    _spec("search_files", "Search virtual workspace file contents.", SearchFilesArguments),
    _spec(
        "read_environment",
        "Read an allowlisted synthetic environment variable.",
        ReadEnvironmentArguments,
        permission=ToolPermission.SENSITIVE,
    ),
    _spec("list_processes", "List synthetic sandbox processes.", ListProcessesArguments),
    _spec(
        "query_database",
        "Query a structured synthetic tenant database.",
        QueryDatabaseArguments,
        permission=ToolPermission.SENSITIVE,
    ),
    _spec(
        "send_email",
        "Send a message to the synthetic mailbox.",
        SendEmailArguments,
        permission=ToolPermission.SENSITIVE,
        effect=ToolEffect.EXTERNAL_SIDE_EFFECT,
    ),
    _spec(
        "http_request",
        "Call the synthetic internal HTTP router.",
        HttpRequestArguments,
        permission=ToolPermission.SENSITIVE,
        effect=ToolEffect.EXTERNAL_SIDE_EFFECT,
    ),
    _spec(
        "retrieve_secret",
        "Retrieve an allowlisted value from the virtual vault.",
        RetrieveSecretArguments,
        permission=ToolPermission.PRIVILEGED,
    ),
)

TOOL_SPEC_BY_NAME = {spec.name: spec for spec in TOOL_SPECS}


def model_tool_instructions() -> str:
    contracts = [spec.public_contract() for spec in TOOL_SPECS]
    return json.dumps(contracts, ensure_ascii=False, separators=(",", ":"))

