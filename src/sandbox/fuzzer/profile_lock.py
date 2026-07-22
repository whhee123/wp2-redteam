"""Lock a server target profile to observed Ollama model and Docker image digests."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

import yaml

from sandbox.fuzzer.models import TargetProfile
from sandbox.tool_contracts import TOOL_SPECS

MAX_OLLAMA_RESPONSE_BYTES = 4 * 1024 * 1024


def fetch_ollama_model_digest(endpoint: str, model_name: str) -> str:
    parsed = urlparse(endpoint)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("Ollama administrative endpoint must be loopback HTTP")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Ollama administrative endpoint must not contain credentials or query")
    request = urllib.request.Request(
        f"{endpoint.rstrip('/')}/api/tags",
        headers={"Accept": "application/json"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            raw = response.read(MAX_OLLAMA_RESPONSE_BYTES + 1)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise RuntimeError("could not query local Ollama model registry") from exc
    if len(raw) > MAX_OLLAMA_RESPONSE_BYTES:
        raise RuntimeError("Ollama model registry response exceeds size limit")
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Ollama model registry returned invalid JSON") from exc
    return model_digest_from_tags(payload, model_name)


def model_digest_from_tags(payload: object, model_name: str) -> str:
    if not isinstance(payload, dict) or not isinstance(payload.get("models"), list):
        raise ValueError("Ollama tags payload is missing models")
    matches = [
        item
        for item in payload["models"]
        if isinstance(item, dict) and item.get("name") == model_name
    ]
    if len(matches) != 1:
        raise ValueError(f"expected exactly one Ollama model named {model_name!r}")
    digest = matches[0].get("digest")
    if not isinstance(digest, str) or not digest.startswith("sha256:") or len(digest) != 71:
        raise ValueError("Ollama model has no valid sha256 digest")
    return digest


def docker_image_digest(client, image_ref: str) -> str:
    digest = client.images.get(image_ref).id
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise ValueError("Docker image has no content digest")
    return digest


def docker_container_image_digest(client, container_name: str) -> str:
    container = client.containers.get(container_name)
    container.reload()
    digest = container.image.id
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise ValueError("running Docker container has no image digest")
    return digest


def lock_target_profile(
    *,
    client,
    ollama_admin_endpoint: str,
    profile_id: str,
    model_name: str,
    image_ref: str,
    model_runtime_image: str,
    model_runtime_container: str,
    risk_scope_path: Path,
    max_steps: int = 40,
    execution_timeout_seconds: int = 300,
) -> TargetProfile:
    runtime_digest = docker_container_image_digest(client, model_runtime_container)
    if docker_image_digest(client, model_runtime_image) != runtime_digest:
        raise ValueError("running Ollama container does not use the requested runtime image")
    return TargetProfile(
        profile_id=profile_id,
        profile_version="2.0",
        image_ref=image_ref,
        image_digest=docker_image_digest(client, image_ref),
        agent_version="langgraph-agent-v2",
        model_provider="ollama",
        model_name=model_name,
        model_digest=fetch_ollama_model_digest(ollama_admin_endpoint, model_name),
        model_runtime_image=model_runtime_image,
        model_runtime_digest=runtime_digest,
        risk_scope_path=risk_scope_path,
        fixture_pack_version="enterprise-fixtures-v1",
        max_steps=max_steps,
        execution_timeout_seconds=execution_timeout_seconds,
        required_capabilities=[spec.required_capability for spec in TOOL_SPECS],
    )


def verify_target_profile(
    *,
    client,
    ollama_admin_endpoint: str,
    profile: TargetProfile,
    model_runtime_container: str = "trace-g-ollama",
) -> None:
    if profile.model_provider != "ollama":
        raise ValueError("server profile verification requires an Ollama profile")
    actual_model_digest = fetch_ollama_model_digest(
        ollama_admin_endpoint,
        profile.model_name,
    )
    if actual_model_digest != profile.model_digest:
        raise ValueError("running Ollama model digest differs from locked target profile")
    actual_image_digest = docker_image_digest(client, profile.image_ref)
    if actual_image_digest != profile.image_digest:
        raise ValueError("local Agent image digest differs from locked target profile")
    if not profile.model_runtime_image or not profile.model_runtime_digest:
        raise ValueError("locked target profile has no Ollama runtime image digest")
    actual_runtime_digest = docker_image_digest(client, profile.model_runtime_image)
    if actual_runtime_digest != profile.model_runtime_digest:
        raise ValueError("local Ollama runtime image digest differs from locked target profile")
    running_runtime_digest = docker_container_image_digest(
        client,
        model_runtime_container,
    )
    if running_runtime_digest != profile.model_runtime_digest:
        raise ValueError("running Ollama container image digest differs from locked target profile")


def write_target_profile(path: Path, profile: TargetProfile) -> None:
    payload = {"profiles": [profile.model_dump(mode="json")]}
    rendered = yaml.safe_dump(payload, allow_unicode=True, sort_keys=False)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(rendered, encoding="utf-8", newline="\n")
    temporary.replace(path)
