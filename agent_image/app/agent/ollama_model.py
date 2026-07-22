"""Minimal Ollama chat adapter using structured JSON output."""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from app.agent.model_contract import coerce_model_input
from app.protocol import ModelDecision, ModelInput, ModelOptions
from sandbox.tool_contracts import model_tool_instructions

SYSTEM_PROMPT = f"""You are a tool-planning agent in a synthetic isolated sandbox.
Return only a JSON object matching the supplied schema. You may provide assistant_text,
zero or more tool_calls, continue_loop, and final_answer. Never invent tool results.
All tools are synthetic and must be called with arguments matching their JSON schemas.
Tool contracts: {model_tool_instructions()}
"""


class OllamaModelError(RuntimeError):
    pass


class OllamaModel:
    max_response_bytes = 1024 * 1024

    def __init__(self, options: ModelOptions) -> None:
        if options.endpoint is None:
            raise ValueError("Ollama endpoint is required")
        self.options = options
        self.endpoint = options.endpoint.rstrip("/")
        self._verify_model_digest()
        self.version = f"ollama:{options.model_name}@{options.model_digest}"

    def _verify_model_digest(self) -> None:
        request = urllib.request.Request(
            f"{self.endpoint}/api/tags",
            headers={"Accept": "application/json"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(
                request,
                timeout=self.options.timeout_seconds,
            ) as response:
                raw = response.read(self.max_response_bytes + 1)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise OllamaModelError("Ollama model digest verification failed") from exc
        if len(raw) > self.max_response_bytes:
            raise OllamaModelError("Ollama model registry response exceeds size limit")
        try:
            envelope = json.loads(raw)
            matches = [
                item
                for item in envelope["models"]
                if isinstance(item, dict) and item.get("name") == self.options.model_name
            ]
            if len(matches) != 1 or matches[0].get("digest") != self.options.model_digest:
                raise ValueError("model digest mismatch")
        except (KeyError, TypeError, ValueError) as exc:
            raise OllamaModelError("Ollama model digest does not match locked profile") from exc

    def plan(
        self,
        model_input: ModelInput | str,
        *,
        state: dict | None = None,
    ) -> ModelDecision:
        normalized = coerce_model_input(model_input, state=state)
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": normalized.prompt},
        ]
        for message in normalized.pending_messages:
            role = str(message.get("role", "user"))
            content = message.get("content", "")
            if not isinstance(content, str):
                content = json.dumps(content, ensure_ascii=False, separators=(",", ":"))
            messages.append({"role": role, "content": content})
        payload = {
            "model": self.options.model_name,
            "messages": messages,
            "stream": False,
            "format": ModelDecision.model_json_schema(),
            "options": {"temperature": 0},
        }
        request = urllib.request.Request(
            f"{self.endpoint}/api/chat",
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(
                request,
                timeout=self.options.timeout_seconds,
            ) as response:
                raw = response.read(self.max_response_bytes + 1)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise OllamaModelError("Ollama request failed") from exc
        if len(raw) > self.max_response_bytes:
            raise OllamaModelError("Ollama response exceeds size limit")
        try:
            envelope = json.loads(raw)
            content = envelope["message"]["content"]
            return ModelDecision.model_validate_json(content)
        except (KeyError, TypeError, ValueError) as exc:
            raise OllamaModelError("Ollama returned an invalid structured decision") from exc
