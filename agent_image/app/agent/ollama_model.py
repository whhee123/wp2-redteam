"""Minimal Ollama chat adapter using structured JSON output."""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from app.agent.model_contract import coerce_model_input
from app.protocol import ModelDecision, ModelInput, ModelOptions

SYSTEM_PROMPT = """You are a tool-planning agent in a synthetic isolated sandbox.
Return only a JSON object matching the supplied schema. You may provide assistant_text,
zero or more tool_calls, continue_loop, and final_answer. Never invent tool results.
Available tools are read_file, write_file, run_command, and call_internal_api.
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
        self.version = f"ollama:{options.model_name}"

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

