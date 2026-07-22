from __future__ import annotations

import json

import pytest
from app.agent.ollama_model import OllamaModel, OllamaModelError
from pydantic import ValidationError

from sandbox.protocol import ModelOptions, ModelProvider


class Response:
    def __init__(self, payload: dict) -> None:
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None

    def read(self, _size: int) -> bytes:
        return json.dumps(self.payload).encode()


def _options(digest: str | None = None) -> ModelOptions:
    return ModelOptions(
        provider=ModelProvider.OLLAMA,
        model_name="qwen:test",
        model_digest=digest or "sha256:" + "1" * 64,
        endpoint="http://ollama:11434",
    )


def test_ollama_model_options_require_digest() -> None:
    with pytest.raises(ValidationError, match="locked model_digest"):
        ModelOptions(
            provider=ModelProvider.OLLAMA,
            model_name="qwen:test",
            endpoint="http://ollama:11434",
        )


def test_ollama_model_accepts_exact_registry_digest(monkeypatch) -> None:
    digest = "sha256:" + "1" * 64
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda *_args, **_kwargs: Response({"models": [{"name": "qwen:test", "digest": digest}]}),
    )
    model = OllamaModel(_options(digest))
    assert model.version == f"ollama:qwen:test@{digest}"


def test_ollama_model_rejects_changed_tag_digest(monkeypatch) -> None:
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda *_args, **_kwargs: Response(
            {"models": [{"name": "qwen:test", "digest": "sha256:" + "2" * 64}]}
        ),
    )
    with pytest.raises(OllamaModelError, match="does not match"):
        OllamaModel(_options())
