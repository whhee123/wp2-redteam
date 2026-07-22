"""Select the planning model without changing graph infrastructure."""

from __future__ import annotations

from app.agent.fake_model import FakeChatModel
from app.agent.ollama_model import OllamaModel
from app.protocol import ModelOptions, ModelProvider


class ModelFactory:
    @staticmethod
    def create(options: ModelOptions | None):
        resolved = options or ModelOptions()
        if resolved.provider == ModelProvider.FAKE:
            return FakeChatModel()
        if resolved.provider == ModelProvider.OLLAMA:
            return OllamaModel(resolved)
        raise ValueError(f"unsupported model provider: {resolved.provider}")

