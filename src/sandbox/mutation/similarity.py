"""Deterministic lexical similarity and optional local embeddings."""

from __future__ import annotations

import asyncio
import json
import math
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Literal, Protocol

from sandbox.mutation.exceptions import MutationProviderError
from sandbox.mutation.normalizer import normalize_prompt


class SimilarityBackend(Protocol):
    version: str
    capability: Literal["lexical", "semantic"]

    async def similarity(self, left: str, right: str) -> float: ...


class CharacterShingleSimilarity:
    version = "char3-jaccard-v1"
    capability: Literal["lexical"] = "lexical"

    @staticmethod
    def _shingles(value: str) -> set[str]:
        normalized = normalize_prompt(value)
        if not normalized:
            return set()
        if len(normalized) < 3:
            return {normalized}
        return {normalized[index : index + 3] for index in range(len(normalized) - 2)}

    async def similarity(self, left: str, right: str) -> float:
        left_set = self._shingles(left)
        right_set = self._shingles(right)
        if not left_set and not right_set:
            return 1.0
        union = left_set | right_set
        return len(left_set & right_set) / len(union)


class OllamaEmbeddingSimilarity:
    capability: Literal["semantic"] = "semantic"

    def __init__(
        self,
        endpoint: str,
        model_name: str,
        model_digest: str,
        *,
        timeout_seconds: int = 120,
        max_response_bytes: int = 1_048_576,
        opener: Callable = urllib.request.urlopen,
    ) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.model_name = model_name
        self.model_digest = model_digest
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self.opener = opener
        self.version = f"ollama-embedding:{model_name}:{model_digest}"

    async def similarity(self, left: str, right: str) -> float:
        left_vector, right_vector = await asyncio.gather(
            self._embedding(left),
            self._embedding(right),
        )
        denominator = math.sqrt(sum(value * value for value in left_vector)) * math.sqrt(
            sum(value * value for value in right_vector)
        )
        if denominator == 0:
            return 0.0
        cosine = sum(a * b for a, b in zip(left_vector, right_vector, strict=True)) / denominator
        return max(0.0, min(1.0, cosine))

    async def _embedding(self, prompt: str) -> list[float]:
        return await asyncio.to_thread(self._embedding_sync, prompt)

    def _embedding_sync(self, prompt: str) -> list[float]:
        payload = {"model": self.model_name, "prompt": prompt}
        request = urllib.request.Request(
            f"{self.endpoint}/api/embeddings",
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with self.opener(request, timeout=self.timeout_seconds) as response:
                raw = response.read(self.max_response_bytes + 1)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise MutationProviderError("Ollama embedding request failed") from exc
        if len(raw) > self.max_response_bytes:
            raise MutationProviderError("Ollama embedding response exceeds size limit")
        try:
            envelope = json.loads(raw)
            vector = [float(value) for value in envelope["embedding"]]
        except (KeyError, TypeError, ValueError) as exc:
            raise MutationProviderError("Ollama returned an invalid embedding") from exc
        if not vector:
            raise MutationProviderError("Ollama returned an empty embedding")
        return vector
