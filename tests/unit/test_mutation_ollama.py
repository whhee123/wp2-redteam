from __future__ import annotations

import json

from sandbox.engine.case_source import TemplateCaseSource
from sandbox.mutation.config import MutationProviderConfig
from sandbox.mutation.models import (
    MutationPlan,
    MutationProviderKind,
    MutationSeed,
    PlannedMutation,
    RawMutationBatch,
    RawMutationCandidate,
)
from sandbox.mutation.normalizer import prompt_digest
from sandbox.mutation.providers.ollama import OllamaMutationProvider


class FakeResponse:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None

    def read(self, _size: int) -> bytes:
        return self.payload


async def test_ollama_provider_parses_strict_structured_batch() -> None:
    raw_batch = RawMutationBatch(
        candidates=[
            RawMutationCandidate(
                prompt="变异 Prompt",
                operator_id="roleplay_wrapper",
                target_risks=["unauthorized_file_read"],
            )
        ]
    )
    envelope = json.dumps(
        {"message": {"content": raw_batch.model_dump_json()}},
        ensure_ascii=False,
    ).encode("utf-8")

    def opener(request, *, timeout):
        assert request.full_url == "http://127.0.0.1:11434/api/chat"
        assert timeout == 10
        return FakeResponse(envelope)

    config = MutationProviderConfig(
        kind=MutationProviderKind.OLLAMA,
        provider_version="ollama-mutator-v1",
        model_name="local-model",
        model_digest="sha256:model",
        endpoint="http://127.0.0.1:11434",
        timeout_seconds=10,
    )
    provider = OllamaMutationProvider(config, opener=opener)
    case = TemplateCaseSource().generate("path-absolute-001", seed=42)
    seed = MutationSeed(
        seed_id=case.case_id,
        case=case,
        prompt_sha256=prompt_digest(case.prompt),
    )
    plan = MutationPlan(
        plan_id="sha256:" + "1" * 64,
        feedback_digest="sha256:" + "2" * 64,
        items=[
            PlannedMutation(
                operator_id="roleplay_wrapper",
                target_risks=["unauthorized_file_read"],
                target_depths={"unauthorized_file_read": 1},
                requested_count=1,
                initial_priority=1.0,
            )
        ],
        oversample_count=1,
    )

    result = await provider.generate(seed, plan, count=1, random_seed=42)

    assert result[0].prompt == "变异 Prompt"
    assert provider.model_digest == "sha256:model"
