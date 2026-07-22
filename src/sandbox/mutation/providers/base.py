"""Mutation provider protocol."""

from __future__ import annotations

from typing import Protocol

from sandbox.mutation.models import (
    MutationPlan,
    MutationProviderKind,
    MutationSeed,
    RawMutationCandidate,
)


class MutationProvider(Protocol):
    kind: MutationProviderKind
    version: str
    model_name: str | None
    model_digest: str | None
    generation_prompt_version: str

    async def generate(
        self,
        seed: MutationSeed,
        plan: MutationPlan,
        *,
        count: int,
        random_seed: int,
    ) -> list[RawMutationCandidate]: ...
