from __future__ import annotations

from types import SimpleNamespace

import pytest

from sandbox.mutation.exceptions import MutationTargetError
from sandbox.mutation.handoff import execute_fork_candidate
from sandbox.mutation.models import (
    ForkMutationSpec,
    MutationCandidate,
    MutationCandidateKind,
    MutationProviderKind,
)


class FakeReplayEngine:
    def __init__(self, allowed: list[str]) -> None:
        self.allowed = allowed
        self.call = None

    def checkpoints(self, replay_id: str):
        return [
            SimpleNamespace(
                checkpoint_id="checkpoint-1",
                recoverable=True,
                allowed_injection_types=self.allowed,
            )
        ]

    async def fork(self, *args, **kwargs):
        self.call = (args, kwargs)
        return "manifest"


def _candidate() -> MutationCandidate:
    digest = "sha256:" + "1" * 64
    return MutationCandidate(
        mutation_id=digest,
        candidate_kind=MutationCandidateKind.FORK,
        parent_seed_id="seed-1",
        mutation_depth=1,
        operator_id="branch_prompt_injection",
        operator_version="1.0",
        target_risks=["unauthorized_file_read"],
        target_depths={"unauthorized_file_read": 2},
        fork=ForkMutationSpec(
            parent_replay_id="replay-1",
            checkpoint_id="checkpoint-1",
            injection_type="prompt_append",
            content="追加任务",
        ),
        prompt_sha256=digest,
        normalized_prompt_sha256=digest,
        dedupe_key=digest,
        provider=MutationProviderKind.RULE_BASED,
        provider_version="rule-mutator-v1",
        generation_prompt_version="rule-templates-v1",
        random_seed=42,
        mutation_priority=0.5,
        feedback_digest=digest,
    )


async def test_fork_handoff_checks_allowed_injection_and_records_lineage() -> None:
    engine = FakeReplayEngine(["prompt_append"])

    result = await execute_fork_candidate(_candidate(), engine)

    assert result == "manifest"
    assert engine.call[1]["operator"].startswith("mutator:branch_prompt_injection:sha256:")


async def test_fork_handoff_rejects_disallowed_injection() -> None:
    with pytest.raises(MutationTargetError, match="not allowed"):
        await execute_fork_candidate(_candidate(), FakeReplayEngine(["prompt_replace"]))
