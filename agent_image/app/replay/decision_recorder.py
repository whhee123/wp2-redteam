"""Model decorators for recording, strict replay, and live comparison."""

from __future__ import annotations

from uuid import uuid4

from app.agent.model_contract import coerce_model_input, coerce_recorded_decision
from app.protocol import ModelDecision, ModelInput
from sandbox.replay.digests import sha256_digest
from sandbox.replay.exceptions import ReplayDivergenceError
from sandbox.replay.models import RecordedModelDecision


class DecisionRecorder:
    def __init__(self, model) -> None:
        self.model = model
        self.version = model.version
        self.decisions: list[RecordedModelDecision] = []
        self._sequence = 0
        self._before_checkpoint_id = "unbound"

    def set_context(self, *, sequence: int, before_checkpoint_id: str) -> None:
        self._sequence = sequence
        self._before_checkpoint_id = before_checkpoint_id

    def plan(
        self,
        model_input: ModelInput | str,
        *,
        state: dict | None = None,
    ) -> ModelDecision:
        normalized_input = coerce_model_input(model_input, state=state)
        decision = self.model.plan(normalized_input, state=state)
        if not isinstance(decision, ModelDecision):
            decision = ModelDecision.model_validate(decision)
        input_payload = normalized_input.model_dump(mode="json")
        output_payload = decision.model_dump(mode="json")
        self.decisions.append(
            RecordedModelDecision(
                decision_id=f"decision-{uuid4().hex}",
                sequence=self._sequence,
                decision_index=len(self.decisions),
                before_checkpoint_id=self._before_checkpoint_id,
                input_digest=sha256_digest(input_payload),
                output_digest=sha256_digest(output_payload),
                action=output_payload,
                model_name=type(self.model).__name__,
                model_version=self.model.version,
            )
        )
        return decision

    def attach_after_checkpoint(self, checkpoint_id: str) -> None:
        if not self.decisions:
            raise RuntimeError("no model decision is available")
        self.decisions[-1] = self.decisions[-1].model_copy(
            update={"after_checkpoint_id": checkpoint_id}
        )


class RecordedDecisionModel:
    def __init__(self, decisions: list[RecordedModelDecision], *, start_index: int = 0) -> None:
        self.decisions = decisions
        self.next_index = start_index
        self.version = decisions[0].model_version if decisions else "recorded-decision-model-v1"
        self.last_decision: RecordedModelDecision | None = None

    def plan(
        self,
        model_input: ModelInput | str,
        *,
        state: dict | None = None,
    ) -> ModelDecision:
        normalized_input = coerce_model_input(model_input, state=state)
        if self.next_index >= len(self.decisions):
            raise ReplayDivergenceError(-32106, "recorded model decisions are exhausted")
        decision = self.decisions[self.next_index]
        if decision.decision_index != self.next_index:
            raise ReplayDivergenceError(-32102, "recorded decision index is not contiguous")
        current_digest = sha256_digest(normalized_input.model_dump(mode="json"))
        legacy_digest = sha256_digest({"prompt": normalized_input.prompt})
        if decision.input_digest not in {current_digest, legacy_digest}:
            raise ReplayDivergenceError(-32106, "model input digest diverged")
        try:
            model_decision = coerce_recorded_decision(decision.action)
        except ValueError as exc:
            raise ReplayDivergenceError(-32108, "recorded model action is invalid") from exc
        self.next_index += 1
        self.last_decision = decision
        return model_decision

    def assert_consumed(self) -> None:
        if self.next_index != len(self.decisions):
            raise ReplayDivergenceError(-32108, "recorded model decisions remain unconsumed")


class LiveDecisionModel:
    def __init__(
        self,
        model,
        decisions: list[RecordedModelDecision],
        *,
        start_index: int = 0,
    ) -> None:
        self.model = model
        self.decisions = decisions
        self.next_index = start_index
        self.version = model.version
        self.last_decision: RecordedModelDecision | None = None
        self.diverged = False

    def plan(
        self,
        model_input: ModelInput | str,
        *,
        state: dict | None = None,
    ) -> ModelDecision:
        normalized_input = coerce_model_input(model_input, state=state)
        model_decision = self.model.plan(normalized_input, state=state)
        if not isinstance(model_decision, ModelDecision):
            model_decision = ModelDecision.model_validate(model_decision)
        input_digest = sha256_digest(normalized_input.model_dump(mode="json"))
        output_payload = model_decision.model_dump(mode="json")
        output_digest = sha256_digest(output_payload)
        reference = (
            self.decisions[self.next_index]
            if self.next_index < len(self.decisions)
            else None
        )
        if reference is None:
            self.diverged = True
            before_checkpoint_id = f"live-before-{self.next_index}"
            after_checkpoint_id = None
        else:
            before_checkpoint_id = reference.before_checkpoint_id
            after_checkpoint_id = reference.after_checkpoint_id
            if (
                reference.input_digest != input_digest
                or reference.output_digest != output_digest
                or reference.action != output_payload
            ):
                self.diverged = True
        self.last_decision = RecordedModelDecision(
            decision_id=f"live-decision-{uuid4().hex}",
            sequence=self.next_index,
            decision_index=self.next_index,
            before_checkpoint_id=before_checkpoint_id,
            after_checkpoint_id=after_checkpoint_id,
            input_digest=input_digest,
            output_digest=output_digest,
            action=output_payload,
            model_name=type(self.model).__name__,
            model_version=self.model.version,
        )
        self.next_index += 1
        return model_decision

    def assert_consumed(self) -> None:
        if self.next_index != len(self.decisions):
            self.diverged = True
