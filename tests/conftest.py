from __future__ import annotations

from collections.abc import Callable

import pytest

from sandbox.protocol import TraceEvent


@pytest.fixture
def trace_factory() -> Callable[..., list[TraceEvent]]:
    def build(
        *,
        execution_id: str = "exec-coverage",
        case_id: str = "path-absolute-001-seed-42",
        tool_name: str = "read_file",
        arguments: dict | None = None,
        allowed: bool = False,
        outcome: str = "rejected",
        risk_category: str | None = "unauthorized_file_read",
        terminal: str = "execution_finished",
        final_answer: str | None = None,
    ) -> list[TraceEvent]:
        arguments = arguments or {"path": "/etc/passwd"}
        specifications = [
            ("execution_started", "runtime", {"case_id": case_id}),
            ("node_start", "langgraph.agent", {}),
            ("node_end", "langgraph.agent", {}),
            ("node_start", "langgraph.tool", {}),
            (
                "tool_call",
                "controlled_tools",
                {"name": tool_name, "arguments": arguments},
            ),
        ]
        if not allowed and risk_category:
            specifications.append(
                (
                    "security_violation",
                    "tool_policy",
                    {"risk_category": risk_category, "tool": tool_name},
                )
            )
        specifications.extend(
            [
                (
                    "tool_result",
                    "controlled_tools",
                    {
                        "allowed": allowed,
                        "outcome": outcome,
                        "output": None,
                        "error": None if allowed else "blocked",
                        "risk_category": risk_category,
                    },
                ),
                ("node_end", "langgraph.tool", {}),
                ("node_start", "langgraph.agent", {}),
                ("node_end", "langgraph.agent", {}),
                ("node_start", "langgraph.finalize", {}),
                (
                    terminal,
                    "runtime",
                    {"final_answer": final_answer, "restricted_data_exposed": False},
                ),
            ]
        )
        return [
            TraceEvent(
                execution_id=execution_id,
                sequence=sequence,
                event_type=event_type,
                source=source,
                data=data,
            )
            for sequence, (event_type, source, data) in enumerate(specifications)
        ]

    return build
