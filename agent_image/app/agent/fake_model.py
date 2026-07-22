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
            r"(?:写入文件|write file)\s*(/[^\s，,。]+)"
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

        directory = re.search(
            r"(?:list directory|list files in)\s+(/[^\s,;]+)",
            prompt,
            flags=re.IGNORECASE,
        )
        if directory:
            return self._tool("list_directory", {"path": directory.group(1)}, loop)

        search = re.search(
            r"search files (?:under|in)\s+(/[^\s,;]+)\s+for\s+(.+)",
            prompt,
            flags=re.IGNORECASE,
        )
        if search:
            return self._tool(
                "search_files",
                {
                    "root": search.group(1),
                    "query": search.group(2).strip().strip("."),
                    "max_results": 20,
                },
                loop,
            )

        environment = re.search(
            r"(?:read|get) environment variable\s+([A-Z][A-Z0-9_]*)",
            prompt,
            flags=re.IGNORECASE,
        )
        if environment:
            return self._tool(
                "read_environment",
                {"name": environment.group(1).upper()},
                loop,
            )

        if "list processes" in lowered:
            return self._tool("list_processes", {}, loop)

        database = re.search(
            r"query database table\s+(customers|tickets|audit_logs)"
            r"\s+for tenant\s+([a-z0-9-]+)",
            prompt,
            flags=re.IGNORECASE,
        )
        if database:
            return self._tool(
                "query_database",
                {
                    "table": database.group(1).lower(),
                    "tenant_id": database.group(2).lower(),
                    "include_sensitive": "sensitive" in lowered,
                },
                loop,
            )

        email = re.search(
            r"send email to\s+([^\s,;]+)\s+subject\s+([^;]+);\s*body\s+(.+)",
            prompt,
            flags=re.IGNORECASE,
        )
        if email:
            return self._tool(
                "send_email",
                {
                    "to": email.group(1),
                    "subject": email.group(2).strip(),
                    "body": email.group(3).strip(),
                },
                loop,
            )

        http = re.search(
            r"http (get|post)\s+(https?://[^\s,;]+)(?:\s+with body\s+(.+))?",
            prompt,
            flags=re.IGNORECASE,
        )
        if http:
            body = {"content": http.group(3).strip()} if http.group(3) else None
            return self._tool(
                "http_request",
                {"method": http.group(1).upper(), "url": http.group(2), "body": body},
                loop,
            )

        secret = re.search(
            r"(?:retrieve|get) secret\s+([a-zA-Z0-9._-]+)",
            prompt,
            flags=re.IGNORECASE,
        )
        if secret:
            return self._tool("retrieve_secret", {"secret_id": secret.group(1)}, loop)
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

