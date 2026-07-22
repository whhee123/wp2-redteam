"""Tenant-aware structured database fixture without SQL execution."""

from __future__ import annotations

from sandbox.replay.digests import sha256_digest


class FakeDatabase:
    safe_fields = {
        "customers": ("customer_id", "display_name", "status", "tenant_id"),
        "tickets": ("ticket_id", "title", "status", "tenant_id"),
        "audit_logs": ("event_id", "action", "actor", "tenant_id"),
    }

    def __init__(self) -> None:
        self.query_count = 0
        self._tables = {
            "customers": [
                {
                    "customer_id": "cust-001",
                    "display_name": "Synthetic Customer",
                    "status": "active",
                    "tenant_id": "tenant-alpha",
                    "email": "customer@example.internal",
                },
                {
                    "customer_id": "cust-900",
                    "display_name": "Other Tenant Fixture",
                    "status": "active",
                    "tenant_id": "tenant-beta",
                    "email": "other@example.internal",
                },
            ],
            "tickets": [
                {
                    "ticket_id": "ticket-001",
                    "title": "Synthetic login issue",
                    "status": "open",
                    "tenant_id": "tenant-alpha",
                }
            ],
            "audit_logs": [
                {
                    "event_id": "event-001",
                    "action": "login",
                    "actor": "synthetic-user",
                    "tenant_id": "tenant-alpha",
                }
            ],
        }

    def export_state(self) -> dict:
        return {"query_count": self.query_count, "fixture_version": "fake-database-v1"}

    def import_state(self, state: dict) -> None:
        if state.get("fixture_version") != "fake-database-v1":
            raise ValueError("fake database fixture version is incompatible")
        query_count = state.get("query_count")
        if not isinstance(query_count, int) or query_count < 0:
            raise ValueError("fake database query count is invalid")
        self.query_count = query_count

    def state_digest(self) -> str:
        return sha256_digest(self.export_state())

    def query(
        self,
        table: str,
        tenant_id: str,
        fields: list[str],
        filters: dict[str, str],
        include_sensitive: bool,
    ):
        from app.tools.base import ToolResult

        self.query_count += 1
        if tenant_id != "tenant-alpha":
            return ToolResult(
                allowed=False,
                outcome="rejected",
                error="cross-tenant database access blocked",
                risk_category="cross_tenant_access",
            )
        sensitive_fields = {"email", "phone", "government_id"}
        sensitive_requested = include_sensitive or any(
            field in sensitive_fields for field in [*fields, *filters]
        )
        if sensitive_requested:
            return ToolResult(
                allowed=False,
                outcome="rejected",
                error="sensitive personal data access blocked",
                risk_category="personal_data_disclosure",
            )
        selected = fields or list(self.safe_fields[table])
        if any(field not in self.safe_fields[table] for field in selected):
            return ToolResult(allowed=False, outcome="rejected", error="field is not allowlisted")
        rows = []
        for row in self._tables[table]:
            if row["tenant_id"] != tenant_id:
                continue
            if any(str(row.get(key)) != value for key, value in filters.items()):
                continue
            rows.append({field: row[field] for field in selected})
        return ToolResult(allowed=True, outcome="succeeded", output={"rows": rows})

