"""Domain errors used across scheduler, protocol, and engine layers."""


class SandboxError(RuntimeError):
    """Base exception for the week-one sandbox."""


class InfrastructureError(SandboxError):
    """Docker, protocol, storage, or cleanup infrastructure failed."""


class ProtocolError(InfrastructureError):
    """The Runtime returned an invalid JSON-RPC response."""

    def __init__(
        self,
        message: str,
        *,
        code: int | None = None,
        data: dict | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.data = data


class TraceIntegrityError(InfrastructureError):
    """Trace events were missing, duplicated, or inconsistent."""


class CleanupError(InfrastructureError):
    """A sandbox container could not be confirmed removed."""
