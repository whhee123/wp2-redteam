"""Replay-specific failures with stable preparation/protocol error codes."""


class ReplayError(RuntimeError):
    """Base class for second-week replay failures."""


class CanonicalizationError(ReplayError):
    pass


class ArtifactIntegrityError(ReplayError):
    pass


class ManifestIntegrityError(ReplayError):
    pass


class ReplayPreparationError(ReplayError):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code


class ReplayDivergenceError(ReplayError):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code

