"""Fuzzer-specific errors."""


class FuzzerError(Exception):
    """Base error for the campaign layer."""


class FuzzerIntegrityError(FuzzerError):
    """Persistent state or a state transition violates a contract."""


class CampaignConfigurationError(FuzzerError):
    """Campaign configuration cannot be executed safely."""


class CampaignStateError(FuzzerError):
    """The requested operation is invalid for the current state."""
