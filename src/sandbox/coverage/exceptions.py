"""Coverage pipeline failures."""


class CoverageError(RuntimeError):
    """Base error for coverage processing."""


class CoverageInputError(CoverageError):
    """A trajectory, prompt, or manifest could not be resolved safely."""


class CoverageIntegrityError(CoverageError):
    """Persisted coverage state conflicts with immutable input identity."""


class TaxonomyError(CoverageError):
    """The risk taxonomy is invalid or incompatible."""
