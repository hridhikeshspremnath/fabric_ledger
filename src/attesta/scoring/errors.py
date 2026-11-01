class ScoringError(Exception):
    """Base class for scoring-service failures."""


class InvalidTarget(ScoringError):
    """ecosystem/package/version failed validation."""


class FetchError(ScoringError):
    """The package could not be resolved or downloaded safely."""


class ArchiveError(ScoringError):
    """The downloaded archive could not be read."""


class ConfigError(ScoringError):
    """Misconfiguration (model factory, key location, ...)."""


class SubmitError(ScoringError):
    """The gateway refused or could not be reached."""
