"""Custom exceptions for the ingestor module."""


class IngestionError(Exception):
    """Raised when SharpHound data cannot be loaded or parsed."""
