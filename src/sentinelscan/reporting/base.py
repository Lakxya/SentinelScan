"""Base reporter interface for formatting scan results."""

from abc import ABC, abstractmethod

from sentinelscan.models.result import ScanResult


class BaseReporter(ABC):
    """Abstract base class for all output formatters."""

    @abstractmethod
    def render(self, result: ScanResult) -> str:
        """Render the ScanResult object into a formatted string report."""
