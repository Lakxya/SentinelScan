"""Base scanner abstraction for SentinelScan modules."""

from abc import ABC, abstractmethod

from sentinelscan.models.finding import Category, Finding
from sentinelscan.models.target import Target


class BaseScanner(ABC):
    """Abstract base interface for all security scanners in SentinelScan.

    Future scanner modules (SAST, SCA, DAST, Secrets, Containers, IaC, Cloud, etc.)
    implement this interface to integrate seamlessly into the core engine.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique string identifier for the scanner module."""

    @property
    @abstractmethod
    def category(self) -> Category:
        """Primary security assessment category domain."""

    @property
    @abstractmethod
    def description(self) -> str:
        """Short human-readable summary of what this scanner checks."""

    def is_available(self, target: Target) -> bool:
        """Check if the scanner can run against the given target.

        Can be overridden by scanners to inspect target metadata, file extensions,
        or tool dependencies. Defaults to True.
        """
        return True

    @abstractmethod
    def scan(self, target: Target) -> list[Finding]:
        """Execute assessment on target and return discovered findings."""
