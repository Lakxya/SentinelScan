"""Unit tests for BaseScanner interface and ScannerRegistry."""

import pytest

from sentinelscan.core.exceptions import ScannerAlreadyRegisteredError, ScannerNotFoundError
from sentinelscan.models.finding import Category, Finding
from sentinelscan.models.target import Target
from sentinelscan.scanners.base import BaseScanner
from sentinelscan.scanners.registry import ScannerRegistry


class DummyScanner(BaseScanner):
    def __init__(self, scanner_name: str = "dummy") -> None:
        self._name = scanner_name

    @property
    def name(self) -> str:
        return self._name

    @property
    def category(self) -> Category:
        return Category.SAST

    @property
    def description(self) -> str:
        return "Dummy test scanner"

    def scan(self, target: Target) -> list[Finding]:
        return []


def test_scanner_registry_lifecycle():
    """Verify scanner registration, lookup, listing, and clearing."""
    registry = ScannerRegistry()
    assert len(registry) == 0

    s1 = DummyScanner("scanner-1")
    s2 = DummyScanner("scanner-2")

    registry.register(s1)
    registry.register(s2)

    assert len(registry) == 2
    assert registry.get("scanner-1") is s1
    assert registry.get("scanner-2") is s2
    assert registry.list_all() == [s1, s2]


def test_scanner_registry_duplicate_registration_raises_error():
    """Verify registering two scanners with the same name raises error."""
    registry = ScannerRegistry()
    s1 = DummyScanner("duplicate-name")
    s2 = DummyScanner("duplicate-name")

    registry.register(s1)
    with pytest.raises(ScannerAlreadyRegisteredError):
        registry.register(s2)


def test_scanner_registry_lookup_missing_raises_error():
    """Verify getting a non-existent scanner raises ScannerNotFoundError."""
    registry = ScannerRegistry()
    with pytest.raises(ScannerNotFoundError):
        registry.get("non-existent")
