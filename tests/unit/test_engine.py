"""Unit tests for ScanEngine execution isolation and result aggregation."""

from pathlib import Path

from sentinelscan.core.engine import ScanEngine
from sentinelscan.models.finding import Category, Confidence, Finding, Location, Severity
from sentinelscan.models.result import ScannerExecutionStatus
from sentinelscan.models.target import Target
from sentinelscan.scanners.base import BaseScanner
from sentinelscan.scanners.registry import ScannerRegistry


class FaultyScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "faulty-scanner"

    @property
    def category(self) -> Category:
        return Category.SAST

    @property
    def description(self) -> str:
        return "Scanner that raises unexpected exception during scan"

    def scan(self, target: Target) -> list[Finding]:
        raise RuntimeError("Simulated scanner failure")


class WorkingScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "working-scanner"

    @property
    def category(self) -> Category:
        return Category.SECRET

    @property
    def description(self) -> str:
        return "Working scanner returning 1 finding"

    def scan(self, target: Target) -> list[Finding]:
        return [
            Finding(
                scanner=self.name,
                category=self.category,
                rule_id="SEC-001",
                title="Potential Test Issue",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                description="Test description",
                impact="Test impact",
                remediation="Test remediation",
                location=Location(file_path=Path("test.py")),
            )
        ]


class UnavailableScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "unavailable-scanner"

    @property
    def category(self) -> Category:
        return Category.CONTAINER

    @property
    def description(self) -> str:
        return "Scanner unavailable for target"

    def is_available(self, target: Target) -> bool:
        return False

    def scan(self, target: Target) -> list[Finding]:
        return []


def test_scanner_failure_isolation():
    """Verify an exception in one scanner does not crash the overall scan execution."""
    registry = ScannerRegistry()
    registry.register(FaultyScanner())
    registry.register(WorkingScanner())

    engine = ScanEngine(registry=registry)
    target = Target(
        path=Path("."),
        is_directory=True,
        is_file=False,
        is_git_repo=True,
        file_count=5,
        total_size_bytes=100,
    )

    result = engine.run(target)

    # Entire scan completed and returned result
    assert len(result.scanner_results) == 2
    assert result.total_findings == 1
    assert result.findings[0].scanner == "working-scanner"

    # Statuses distinguished
    assert result.failed_scanners == ["faulty-scanner"]
    assert result.successful_scanners == ["working-scanner"]

    faulty_res = next(r for r in result.scanner_results if r.scanner_name == "faulty-scanner")
    assert faulty_res.status == ScannerExecutionStatus.FAILED
    assert faulty_res.error_message == "Simulated scanner failure"


def test_scanner_unavailable_status():
    """Verify scanners returning False for is_available are marked UNAVAILABLE."""
    registry = ScannerRegistry()
    registry.register(UnavailableScanner())

    engine = ScanEngine(registry=registry)
    target = Target(
        path=Path("."),
        is_directory=True,
        is_file=False,
        is_git_repo=True,
        file_count=5,
        total_size_bytes=100,
    )

    result = engine.run(target)
    assert len(result.scanner_results) == 1
    assert result.scanner_results[0].status == ScannerExecutionStatus.UNAVAILABLE
