"""Example mock scanner demonstrating how to extend SentinelScan with custom scanner modules."""

from sentinelscan.models.finding import Category, Confidence, Finding, Location, Severity
from sentinelscan.models.target import Target
from sentinelscan.scanners.base import BaseScanner
from sentinelscan.scanners.registry import ScannerRegistry


class SampleSecChecker(BaseScanner):
    """Reference example scanner illustrating implementation of BaseScanner interface."""

    @property
    def name(self) -> str:
        return "sample-sec-checker"

    @property
    def category(self) -> Category:
        return Category.SAST

    @property
    def description(self) -> str:
        return "Example scanner assessing mock code safety rules."

    def is_available(self, target: Target) -> bool:
        """Check if target contains python files or indicators."""
        return "python" in target.detected_indicators or target.is_file

    def scan(self, target: Target) -> list[Finding]:
        """Perform scan against target and return list of findings."""
        # Custom scanner logic goes here
        # Return structured Finding objects
        return [
            Finding(
                scanner=self.name,
                category=self.category,
                rule_id="SAMPLE-001",
                title="Example Insecure Pattern",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                description="Demonstration finding created by reference mock scanner.",
                impact="Potential unauthorized data exposure in sample component.",
                remediation="Apply input sanitization and use safe default parameters.",
                location=Location(
                    file_path=target.path / "example.py",
                    start_line=10,
                    end_line=15,
                ),
                resource_id="sample-resource-1",
                tags=["sample", "sast"],
            )
        ]


if __name__ == "__main__":
    from sentinelscan.core.discovery import ProjectDiscoverer
    from sentinelscan.core.engine import ScanEngine
    from sentinelscan.reporting.console import ConsoleReporter

    print("Registering sample scanner into custom registry...")
    registry = ScannerRegistry()
    registry.register(SampleSecChecker())

    discoverer = ProjectDiscoverer()
    target = discoverer.discover(".")

    print(f"Discovered target: {target.path}")
    engine = ScanEngine(registry=registry)
    result = engine.run(target)

    reporter = ConsoleReporter()
    print(reporter.render(result))
