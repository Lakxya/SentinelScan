"""Scan result models aggregating execution outcome and findings."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from sentinelscan.models.finding import Finding
from sentinelscan.models.target import Target


class ScannerExecutionStatus(str, Enum):
    """Status of an individual scanner run."""

    SUCCESS = "SUCCESS"
    UNAVAILABLE = "UNAVAILABLE"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


@dataclass
class ScannerExecutionResult:
    """Outcome metadata for a single scanner execution."""

    scanner_name: str
    status: ScannerExecutionStatus
    finding_count: int = 0
    error_message: str | None = None
    duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert result to a JSON-serializable dictionary."""
        return {
            "scanner_name": self.scanner_name,
            "status": self.status.value if isinstance(self.status, Enum) else self.status,
            "finding_count": self.finding_count,
            "error_message": self.error_message,
            "duration_seconds": round(self.duration_seconds, 4),
        }


@dataclass
class ScanResult:
    """Complete security scan execution summary and findings container."""

    target: Target
    findings: list[Finding] = field(default_factory=list)
    scanner_results: list[ScannerExecutionResult] = field(default_factory=list)
    duration_seconds: float = 0.0

    @property
    def total_findings(self) -> int:
        """Total number of findings discovered across all scanners."""
        return len(self.findings)

    @property
    def successful_scanners(self) -> list[str]:
        """Names of scanners that completed successfully."""
        return [
            r.scanner_name
            for r in self.scanner_results
            if r.status == ScannerExecutionStatus.SUCCESS
        ]

    @property
    def failed_scanners(self) -> list[str]:
        """Names of scanners that failed during execution."""
        return [
            r.scanner_name
            for r in self.scanner_results
            if r.status == ScannerExecutionStatus.FAILED
        ]

    def to_dict(self) -> dict[str, Any]:
        """Convert complete scan result to a JSON-serializable dictionary."""
        return {
            "target": self.target.to_dict(),
            "summary": {
                "total_findings": self.total_findings,
                "total_scanners_registered": len(self.scanner_results),
                "duration_seconds": round(self.duration_seconds, 4),
            },
            "scanner_results": [r.to_dict() for r in self.scanner_results],
            "findings": [f.to_dict() for f in self.findings],
        }
