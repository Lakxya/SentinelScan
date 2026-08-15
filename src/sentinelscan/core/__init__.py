"""Core orchestration, project discovery, and exceptions for SentinelScan."""

from sentinelscan.core.discovery import ProjectDiscoverer
from sentinelscan.core.engine import ScanEngine
from sentinelscan.core.exceptions import (
    InvalidTargetError,
    ReportGenerationError,
    ScannerAlreadyRegisteredError,
    ScannerError,
    ScannerNotFoundError,
    SentinelScanError,
    TargetNotFoundError,
)

__all__ = [
    "InvalidTargetError",
    "ProjectDiscoverer",
    "ReportGenerationError",
    "ScanEngine",
    "ScannerAlreadyRegisteredError",
    "ScannerError",
    "ScannerNotFoundError",
    "SentinelScanError",
    "TargetNotFoundError",
]
