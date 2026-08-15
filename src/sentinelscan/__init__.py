"""SentinelScan - Local-first DevSecOps and cloud security assessment CLI."""

__version__ = "0.1.0"
__author__ = "SentinelScan Contributors"

from sentinelscan.models.finding import Category, Confidence, Finding, Location, Severity
from sentinelscan.models.result import ScanResult
from sentinelscan.models.target import Target
from sentinelscan.scanners.base import BaseScanner

__all__ = [
    "BaseScanner",
    "Category",
    "Confidence",
    "Finding",
    "Location",
    "ScanResult",
    "Severity",
    "Target",
]
