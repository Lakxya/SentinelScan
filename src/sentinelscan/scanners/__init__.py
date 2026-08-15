"""Scanner base interfaces and central registry."""

from sentinelscan.scanners.base import BaseScanner
from sentinelscan.scanners.registry import ScannerRegistry

__all__ = ["BaseScanner", "ScannerRegistry"]
