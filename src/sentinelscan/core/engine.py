"""Scan engine orchestrating scanner execution and finding aggregation."""

import logging
import time
from typing import TYPE_CHECKING

from sentinelscan.models.finding import Finding
from sentinelscan.models.result import ScannerExecutionResult, ScannerExecutionStatus, ScanResult
from sentinelscan.models.target import Target

if TYPE_CHECKING:
    from sentinelscan.scanners.registry import ScannerRegistry

logger = logging.getLogger("sentinelscan.core.engine")


class ScanEngine:
    """Orchestrates security scanners with isolation, timing, and error handling."""

    def __init__(self, registry: "ScannerRegistry | None" = None) -> None:
        if registry is None:
            from sentinelscan.scanners.registry import ScannerRegistry
            self.registry = ScannerRegistry()
        else:
            self.registry = registry


    def run(self, target: Target) -> ScanResult:
        """Run all registered scanners against the target.

        Ensures scanner failures are isolated so that an unhandled exception in one scanner
        does not crash or abort the scan for other scanners.

        Args:
            target: Discovered Target model.

        Returns:
            ScanResult containing target metadata, combined findings, and scanner statuses.
        """
        start_time = time.perf_counter()
        all_findings: list[Finding] = []
        scanner_results: list[ScannerExecutionResult] = []

        scanners = self.registry.list_all()

        for scanner in scanners:
            scanner_start = time.perf_counter()

            # Check scanner availability
            try:
                available = scanner.is_available(target)
            except Exception as e:  # noqa: BLE001
                logger.warning(
                    "Error checking availability for scanner '%s': %s", scanner.name, str(e)
                )
                available = False

            if not available:
                scanner_results.append(
                    ScannerExecutionResult(
                        scanner_name=scanner.name,
                        status=ScannerExecutionStatus.UNAVAILABLE,
                        finding_count=0,
                        duration_seconds=time.perf_counter() - scanner_start,
                    )
                )
                continue

            # Execute scanner with isolation boundary
            try:
                findings = scanner.scan(target)
                duration = time.perf_counter() - scanner_start
                all_findings.extend(findings)

                scanner_results.append(
                    ScannerExecutionResult(
                        scanner_name=scanner.name,
                        status=ScannerExecutionStatus.SUCCESS,
                        finding_count=len(findings),
                        duration_seconds=duration,
                    )
                )
            except Exception as e:  # noqa: BLE001
                duration = time.perf_counter() - scanner_start

                logger.error(
                    "Scanner '%s' failed during execution: %s", scanner.name, str(e), exc_info=False
                )
                scanner_results.append(
                    ScannerExecutionResult(
                        scanner_name=scanner.name,
                        status=ScannerExecutionStatus.FAILED,
                        finding_count=0,
                        error_message=str(e),
                        duration_seconds=duration,
                    )
                )

        total_duration = time.perf_counter() - start_time
        return ScanResult(
            target=target,
            findings=all_findings,
            scanner_results=scanner_results,
            duration_seconds=total_duration,
        )
