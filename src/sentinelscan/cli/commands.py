"""Command handler implementations for SentinelScan CLI actions."""

import sys

from sentinelscan import __version__
from sentinelscan.core.discovery import ProjectDiscoverer
from sentinelscan.core.engine import ScanEngine
from sentinelscan.core.exceptions import InvalidTargetError, TargetNotFoundError
from sentinelscan.reporting.console import ConsoleReporter
from sentinelscan.reporting.json import JsonReporter
from sentinelscan.scanners.registry import ScannerRegistry
from sentinelscan.utils.logging import setup_logging


def handle_version() -> int:
    """Print SentinelScan package version."""
    print(f"SentinelScan v{__version__}")
    return 0


def handle_scan(
    target_path_str: str,
    json_output: bool = False,
    verbose: bool = False,
    registry: ScannerRegistry | None = None,
) -> int:
    """Execute scan workflow against target path.

    Args:
        target_path_str: Target directory or file path string.
        json_output: Render output as JSON if True, else console text.
        verbose: Enable verbose logging if True.
        registry: Custom ScannerRegistry instance (useful for testing).

    Returns:
        int: Status exit code (0 = success, 1 = user/target error, 2 = system error).
    """
    setup_logging(verbose=verbose)

    discoverer = ProjectDiscoverer()
    try:
        target = discoverer.discover(target_path_str)
    except (TargetNotFoundError, InvalidTargetError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:  # noqa: BLE001
        print(f"Error: Failed to discover target: {e}", file=sys.stderr)
        return 1

    engine = ScanEngine(registry=registry)
    result = engine.run(target)

    reporter = JsonReporter() if json_output else ConsoleReporter()
    try:
        output = reporter.render(result)
        print(output)
    except Exception as e:  # noqa: BLE001
        print(f"Error rendering report: {e}", file=sys.stderr)
        return 2


    return 0
