"""Command handler implementations for SentinelScan CLI actions."""

import sys

from sentinelscan import __version__
from sentinelscan.core.discovery import ProjectDiscoverer
from sentinelscan.core.engine import ScanEngine
from sentinelscan.core.exceptions import InvalidTargetError, TargetNotFoundError
from sentinelscan.reporting.console import ConsoleReporter
from sentinelscan.reporting.json import JsonReporter
from sentinelscan.scanners.iac_scanner import IacScanner
from sentinelscan.scanners.registry import ScannerRegistry
from sentinelscan.scanners.sast_scanner import SastScanner
from sentinelscan.scanners.sca_scanner import ScaScanner
from sentinelscan.scanners.secret_scanner import SecretScanner
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
    """Execute full scan workflow against target path.

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


def handle_secrets(
    target_path_str: str,
    json_output: bool = False,
    verbose: bool = False,
) -> int:
    """Execute dedicated secret scanning workflow against target path."""
    secrets_registry = ScannerRegistry(register_defaults=False)
    secrets_registry.register(SecretScanner())
    return handle_scan(
        target_path_str=target_path_str,
        json_output=json_output,
        verbose=verbose,
        registry=secrets_registry,
    )


def handle_sast(
    target_path_str: str,
    json_output: bool = False,
    verbose: bool = False,
) -> int:
    """Execute dedicated SAST security scanning workflow against target path."""
    sast_registry = ScannerRegistry(register_defaults=False)
    sast_registry.register(SastScanner())
    return handle_scan(
        target_path_str=target_path_str,
        json_output=json_output,
        verbose=verbose,
        registry=sast_registry,
    )


def handle_iac(
    target_path_str: str,
    json_output: bool = False,
    verbose: bool = False,
) -> int:
    """Execute dedicated IaC security scanning workflow against target path."""
    iac_registry = ScannerRegistry(register_defaults=False)
    iac_registry.register(IacScanner())
    return handle_scan(
        target_path_str=target_path_str,
        json_output=json_output,
        verbose=verbose,
        registry=iac_registry,
    )


def handle_sca(
    target_path_str: str,
    json_output: bool = False,
    verbose: bool = False,
    offline: bool = False,
) -> int:
    """Execute dedicated SCA security scanning workflow against target path."""
    sca_registry = ScannerRegistry(register_defaults=False)
    sca_registry.register(ScaScanner(offline=offline))
    return handle_scan(
        target_path_str=target_path_str,
        json_output=json_output,
        verbose=verbose,
        registry=sca_registry,
    )
