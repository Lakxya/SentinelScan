"""Command handler implementations for SentinelScan CLI actions."""

import sys

from sentinelscan import __version__
from sentinelscan.core.discovery import ProjectDiscoverer
from sentinelscan.core.engine import ScanEngine
from sentinelscan.core.exceptions import InvalidTargetError, TargetNotFoundError
from sentinelscan.core.graph_builder import ArchitectureGraphBuilder
from sentinelscan.reporting.console import ConsoleReporter
from sentinelscan.reporting.graph_reporter import JsonGraphReporter, TerminalGraphReporter
from sentinelscan.reporting.json import JsonReporter
from sentinelscan.scanners.aws_scanner import AwsScanner
from sentinelscan.scanners.dast_scanner import DastScanner
from sentinelscan.scanners.docker_scanner import DockerScanner
from sentinelscan.scanners.iac_scanner import IacScanner
from sentinelscan.scanners.k8s_scanner import KubernetesScanner
from sentinelscan.scanners.network_scanner import NetworkScanner
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


def handle_docker(
    target_path_str: str,
    json_output: bool = False,
    verbose: bool = False,
) -> int:
    """Execute dedicated Docker security scanning workflow against target path."""
    docker_registry = ScannerRegistry(register_defaults=False)
    docker_registry.register(DockerScanner())
    return handle_scan(
        target_path_str=target_path_str,
        json_output=json_output,
        verbose=verbose,
        registry=docker_registry,
    )


def handle_k8s(
    target_path_str: str,
    json_output: bool = False,
    verbose: bool = False,
) -> int:
    """Execute dedicated Kubernetes security scanning workflow against target path."""
    k8s_registry = ScannerRegistry(register_defaults=False)
    k8s_registry.register(KubernetesScanner())
    return handle_scan(
        target_path_str=target_path_str,
        json_output=json_output,
        verbose=verbose,
        registry=k8s_registry,
    )


def handle_aws(
    target_path_str: str,
    json_output: bool = False,
    verbose: bool = False,
) -> int:
    """Execute dedicated AWS security posture scanning workflow against target path."""
    aws_registry = ScannerRegistry(register_defaults=False)
    aws_registry.register(AwsScanner())
    return handle_scan(
        target_path_str=target_path_str,
        json_output=json_output,
        verbose=verbose,
        registry=aws_registry,
    )


def handle_dast(
    target_path_str: str = ".",
    target_url: str | None = None,
    json_output: bool = False,
    verbose: bool = False,
) -> int:
    """Execute dedicated DAST and web security scanning workflow against target path or active URL."""
    dast_registry = ScannerRegistry(register_defaults=False)
    dast_registry.register(DastScanner(target_url=target_url))
    return handle_scan(
        target_path_str=target_path_str,
        json_output=json_output,
        verbose=verbose,
        registry=dast_registry,
    )


def handle_graph(
    target_path_str: str = ".",
    json_output: bool = False,
    verbose: bool = False,
) -> int:
    """Execute architecture graph discovery workflow against target path and associate findings."""
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

    # Execute scanners to obtain findings for node association
    engine = ScanEngine()
    scan_result = engine.run(target)

    # Build architecture graph
    builder = ArchitectureGraphBuilder()
    graph = builder.build(target, scan_result=scan_result)

    reporter = JsonGraphReporter() if json_output else TerminalGraphReporter()
    try:
        output = reporter.render(graph) if isinstance(reporter, JsonGraphReporter) else reporter.render(graph, target_path_str=target_path_str)
        print(output)
    except Exception as e:  # noqa: BLE001
        print(f"Error rendering graph report: {e}", file=sys.stderr)
        return 2

    return 0


def handle_network(
    target_host: str,
    ports_list: list[int] | None = None,
    json_output: bool = False,
    verbose: bool = False,
) -> int:
    """Execute dedicated Network Security Assessment scanning workflow against target host."""
    net_registry = ScannerRegistry(register_defaults=False)
    net_registry.register(NetworkScanner(target_host=target_host, ports=ports_list))
    return handle_scan(
        target_path_str=".",
        json_output=json_output,
        verbose=verbose,
        registry=net_registry,
    )
