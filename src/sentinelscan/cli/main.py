"""Main CLI entrypoint for SentinelScan."""

import argparse
import sys
from collections.abc import Sequence

from sentinelscan.cli.commands import (
    handle_aws,
    handle_dast,
    handle_docker,
    handle_graph,
    handle_iac,
    handle_k8s,
    handle_network,
    handle_paths,
    handle_sast,
    handle_sca,
    handle_scan,
    handle_secrets,
    handle_version,
)


def create_parser() -> argparse.ArgumentParser:
    """Construct the command line argument parser for SentinelScan."""
    parser = argparse.ArgumentParser(
        prog="sentinelscan",
        description="SentinelScan - Local-first DevSecOps and cloud security assessment CLI",
        epilog="For documentation and contributing guidelines, visit https://github.com/sentinelscan",
    )

    parser.add_argument(
        "-v",
        "--version",
        action="store_true",
        help="Show SentinelScan version information and exit.",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # 'scan' command
    scan_parser = subparsers.add_parser(
        "scan",
        help="Run security assessment against a target directory or file.",
    )
    scan_parser.add_argument(
        "target",
        metavar="PATH",
        help="Target directory or file path to assess (e.g. '.').",
    )
    scan_parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Render report output in structured JSON format.",
    )
    scan_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable detailed debug log messages.",
    )

    # 'secrets' command
    secrets_parser = subparsers.add_parser(
        "secrets",
        help="Run focused secret and credential scanning against a target directory or file.",
    )
    secrets_parser.add_argument(
        "target",
        metavar="PATH",
        help="Target directory or file path to assess for secrets (e.g. '.').",
    )
    secrets_parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Render report output in structured JSON format.",
    )
    secrets_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable detailed debug log messages.",
    )

    # 'sast' command
    sast_parser = subparsers.add_parser(
        "sast",
        help="Run focused Static Application Security Testing (SAST) against a target directory or file.",
    )
    sast_parser.add_argument(
        "target",
        metavar="PATH",
        help="Target directory or file path to assess with SAST (e.g. '.').",
    )
    sast_parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Render report output in structured JSON format.",
    )
    sast_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable detailed debug log messages.",
    )

    # 'iac' command
    iac_parser = subparsers.add_parser(
        "iac",
        help="Run focused Infrastructure-as-Code (IaC) security scanning against a target directory or file.",
    )
    iac_parser.add_argument(
        "target",
        metavar="PATH",
        help="Target directory or file path to assess for IaC misconfigurations (e.g. '.').",
    )
    iac_parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Render report output in structured JSON format.",
    )
    iac_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable detailed debug log messages.",
    )

    # 'sca' command
    sca_parser = subparsers.add_parser(
        "sca",
        help="Run focused Software Composition Analysis (SCA) against Python and JavaScript dependencies.",
    )
    sca_parser.add_argument(
        "target",
        metavar="PATH",
        help="Target directory or file path to assess for vulnerable dependencies (e.g. '.').",
    )
    sca_parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Render report output in structured JSON format.",
    )
    sca_parser.add_argument(
        "--offline",
        action="store_true",
        help="Strictly disable network calls and rely entirely on local vulnerability cache.",
    )
    sca_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable detailed debug log messages.",
    )

    # 'docker' command
    docker_parser = subparsers.add_parser(
        "docker",
        help="Run focused Docker security scanning against Dockerfiles.",
    )
    docker_parser.add_argument(
        "target",
        metavar="PATH",
        help="Target directory or file path to assess for Dockerfile security misconfigurations (e.g. '.').",
    )
    docker_parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Render report output in structured JSON format.",
    )
    docker_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable detailed debug log messages.",
    )

    # 'k8s' command
    k8s_parser = subparsers.add_parser(
        "k8s",
        help="Run focused Kubernetes security scanning against static YAML/JSON manifests.",
    )
    k8s_parser.add_argument(
        "target",
        metavar="PATH",
        help="Target directory or file path to assess for Kubernetes manifest security misconfigurations (e.g. '.').",
    )
    k8s_parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Render report output in structured JSON format.",
    )
    k8s_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable detailed debug log messages.",
    )

    # 'aws' command
    aws_parser = subparsers.add_parser(
        "aws",
        help="Run focused AWS security posture scanning against static IAM policies and local configuration.",
    )
    aws_parser.add_argument(
        "target",
        metavar="PATH",
        help="Target directory or file path to assess for AWS security misconfigurations (e.g. '.').",
    )
    aws_parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Render report output in structured JSON format.",
    )
    aws_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable detailed debug log messages.",
    )

    # 'dast' command
    dast_parser = subparsers.add_parser(
        "dast",
        help="Run focused Web Application and DAST security scanning against OpenAPI specs or web configs.",
    )
    dast_parser.add_argument(
        "target",
        nargs="?",
        default=".",
        metavar="PATH",
        help="Target directory or file path to assess (defaults to '.').",
    )
    dast_parser.add_argument(
        "--target-url",
        metavar="URL",
        help="Explicit HTTP/HTTPS target URL for active read-only response header inspection.",
    )
    dast_parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Render report output in structured JSON format.",
    )
    dast_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable detailed debug log messages.",
    )

    # 'graph' command
    graph_parser = subparsers.add_parser(
        "graph",
        help="Build and display local architecture resource and relationship graph.",
    )
    graph_parser.add_argument(
        "target",
        nargs="?",
        default=".",
        metavar="PATH",
        help="Target directory or file path to construct graph for (defaults to '.').",
    )
    graph_parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Render architecture graph output in structured JSON format.",
    )
    graph_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable detailed debug log messages.",
    )

    # 'network' command
    network_parser = subparsers.add_parser(
        "network",
        help="Run authorized Network Security Assessment scanning against an explicit target host.",
    )
    network_parser.add_argument(
        "target_host",
        metavar="HOST",
        help="Explicit target host IP or hostname (e.g. '127.0.0.1' or 'localhost').",
    )
    network_parser.add_argument(
        "--ports",
        metavar="PORTS",
        help="Comma-separated list of TCP ports to inspect (e.g. '22,80,443,3306').",
    )
    network_parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Render report output in structured JSON format.",
    )
    network_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable detailed debug log messages.",
    )

    # 'paths' command
    paths_parser = subparsers.add_parser(
        "paths",
        help="Analyze potential attack paths and correlated risk chains across architecture assets and findings.",
    )
    paths_parser.add_argument(
        "target",
        nargs="?",
        default=".",
        metavar="PATH",
        help="Target directory or file path to analyze potential attack paths for (defaults to '.').",
    )
    paths_parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Render potential attack paths in structured JSON format.",
    )
    paths_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable detailed debug log messages.",
    )

    return parser


def main(args: Sequence[str] | None = None) -> None:
    """Execute main CLI argument parsing and handler invocation."""
    parser = create_parser()
    parsed = parser.parse_args(args)

    if parsed.version:
        sys.exit(handle_version())

    if parsed.command == "scan":
        sys.exit(
            handle_scan(
                target_path_str=parsed.target,
                json_output=parsed.json_output,
                verbose=parsed.verbose,
            )
        )

    if parsed.command == "secrets":
        sys.exit(
            handle_secrets(
                target_path_str=parsed.target,
                json_output=parsed.json_output,
                verbose=parsed.verbose,
            )
        )

    if parsed.command == "sast":
        sys.exit(
            handle_sast(
                target_path_str=parsed.target,
                json_output=parsed.json_output,
                verbose=parsed.verbose,
            )
        )

    if parsed.command == "iac":
        sys.exit(
            handle_iac(
                target_path_str=parsed.target,
                json_output=parsed.json_output,
                verbose=parsed.verbose,
            )
        )

    if parsed.command == "sca":
        sys.exit(
            handle_sca(
                target_path_str=parsed.target,
                json_output=parsed.json_output,
                verbose=parsed.verbose,
                offline=parsed.offline,
            )
        )

    if parsed.command == "docker":
        sys.exit(
            handle_docker(
                target_path_str=parsed.target,
                json_output=parsed.json_output,
                verbose=parsed.verbose,
            )
        )

    if parsed.command == "k8s":
        sys.exit(
            handle_k8s(
                target_path_str=parsed.target,
                json_output=parsed.json_output,
                verbose=parsed.verbose,
            )
        )

    if parsed.command == "aws":
        sys.exit(
            handle_aws(
                target_path_str=parsed.target,
                json_output=parsed.json_output,
                verbose=parsed.verbose,
            )
        )

    if parsed.command == "dast":
        sys.exit(
            handle_dast(
                target_path_str=parsed.target,
                target_url=parsed.target_url,
                json_output=parsed.json_output,
                verbose=parsed.verbose,
            )
        )

    if parsed.command == "graph":
        sys.exit(
            handle_graph(
                target_path_str=parsed.target,
                json_output=parsed.json_output,
                verbose=parsed.verbose,
            )
        )

    if parsed.command == "network":
        ports_list = None
        if parsed.ports:
            try:
                ports_list = [int(p.strip()) for p in parsed.ports.split(",") if p.strip().isdigit()]
            except Exception:  # noqa: BLE001
                ports_list = None

        sys.exit(
            handle_network(
                target_host=parsed.target_host,
                ports_list=ports_list,
                json_output=parsed.json_output,
                verbose=parsed.verbose,
            )
        )

    if parsed.command == "paths":
        sys.exit(
            handle_paths(
                target_path_str=parsed.target,
                json_output=parsed.json_output,
                verbose=parsed.verbose,
            )
        )

    parser.print_help()
    sys.exit(0)


if __name__ == "__main__":
    main()
