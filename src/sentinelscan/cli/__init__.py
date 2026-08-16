"""SentinelScan Command Line Interface package."""

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
from sentinelscan.cli.main import create_parser, main

__all__ = [
    "create_parser",
    "handle_aws",
    "handle_dast",
    "handle_docker",
    "handle_graph",
    "handle_iac",
    "handle_k8s",
    "handle_network",
    "handle_paths",
    "handle_sast",
    "handle_sca",
    "handle_scan",
    "handle_secrets",
    "handle_version",
    "main",
]
