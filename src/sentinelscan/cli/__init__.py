"""SentinelScan Command Line Interface package."""

from sentinelscan.cli.commands import (
    handle_iac,
    handle_sast,
    handle_sca,
    handle_scan,
    handle_secrets,
    handle_version,
)
from sentinelscan.cli.main import create_parser, main

__all__ = [
    "create_parser",
    "handle_iac",
    "handle_sast",
    "handle_sca",
    "handle_scan",
    "handle_secrets",
    "handle_version",
    "main",
]
