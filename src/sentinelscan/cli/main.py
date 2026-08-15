"""Main CLI entrypoint for SentinelScan."""

import argparse
import sys
from collections.abc import Sequence

from sentinelscan.cli.commands import handle_scan, handle_version


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

    parser.print_help()
    sys.exit(0)


if __name__ == "__main__":
    main()
