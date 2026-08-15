"""Unit tests for SentinelScan CLI commands, parser, and argument handling."""

from sentinelscan.cli.commands import handle_scan, handle_secrets, handle_version
from sentinelscan.cli.main import create_parser


def test_cli_version_flag(capsys):
    """Verify --version flag prints version string."""
    parser = create_parser()
    args = parser.parse_args(["--version"])
    assert args.version is True

    exit_code = handle_version()
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "SentinelScan v0.1.0" in captured.out


def test_cli_scan_invalid_path(capsys):
    """Verify scanning an invalid non-existent path prints error and returns exit code 1."""
    exit_code = handle_scan("./non_existent_directory_abc123")
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "Error:" in captured.err


def test_cli_scan_valid_directory(capsys):
    """Verify scanning current valid directory returns exit code 0."""
    exit_code = handle_scan(".", json_output=False, verbose=False)
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "TARGET DISCOVERY" in captured.out


def test_cli_scan_json_output_flag(capsys):
    """Verify scan command with --json returns valid JSON output and exit code 0."""
    exit_code = handle_scan(".", json_output=True, verbose=False)
    assert exit_code == 0
    captured = capsys.readouterr()
    assert '"summary":' in captured.out


def test_cli_secrets_command(capsys):
    """Verify dedicated secrets command executes secret scanner workflow."""
    parser = create_parser()
    args = parser.parse_args(["secrets", "."])
    assert args.command == "secrets"

    exit_code = handle_secrets(".", json_output=False, verbose=False)
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "secret-scanner" in captured.out
