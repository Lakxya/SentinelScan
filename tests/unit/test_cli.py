"""Unit tests for SentinelScan CLI commands, parser, and argument handling."""

from sentinelscan.cli.commands import (
    handle_aws,
    handle_dast,
    handle_docker,
    handle_graph,
    handle_iac,
    handle_k8s,
    handle_network,
    handle_paths,
    handle_posture,
    handle_sast,
    handle_sca,
    handle_scan,
    handle_secrets,
    handle_version,
)
from sentinelscan.cli.main import create_parser


def test_cli_version_flag(capsys):
    """Verify --version flag prints version string."""
    parser = create_parser()
    args = parser.parse_args(["--version"])
    assert args.version is True

    exit_code = handle_version()
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "SentinelScan v1.3.0" in captured.out



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


def test_cli_sast_command(capsys):
    """Verify dedicated sast command executes SAST scanner workflow."""
    parser = create_parser()
    args = parser.parse_args(["sast", "."])
    assert args.command == "sast"

    exit_code = handle_sast(".", json_output=False, verbose=False)
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "sast-scanner" in captured.out


def test_cli_iac_command(capsys):
    """Verify dedicated iac command executes IaC scanner workflow."""
    parser = create_parser()
    args = parser.parse_args(["iac", "."])
    assert args.command == "iac"

    exit_code = handle_iac(".", json_output=False, verbose=False)
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "iac-scanner" in captured.out


def test_cli_sca_command(capsys):
    """Verify dedicated sca command executes SCA scanner workflow with --offline flag."""
    parser = create_parser()
    args = parser.parse_args(["sca", ".", "--offline"])
    assert args.command == "sca"
    assert args.offline is True

    exit_code = handle_sca(".", json_output=False, verbose=False, offline=True)
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "sca-scanner" in captured.out


def test_cli_docker_command(capsys):
    """Verify dedicated docker command executes Docker scanner workflow."""
    parser = create_parser()
    args = parser.parse_args(["docker", "."])
    assert args.command == "docker"

    exit_code = handle_docker(".", json_output=False, verbose=False)
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "docker-scanner" in captured.out


def test_cli_k8s_command(capsys):
    """Verify dedicated k8s command executes Kubernetes scanner workflow."""
    parser = create_parser()
    args = parser.parse_args(["k8s", "."])
    assert args.command == "k8s"

    exit_code = handle_k8s(".", json_output=False, verbose=False)
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "k8s-scanner" in captured.out


def test_cli_aws_command(capsys):
    """Verify dedicated aws command executes AWS scanner workflow."""
    parser = create_parser()
    args = parser.parse_args(["aws", "."])
    assert args.command == "aws"

    exit_code = handle_aws(".", json_output=False, verbose=False)
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "aws-scanner" in captured.out


def test_cli_dast_command(capsys):
    """Verify dedicated dast command executes DAST scanner workflow with static path and --target-url."""
    parser = create_parser()
    args = parser.parse_args(["dast", ".", "--target-url", "http://localhost:8080"])
    assert args.command == "dast"
    assert args.target_url == "http://localhost:8080"

    exit_code = handle_dast(".", target_url=None, json_output=False, verbose=False)
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "dast-scanner" in captured.out


def test_cli_graph_command(capsys):
    """Verify dedicated graph command builds and displays architecture graph."""
    parser = create_parser()
    args = parser.parse_args(["graph", "."])
    assert args.command == "graph"

    exit_code = handle_graph(".", json_output=False, verbose=False)
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "SentinelScan Architecture Graph" in captured.out


def test_cli_network_command(capsys):
    """Verify dedicated network command executes Network scanner workflow."""
    parser = create_parser()
    args = parser.parse_args(["network", "127.0.0.1", "--ports", "22,80,443"])
    assert args.command == "network"
    assert args.target_host == "127.0.0.1"
    assert args.ports == "22,80,443"

    exit_code = handle_network("127.0.0.1", ports_list=[22, 80, 443], json_output=False, verbose=False)
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "network-scanner" in captured.out


def test_cli_paths_command(capsys):
    """Verify dedicated paths command analyzes potential attack paths."""
    parser = create_parser()
    args = parser.parse_args(["paths", "."])
    assert args.command == "paths"

    exit_code = handle_paths(".", json_output=False, verbose=False)
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "SentinelScan Potential Attack Path Analysis" in captured.out


def test_cli_posture_command(capsys):
    """Verify dedicated posture command evaluates security posture score and remediation advice."""
    parser = create_parser()
    args = parser.parse_args(["posture", "."])
    assert args.command == "posture"

    exit_code = handle_posture(".", json_output=False, verbose=False)
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "SentinelScan Posture & Remediation Report" in captured.out
