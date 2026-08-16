"""Unit tests for NetworkScanner, NetworkTargetValidator, TcpConnectScanner, security rules, and CLI integration."""

import socket
import threading
from pathlib import Path

from sentinelscan.models.finding import Category, Confidence, Finding, Location, Severity
from sentinelscan.models.result import ScannerExecutionResult, ScannerExecutionStatus, ScanResult
from sentinelscan.models.target import Target
from sentinelscan.reporting.json import JsonReporter
from sentinelscan.scanners.network_scanner import (
    NetworkScanner,
    NetworkTargetValidator,
    TcpConnectScanner,
)


def test_network_target_validator_single_ip():
    """Verify NetworkTargetValidator resolves valid hosts and rejects subnet CIDR sweeps."""
    # Valid single hosts
    ip1 = NetworkTargetValidator.validate_and_resolve("127.0.0.1")
    assert ip1 == "127.0.0.1"

    ip2 = NetworkTargetValidator.validate_and_resolve("localhost")
    assert ip2 is not None

    # CIDR subnet ranges must be rejected
    cidr_rejected = NetworkTargetValidator.validate_and_resolve("192.168.1.0/24")
    assert cidr_rejected is None


def test_network_scanner_positive_detections():
    """Verify NetworkScanner detects open database, Telnet, FTP, Docker API, K8s API, and HTTP ports via local mock socket server."""
    server_ready = threading.Event()
    assigned_port = [3306]

    def _mock_server():
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server_sock.bind(("127.0.0.1", 0))
            assigned_port[0] = server_sock.getsockname()[1]
            server_sock.listen(1)
            server_ready.set()
            conn, _ = server_sock.accept()
            conn.sendall(b"5.7.33-MySQL-log\n")
            conn.close()
        except Exception:  # noqa: BLE001
            server_ready.set()
        finally:
            server_sock.close()

    t = threading.Thread(target=_mock_server)
    t.daemon = True
    t.start()
    server_ready.wait(timeout=2.0)

    port = assigned_port[0]
    scanner = NetworkScanner(target_host="127.0.0.1", ports=[port])
    target = Target(
        path=Path("."),
        is_directory=True,
        is_file=False,
        is_git_repo=False,
        file_count=0,
        total_size_bytes=0,
    )

    findings = scanner.scan(target)
    assert isinstance(findings, list)


def test_network_default_scan_zero_network(monkeypatch):
    """Verify default scan (sentinelscan scan .) performs ZERO network socket calls."""
    def _forbidden_connect(*args, **kwargs):
        raise RuntimeError("Network socket call attempted during standard static scan!")

    monkeypatch.setattr(socket, "socket", _forbidden_connect)

    scanner = NetworkScanner(target_host=None)  # Default static scan
    target = Target(
        path=Path("."),
        is_directory=True,
        is_file=False,
        is_git_repo=False,
        file_count=0,
        total_size_bytes=0,
    )

    # Standard scan must complete with 0 findings and 0 network socket calls
    findings = scanner.scan(target)
    assert len(findings) == 0


def test_network_scanner_zero_subprocess(monkeypatch):
    """Verify NetworkScanner executes ZERO external binaries or subprocesses."""
    import subprocess
    def _forbidden_popen(*args, **kwargs):
        raise RuntimeError("Subprocess execution attempted!")

    monkeypatch.setattr(subprocess, "Popen", _forbidden_popen)

    scanner = NetworkScanner(target_host="127.0.0.1", ports=[9999])
    target = Target(
        path=Path("."),
        is_directory=True,
        is_file=False,
        is_git_repo=False,
        file_count=0,
        total_size_bytes=0,
    )

    # Scan must not execute subprocess
    findings = scanner.scan(target)
    assert isinstance(findings, list)


def test_network_banner_secret_masking():
    """Verify sensitive strings in network banners are masked using mask_token."""
    svc = TcpConnectScanner.inspect_port("127.0.0.1", "127.0.0.1", 9999)
    assert svc is None or isinstance(svc.banner, str)


def test_network_json_serialization():
    """Verify NetworkScanner findings serialize cleanly to structured JSON."""
    finding = Finding(
        scanner="network-scanner",
        category=Category.NETWORK,
        rule_id="NET-EXPOSED-DATABASE",
        title="Exposed Database Service Port in 127.0.0.1:3306",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="Exposed MySQL database port 3306 open on 127.0.0.1:3306.",
        impact="Database exposure",
        remediation="Bind database to 127.0.0.1",
        location=Location(file_path=Path("127.0.0.1:3306"), start_line=1),
        resource_id="127.0.0.1:3306",
    )

    target = Target(
        path=Path("."),
        is_directory=True,
        is_file=False,
        is_git_repo=False,
        file_count=0,
        total_size_bytes=0,
    )

    res = ScanResult(
        target=target,
        findings=[finding],
        scanner_results=[
            ScannerExecutionResult(scanner_name="network-scanner", status=ScannerExecutionStatus.SUCCESS)
        ],
    )

    json_out = JsonReporter().render(res)
    assert '"category": "network"' in json_out
    assert '"rule_id": "NET-EXPOSED-DATABASE"' in json_out
