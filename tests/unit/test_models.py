"""Unit tests for SentinelScan domain models (Finding, Target, Location, ScanResult)."""

from pathlib import Path

from sentinelscan.models.finding import Category, Confidence, Finding, Location, Severity
from sentinelscan.models.result import ScannerExecutionResult, ScannerExecutionStatus, ScanResult
from sentinelscan.models.target import Target


def test_location_to_dict_omits_raw_snippets():
    """Verify Location only stores file_path, start_line, end_line and no raw code snippets."""
    loc = Location(file_path=Path("src/app.py"), start_line=12, end_line=15)
    data = loc.to_dict()

    assert data == {
        "file_path": "src\\app.py" if "\\" in str(loc.file_path) else "src/app.py",
        "start_line": 12,
        "end_line": 15,
    }
    assert "snippet" not in data
    assert "raw_code" not in data


def test_finding_deterministic_fingerprint_and_dict():
    """Verify Finding auto-generates deterministic finding_id and fingerprint."""
    loc = Location(file_path=Path("main.py"), start_line=5)
    f1 = Finding(
        scanner="sast-rules",
        category=Category.SAST,
        rule_id="RULE-01",
        title="SQL Injection Vulnerability",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="Unsanitized query string.",
        impact="Data leakage",
        remediation="Use parameterized queries",
        location=loc,
        tags=["sast", "sql-injection"],
    )

    assert f1.finding_id.startswith("FS-")
    assert len(f1.fingerprint) == 16

    data = f1.to_dict()
    assert data["finding_id"] == f1.finding_id
    assert data["scanner"] == "sast-rules"
    assert data["category"] == "sast"
    assert data["severity"] == "HIGH"
    assert data["confidence"] == "HIGH"
    assert data["tags"] == ["sast", "sql-injection"]


def test_scan_result_distinguishes_zero_findings_from_failure():
    """Verify ScanResult differentiates SUCCESS with 0 findings from scanner FAILED status."""
    target = Target(
        path=Path("."),
        is_directory=True,
        is_file=False,
        is_git_repo=True,
        file_count=10,
        total_size_bytes=1000,
    )

    success_result = ScannerExecutionResult(
        scanner_name="clean-scanner",
        status=ScannerExecutionStatus.SUCCESS,
        finding_count=0,
    )

    failed_result = ScannerExecutionResult(
        scanner_name="broken-scanner",
        status=ScannerExecutionStatus.FAILED,
        finding_count=0,
        error_message="Runtime error in scanner",
    )

    scan_result = ScanResult(
        target=target,
        findings=[],
        scanner_results=[success_result, failed_result],
    )

    assert scan_result.total_findings == 0
    assert scan_result.successful_scanners == ["clean-scanner"]
    assert scan_result.failed_scanners == ["broken-scanner"]
    assert scan_result.scanner_results[0].status == ScannerExecutionStatus.SUCCESS
    assert scan_result.scanner_results[1].status == ScannerExecutionStatus.FAILED
