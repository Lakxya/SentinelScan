"""Unit tests for reporting modules (ConsoleReporter, JsonReporter, sensitive data redaction)."""

import json
from pathlib import Path

from sentinelscan.models.finding import Category, Confidence, Finding, Location, Severity
from sentinelscan.models.result import ScannerExecutionResult, ScannerExecutionStatus, ScanResult
from sentinelscan.models.target import Target
from sentinelscan.reporting.console import ConsoleReporter
from sentinelscan.reporting.json import JsonReporter, sanitize_sensitive_data


def test_sanitize_sensitive_data_redacts_credentials():
    """Verify sanitize_sensitive_data redacts secret keys recursively."""
    sensitive_dict = {
        "user": "admin",
        "api_key": "supersecretkey123",
        "nested": {
            "password": "my_password_456",
            "token": "bearer_token_789",
            "normal_field": "safe_value",
        },
    }

    sanitized = sanitize_sensitive_data(sensitive_dict)

    assert sanitized["user"] == "admin"
    assert sanitized["api_key"] == "[REDACTED]"
    assert sanitized["nested"]["password"] == "[REDACTED]"
    assert sanitized["nested"]["token"] == "[REDACTED]"
    assert sanitized["nested"]["normal_field"] == "safe_value"


def test_json_reporter_machine_readable_output():
    """Verify JsonReporter produces valid machine-readable JSON without leaking sensitive metadata."""
    target = Target(
        path=Path("."),
        is_directory=True,
        is_file=False,
        is_git_repo=True,
        file_count=5,
        total_size_bytes=500,
        detected_indicators=["python"],
    )

    finding = Finding(
        scanner="secret-scanner",
        category=Category.SECRET,
        rule_id="SEC-99",
        title="Detected Secret Pattern",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="Found key pattern",
        impact="Leakage",
        remediation="Rotate key",
        location=Location(file_path=Path("config.py"), start_line=1),
        metadata={"secret_value": "raw_secret_token_123"},
    )

    result = ScanResult(
        target=target,
        findings=[finding],
        scanner_results=[
            ScannerExecutionResult(
                scanner_name="secret-scanner",
                status=ScannerExecutionStatus.SUCCESS,
                finding_count=1,
            )
        ],
        duration_seconds=0.05,
    )

    reporter = JsonReporter()
    json_output = reporter.render(result)

    # Verify JSON structure
    parsed = json.loads(json_output)
    assert "target" in parsed
    assert "summary" in parsed
    assert "scanner_results" in parsed
    assert "findings" in parsed
    assert parsed["summary"]["total_findings"] == 1

    # Verify secret redaction
    assert parsed["findings"][0]["metadata"]["secret_value"] == "[REDACTED]"
    assert "raw_secret_token_123" not in json_output


def test_console_reporter_rendering():
    """Verify ConsoleReporter formats summary and initialized scanner status correctly."""
    target = Target(
        path=Path("."),
        is_directory=True,
        is_file=False,
        is_git_repo=True,
        file_count=12,
        total_size_bytes=4096,
        detected_indicators=["python", "docker"],
    )

    result = ScanResult(target=target, findings=[], scanner_results=[], duration_seconds=0.01)
    reporter = ConsoleReporter()
    rendered = reporter.render(result)

    assert "SentinelScan Security Assessment" in rendered
    assert "Target Type       : Directory" in rendered
    assert "Total Files       : 12" in rendered
    assert "0 scanner modules currently registered" in rendered
