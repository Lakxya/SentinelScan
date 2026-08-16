"""Unit tests for PostureEngine, RemediationEngine, data models, and posture reporters."""

import socket
from pathlib import Path

from sentinelscan.core.posture_engine import PostureEngine, RemediationEngine, calculate_grade
from sentinelscan.models.attack_path import AttackPath
from sentinelscan.models.finding import Category, Confidence, Finding, Location, Severity
from sentinelscan.models.posture import PostureScore
from sentinelscan.models.result import ScanResult
from sentinelscan.models.target import Target
from sentinelscan.reporting.posture_reporter import JsonPostureReporter, TerminalPostureReporter


def make_dummy_target() -> Target:
    return Target(
        path=Path("."),
        is_directory=True,
        is_file=False,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=100,
    )


def test_posture_calculate_grade():
    """Verify numeric score to letter grade conversion."""
    assert calculate_grade(100.0) == "A+"
    assert calculate_grade(95.0) == "A+"
    assert calculate_grade(92.0) == "A"
    assert calculate_grade(85.0) == "B"
    assert calculate_grade(75.0) == "C"
    assert calculate_grade(65.0) == "D"
    assert calculate_grade(40.0) == "F"


def test_posture_zero_findings_benchmark():
    """Verify project with 0 findings receives 100.0 score and Grade A+."""
    scan_res = ScanResult(target=make_dummy_target())
    engine = PostureEngine()
    posture = engine.evaluate_posture(scan_res)

    assert posture.overall_score == 100.0
    assert posture.grade == "A+"
    assert len(posture.domain_scores) == 9
    for ds in posture.domain_scores.values():
        assert ds.score == 100.0
        assert ds.grade == "A+"


def test_posture_scoring_formula_and_clamping():
    """Verify posture scoring formula, severity weights, confidence multipliers, and 0-100 clamping."""
    finding_crit = Finding(
        rule_id="AWS-IAM-WILDCARD",
        category=Category.CLOUD,
        severity=Severity.CRITICAL,  # Weight: 15.0
        confidence=Confidence.HIGH,  # Multiplier: 1.0 -> 15.0 pts deduction
        title="Wildcard IAM",
        description="Wildcard IAM action",
        remediation="Restrict IAM actions.",
        location=Location(file_path=Path("main.tf"), start_line=1),
        scanner="aws-scanner",
        impact="Critical AWS vulnerability",
    )

    scan_res = ScanResult(target=make_dummy_target(), findings=[finding_crit])
    engine = PostureEngine()
    posture = engine.evaluate_posture(scan_res)

    # Cloud domain score should be 100.0 - 15.0 = 85.0 (Grade B)
    cloud_ds = posture.domain_scores["cloud"]
    assert cloud_ds.score == 85.0
    assert cloud_ds.grade == "B"

    # Overall base score: 8 domain scores of 100.0 + 1 domain score of 85.0 -> (800 + 85) / 9 = 98.33 -> 98.3
    assert round(posture.overall_score, 1) == 98.3
    assert posture.grade == "A+"


def test_posture_finding_deduplication():
    """Verify identical findings with matching fingerprints are deduplicated before scoring."""
    f1 = Finding(
        rule_id="SEC-001",
        category=Category.SECRET,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        title="AWS Key",
        description="AWS Key leaked",
        remediation="Revoke key.",
        location=Location(file_path=Path("app.py"), start_line=10),
        scanner="secret-scanner",
        impact="Exposed AWS credential",
    )
    f2 = Finding(
        rule_id="SEC-001",
        category=Category.SECRET,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        title="AWS Key",
        description="AWS Key leaked",
        remediation="Revoke key.",
        location=Location(file_path=Path("app.py"), start_line=10),
        scanner="secret-scanner",
        impact="Exposed AWS credential",
    )
    assert f1.fingerprint == f2.fingerprint

    scan_res = ScanResult(target=make_dummy_target(), findings=[f1, f2])
    engine = PostureEngine()
    posture = engine.evaluate_posture(scan_res)

    # Secret domain score should deduct 8.0 pts ONLY ONCE (100.0 - 8.0 = 92.0)
    secret_ds = posture.domain_scores["secret"]
    assert secret_ds.score == 92.0
    assert len(secret_ds.deductions) == 1


def test_posture_anti_double_counting_cap():
    """Verify attack path penalties are capped at 15.0 max and applied to Overall Score only."""
    path1 = AttackPath(
        path_id="AP-1",
        title="Crit Path 1",
        entry_node_id="n1",
        target_node_id="n2",
        composite_severity=Severity.CRITICAL,  # -3.0 pts
    )
    path2 = AttackPath(
        path_id="AP-2",
        title="Crit Path 2",
        entry_node_id="n3",
        target_node_id="n4",
        composite_severity=Severity.CRITICAL,  # -3.0 pts
    )

    scan_res = ScanResult(target=make_dummy_target())
    engine = PostureEngine()
    posture = engine.evaluate_posture(scan_res, attack_paths=[path1, path2])

    # Domain scores should remain 100.0
    for ds in posture.domain_scores.values():
        assert ds.score == 100.0

    # Overall score should deduct 6.0 pts path penalty from 100.0 base -> 94.0
    assert posture.overall_score == 94.0


def test_remediation_priority_formula():
    """Verify RemediationEngine priority formula ranks remediations correctly."""
    f_high = Finding(
        rule_id="SAST-CMD-INJ",
        category=Category.SAST,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        title="Command Injection",
        description="os.system call",
        remediation="Use subprocess list args.",
        location=Location(file_path=Path("main.py"), start_line=5),
        scanner="sast-scanner",
        impact="Command execution",
    )
    f_med = Finding(
        rule_id="K8S-NO-READONLY",
        category=Category.KUBERNETES,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        title="Writable Root FS",
        description="readOnlyRootFilesystem not set",
        remediation="Set readOnlyRootFilesystem=true",
        location=Location(file_path=Path("pod.yaml"), start_line=12),
        scanner="k8s-scanner",
        impact="FS modification",
    )

    rems = RemediationEngine.generate_remediations([f_high, f_med])
    assert len(rems) == 2
    assert rems[0].rule_id == "SAST-CMD-INJ"
    assert rems[0].priority == 1


def test_posture_zero_network(monkeypatch):
    """Verify PostureEngine evaluation performs ZERO network socket calls."""
    def _forbidden_connect(*args, **kwargs):
        raise RuntimeError("Network socket call attempted during posture analysis!")

    monkeypatch.setattr(socket, "socket", _forbidden_connect)

    scan_res = ScanResult(target=make_dummy_target())
    posture = PostureEngine().evaluate_posture(scan_res)
    assert isinstance(posture, PostureScore)


def test_posture_reporters_and_json_serialization():
    """Verify TerminalPostureReporter and JsonPostureReporter outputs."""
    scan_res = ScanResult(target=make_dummy_target())
    posture = PostureEngine().evaluate_posture(scan_res)

    terminal_out = TerminalPostureReporter().render(posture, target_path_str=".")
    assert "SentinelScan Posture & Remediation Report" in terminal_out
    assert "100.0 / 100.0" in terminal_out

    json_out = JsonPostureReporter().render(posture)
    assert '"overall_score": 100.0' in json_out
    assert '"grade": "A+"' in json_out
