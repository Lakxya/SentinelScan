"""Comprehensive unit tests for SecretScanner, detector rules, secret masking, and leak prevention."""


from sentinelscan.models.finding import Category, Confidence, Severity
from sentinelscan.models.target import Target
from sentinelscan.reporting.console import ConsoleReporter
from sentinelscan.reporting.json import JsonReporter
from sentinelscan.scanners.secret_scanner import SecretScanner, calculate_entropy, mask_token

# Synthetic test credentials (non-operational)
SYNTHETIC_AWS_KEY = "AKIA1234567890ABCDEF"
SYNTHETIC_AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
SYNTHETIC_GITHUB_PAT = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
SYNTHETIC_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)
SYNTHETIC_DB_PASS = "SuperSecretPassword123"
SYNTHETIC_DB_URL = f"postgresql://admin:{SYNTHETIC_DB_PASS}@localhost:5432/production_db"
SYNTHETIC_PEM = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC3x...\n"
    "-----END PRIVATE KEY-----"
)
SYNTHETIC_GENERIC_SECRET = "x9K#mP2$vN5&qL8*"


def test_entropy_calculation():
    """Verify Shannon entropy computation."""
    assert calculate_entropy("") == 0.0
    assert calculate_entropy("AAAA") == 0.0
    # High entropy string
    assert calculate_entropy(SYNTHETIC_GENERIC_SECRET) > 3.5


def test_mask_token_helper():
    """Verify token masking never returns raw secret."""
    assert mask_token("short") == "s***t"
    assert mask_token(SYNTHETIC_AWS_KEY) == "AKIA************CDEF"
    assert SYNTHETIC_AWS_KEY not in mask_token(SYNTHETIC_AWS_KEY)


def test_aws_access_key_detection_and_leak_prevention(tmp_path):
    """Verify detection of AWS Access Key ID and strict absence of raw key in outputs."""
    target_file = tmp_path / "aws_config.py"
    target_file.write_text(f"AWS_KEY_ID = '{SYNTHETIC_AWS_KEY}'\n")

    scanner = SecretScanner()
    target = Target(
        path=target_file,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(target_file.read_bytes()),
    )

    findings = scanner.scan(target)
    assert len(findings) == 1

    f = findings[0]
    assert f.rule_id == "SECRET-AWS-ACCESS-KEY"
    assert f.category == Category.SECRET
    assert f.severity == Severity.CRITICAL
    assert f.confidence == Confidence.HIGH
    assert f.metadata["masked_value"] == "AKIA************CDEF"

    # STRICT LEAK PREVENTION ASSERTIONS
    assert SYNTHETIC_AWS_KEY not in f.description
    assert SYNTHETIC_AWS_KEY not in f.impact
    assert SYNTHETIC_AWS_KEY not in f.remediation
    assert SYNTHETIC_AWS_KEY not in str(f.metadata)
    assert SYNTHETIC_AWS_KEY not in repr(f)

    # Reporter output leak prevention assertions
    from sentinelscan.models.result import (
        ScannerExecutionResult,
        ScannerExecutionStatus,
        ScanResult,
    )

    res = ScanResult(
        target=target,
        findings=findings,
        scanner_results=[
            ScannerExecutionResult(scanner_name="secret-scanner", status=ScannerExecutionStatus.SUCCESS)
        ],
    )
    console_out = ConsoleReporter().render(res)
    json_out = JsonReporter().render(res)

    assert SYNTHETIC_AWS_KEY not in console_out
    assert SYNTHETIC_AWS_KEY not in json_out


def test_aws_secret_key_requires_context(tmp_path):
    """Verify AWS Secret Key requires variable context and does not match arbitrary strings."""
    valid_file = tmp_path / "valid_secret.env"
    valid_file.write_text(f"AWS_SECRET_ACCESS_KEY='{SYNTHETIC_AWS_SECRET}'\n")

    arbitrary_file = tmp_path / "arbitrary.txt"
    arbitrary_file.write_text("This is an arbitrary 40 char string: 1234567890123456789012345678901234567890\n")

    scanner = SecretScanner()

    # Valid context
    t1 = Target(path=valid_file, is_directory=False, is_file=True, is_git_repo=False, file_count=1, total_size_bytes=100)
    findings1 = scanner.scan(t1)
    assert len(findings1) == 1
    assert findings1[0].rule_id == "SECRET-AWS-SECRET-KEY"
    assert SYNTHETIC_AWS_SECRET not in str(findings1[0].to_dict())

    # Arbitrary context -> should not match
    t2 = Target(path=arbitrary_file, is_directory=False, is_file=True, is_git_repo=False, file_count=1, total_size_bytes=100)
    findings2 = scanner.scan(t2)
    assert len(findings2) == 0


def test_private_key_safety(tmp_path):
    """Verify Private Key PEM detection replaces raw key with fixed masked string."""
    key_file = tmp_path / "id_rsa"
    key_file.write_text(SYNTHETIC_PEM)

    scanner = SecretScanner()
    target = Target(path=key_file, is_directory=False, is_file=True, is_git_repo=False, file_count=1, total_size_bytes=100)

    findings = scanner.scan(target)
    assert len(findings) == 1
    f = findings[0]

    assert f.rule_id == "SECRET-PRIVATE-KEY"
    assert f.metadata["masked_value"] == "[PRIVATE KEY REDACTED]"

    # Ensure no raw PEM lines leak
    assert "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC3x" not in str(f.to_dict())
    assert "BEGIN PRIVATE KEY" not in f.description


def test_github_token_and_jwt_detection(tmp_path):
    """Verify GitHub PAT and JWT token detection."""
    code_file = tmp_path / "tokens.py"
    code_file.write_text(
        f"gh_pat = '{SYNTHETIC_GITHUB_PAT}'\n"
        f"jwt_token = '{SYNTHETIC_JWT}'\n"
    )

    scanner = SecretScanner()
    target = Target(path=code_file, is_directory=False, is_file=True, is_git_repo=False, file_count=1, total_size_bytes=200)

    findings = scanner.scan(target)
    rule_ids = {f.rule_id for f in findings}

    assert "SECRET-GITHUB-TOKEN" in rule_ids
    assert "SECRET-JWT" in rule_ids

    assert SYNTHETIC_GITHUB_PAT not in str([f.to_dict() for f in findings])
    assert SYNTHETIC_JWT not in str([f.to_dict() for f in findings])


def test_database_url_credential_masking(tmp_path):
    """Verify DB URL password is completely stripped and replaced with [REDACTED]."""
    db_file = tmp_path / "config.yaml"
    db_file.write_text(f"database_url: \"{SYNTHETIC_DB_URL}\"\n")

    scanner = SecretScanner()
    target = Target(path=db_file, is_directory=False, is_file=True, is_git_repo=False, file_count=1, total_size_bytes=100)

    findings = scanner.scan(target)
    assert len(findings) == 1
    f = findings[0]

    assert f.rule_id == "SECRET-DATABASE-CREDENTIAL"
    assert "[REDACTED]" in f.metadata["masked_value"]
    assert SYNTHETIC_DB_PASS not in f.metadata["masked_value"]
    assert SYNTHETIC_DB_PASS not in str(f.to_dict())


def test_generic_secret_detection_and_placeholder_negative(tmp_path):
    """Verify generic secret detection triggers on entropy and ignores common placeholders."""
    secret_file = tmp_path / "app_secrets.py"
    secret_file.write_text(
        f"API_KEY = '{SYNTHETIC_GENERIC_SECRET}'\n"
        "IGNORE_KEY_1 = 'your_api_key_here'\n"
        "IGNORE_KEY_2 = '12345678'\n"
        "IGNORE_KEY_3 = 'placeholder'\n"
    )

    scanner = SecretScanner()
    target = Target(path=secret_file, is_directory=False, is_file=True, is_git_repo=False, file_count=1, total_size_bytes=100)

    findings = scanner.scan(target)
    assert len(findings) == 1
    f = findings[0]

    assert f.rule_id == "SECRET-GENERIC"
    assert SYNTHETIC_GENERIC_SECRET not in str(f.to_dict())


def test_filesystem_safety_binary_and_large_files(tmp_path):
    """Verify binary files, large files, and unreadable files are safely skipped."""
    # Binary file
    bin_file = tmp_path / "sample.bin"
    bin_file.write_bytes(b"\x00\x01\x02\x03" + SYNTHETIC_AWS_KEY.encode())

    # Large file simulation (> 5 MB)
    large_file = tmp_path / "large.txt"
    with open(large_file, "wb") as f:
        f.seek(6 * 1024 * 1024)
        f.write(b"end")

    scanner = SecretScanner()

    # Scan binary file -> 0 findings
    t_bin = Target(path=bin_file, is_directory=False, is_file=True, is_git_repo=False, file_count=1, total_size_bytes=100)
    assert len(scanner.scan(t_bin)) == 0

    # Scan large file -> 0 findings
    t_large = Target(path=large_file, is_directory=False, is_file=True, is_git_repo=False, file_count=1, total_size_bytes=6 * 1024 * 1024)
    assert len(scanner.scan(t_large)) == 0


def test_detector_isolation(tmp_path, monkeypatch):
    """Verify failure in one detector function does not abort other detectors or the overall scanner."""
    test_file = tmp_path / "mixed.py"
    test_file.write_text(
        f"AWS_KEY_ID = '{SYNTHETIC_AWS_KEY}'\n"
        f"gh_pat = '{SYNTHETIC_GITHUB_PAT}'\n"
    )

    scanner = SecretScanner()

    # Monkeypatch AWS access key detector to raise an exception
    def broken_detector(line, line_num, fpath, findings):
        raise RuntimeError("Simulated detector fault")

    monkeypatch.setattr(scanner, "_detect_aws_access_key", broken_detector)

    target = Target(path=test_file, is_directory=False, is_file=True, is_git_repo=False, file_count=1, total_size_bytes=100)
    findings = scanner.scan(target)

    # AWS detector failed, but GitHub token detector ran successfully!
    assert len(findings) == 1
    assert findings[0].rule_id == "SECRET-GITHUB-TOKEN"
