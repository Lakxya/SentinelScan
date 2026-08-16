"""Unit tests for AwsScanner, AwsPolicyParser, AWS security rules, and CLI integration."""

from sentinelscan.models.finding import Category, Confidence, Severity
from sentinelscan.models.result import ScannerExecutionResult, ScannerExecutionStatus, ScanResult
from sentinelscan.models.target import Target
from sentinelscan.reporting.json import JsonReporter
from sentinelscan.scanners.aws_scanner import AwsPolicyParser, AwsScanner


def test_aws_policy_parser_statement_object_and_list(tmp_path):
    """Verify AwsPolicyParser parses IAM policies with Statement declared as object or list."""
    policy_obj = tmp_path / "policy-obj.json"
    policy_obj.write_text(
        '{\n'
        '  "Version": "2012-10-17",\n'
        '  "Statement": {\n'
        '    "Effect": "Allow",\n'
        '    "Action": "s3:ListBucket",\n'
        '    "Resource": "arn:aws:s3:::my-bucket"\n'
        '  }\n'
        '}\n'
    )

    policy_list = tmp_path / "policy-list.json"
    policy_list.write_text(
        '{\n'
        '  "Version": "2012-10-17",\n'
        '  "Statement": [\n'
        '    {\n'
        '      "Effect": "Allow",\n'
        '      "Action": "s3:GetObject",\n'
        '      "Resource": "*"\n'
        '    }\n'
        '  ]\n'
        '}\n'
    )

    res1 = AwsPolicyParser.parse_file(policy_obj)
    assert len(res1) == 1
    assert len(res1[0].statements) == 1

    res2 = AwsPolicyParser.parse_file(policy_list)
    assert len(res2) == 1
    assert len(res2[0].statements) == 1


def test_aws_positive_security_detections(tmp_path):
    """Verify AwsScanner positive detections for wildcard action, wildcard resource, and passrole wildcard."""
    policy = tmp_path / "iam-insecure.json"
    policy.write_text(
        '{\n'
        '  "Version": "2012-10-17",\n'
        '  "Statement": [\n'
        '    {\n'
        '      "Effect": "Allow",\n'
        '      "Action": "*",\n'
        '      "Resource": "*"\n'
        '    },\n'
        '    {\n'
        '      "Effect": "Allow",\n'
        '      "Action": "s3:GetObject",\n'
        '      "Resource": "*"\n'
        '    },\n'
        '    {\n'
        '      "Effect": "Allow",\n'
        '      "Action": "iam:PassRole",\n'
        '      "Resource": "*"\n'
        '    }\n'
        '  ]\n'
        '}\n'
    )

    scanner = AwsScanner()
    target = Target(
        path=policy,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(policy.read_bytes()),
    )

    findings = scanner.scan(target)
    rule_ids = [f.rule_id for f in findings]

    assert "AWS-IAM-WILDCARD-ACTION" in rule_ids
    assert "AWS-IAM-WILDCARD-RESOURCE" in rule_ids
    assert "AWS-IAM-PASSROLE-WILDCARD" in rule_ids

    wildcard_act = next(f for f in findings if f.rule_id == "AWS-IAM-WILDCARD-ACTION")
    assert wildcard_act.severity == Severity.CRITICAL
    assert wildcard_act.confidence == Confidence.HIGH
    assert wildcard_act.category == Category.CLOUD


def test_aws_s3_public_policy_and_unencrypted_transport(tmp_path):
    """Verify S3 public policy and unencrypted transport detections."""
    s3_policy = tmp_path / "s3-policy.json"
    s3_policy.write_text(
        '{\n'
        '  "Version": "2012-10-17",\n'
        '  "Statement": [\n'
        '    {\n'
        '      "Effect": "Allow",\n'
        '      "Principal": "*",\n'
        '      "Action": "s3:GetObject",\n'
        '      "Resource": "arn:aws:s3:::my-public-bucket/*"\n'
        '    }\n'
        '  ]\n'
        '}\n'
    )

    scanner = AwsScanner()
    target = Target(
        path=s3_policy,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(s3_policy.read_bytes()),
    )

    findings = scanner.scan(target)
    rule_ids = [f.rule_id for f in findings]

    assert "AWS-S3-PUBLIC-POLICY" in rule_ids
    assert "AWS-S3-UNENCRYPTED-POLICY" in rule_ids

    public_finding = next(f for f in findings if f.rule_id == "AWS-S3-PUBLIC-POLICY")
    assert public_finding.severity == Severity.CRITICAL
    assert public_finding.confidence == Confidence.HIGH


def test_aws_s3_public_policy_restrictive_condition(tmp_path):
    """Verify restrictive conditions reduce Severity and Confidence to MEDIUM."""
    s3_policy = tmp_path / "s3-cond.json"
    s3_policy.write_text(
        '{\n'
        '  "Version": "2012-10-17",\n'
        '  "Statement": [\n'
        '    {\n'
        '      "Effect": "Allow",\n'
        '      "Principal": "*",\n'
        '      "Action": "s3:GetObject",\n'
        '      "Resource": "arn:aws:s3:::org-bucket/*",\n'
        '      "Condition": {\n'
        '        "StringEquals": {\n'
        '          "aws:PrincipalOrgID": "o-123456789"\n'
        '        }\n'
        '      }\n'
        '    }\n'
        '  ]\n'
        '}\n'
    )

    scanner = AwsScanner()
    target = Target(
        path=s3_policy,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(s3_policy.read_bytes()),
    )

    findings = scanner.scan(target)
    public_finding = next(f for f in findings if f.rule_id == "AWS-S3-PUBLIC-POLICY")
    assert public_finding.severity == Severity.MEDIUM
    assert public_finding.confidence == Confidence.MEDIUM


def test_aws_kms_wildcard_principal(tmp_path):
    """Verify KMS key policy with Principal: '*' is flagged."""
    kms_policy = tmp_path / "kms-policy.json"
    kms_policy.write_text(
        '{\n'
        '  "Version": "2012-10-17",\n'
        '  "Statement": [\n'
        '    {\n'
        '      "Effect": "Allow",\n'
        '      "Principal": "*",\n'
        '      "Action": "kms:Decrypt",\n'
        '      "Resource": "*"\n'
        '    }\n'
        '  ]\n'
        '}\n'
    )

    scanner = AwsScanner()
    target = Target(
        path=kms_policy,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(kms_policy.read_bytes()),
    )

    findings = scanner.scan(target)
    rule_ids = [f.rule_id for f in findings]
    assert "AWS-KMS-WILDCARD-PRINCIPAL" in rule_ids


def test_aws_negative_deny_statements(tmp_path):
    """Verify explicit Effect: Deny statements produce 0 allow-based wildcard findings."""
    deny_policy = tmp_path / "iam-deny.json"
    deny_policy.write_text(
        '{\n'
        '  "Version": "2012-10-17",\n'
        '  "Statement": [\n'
        '    {\n'
        '      "Effect": "Deny",\n'
        '      "Action": "*",\n'
        '      "Resource": "*"\n'
        '    }\n'
        '  ]\n'
        '}\n'
    )

    scanner = AwsScanner()
    target = Target(
        path=deny_policy,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(deny_policy.read_bytes()),
    )

    findings = scanner.scan(target)
    assert len(findings) == 0


def test_aws_local_credentials_and_config_masking(tmp_path):
    """Verify local .aws/credentials keys are masked and elevated config profiles flagged."""
    aws_dir = tmp_path / ".aws"
    aws_dir.mkdir()
    creds_file = aws_dir / "credentials"
    creds_file.write_text(
        "[default]\n"
        "aws_access_key_id = AKIA1234567890EXAMPLE\n"
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    )

    config_file = aws_dir / "config"
    config_file.write_text(
        "[profile prod]\n"
        "role_arn = arn:aws:iam::123456789012:role/ProdAdmin\n"
        "source_profile = default\n"
    )

    scanner = AwsScanner()
    target = Target(
        path=tmp_path,
        is_directory=True,
        is_file=False,
        is_git_repo=False,
        file_count=2,
        total_size_bytes=len(creds_file.read_bytes()) + len(config_file.read_bytes()),
    )

    findings = scanner.scan(target)

    cred_finding = next(f for f in findings if f.rule_id == "AWS-LOCAL-PLAINTEXT-CREDENTIALS")
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in cred_finding.description
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in str(cred_finding.metadata)

    mfa_finding = next(f for f in findings if f.rule_id == "AWS-LOCAL-CONFIG-NO-MFA")
    assert mfa_finding.severity == Severity.LOW


def test_aws_non_aws_json_and_yaml_ignored(tmp_path):
    """Verify non-AWS JSON files (package.json, tsconfig.json) are ignored safely."""
    pkg = tmp_path / "package.json"
    pkg.write_text('{\n  "name": "my-app",\n  "version": "1.0.0"\n}\n')

    scanner = AwsScanner()
    target = Target(
        path=pkg,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(pkg.read_bytes()),
    )

    findings = scanner.scan(target)
    assert len(findings) == 0


def test_aws_json_serialization(tmp_path):
    """Verify AWS findings serialize cleanly to structured JSON format."""
    policy = tmp_path / "iam.json"
    policy.write_text(
        '{\n'
        '  "Version": "2012-10-17",\n'
        '  "Statement": [{\n'
        '    "Effect": "Allow",\n'
        '    "Action": "*",\n'
        '    "Resource": "*"\n'
        '  }]\n'
        '}\n'
    )

    scanner = AwsScanner()
    target = Target(
        path=policy,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(policy.read_bytes()),
    )

    findings = scanner.scan(target)
    assert len(findings) >= 1

    res = ScanResult(
        target=target,
        findings=findings,
        scanner_results=[
            ScannerExecutionResult(scanner_name="aws-scanner", status=ScannerExecutionStatus.SUCCESS)
        ],
    )
    json_out = JsonReporter().render(res)
    assert '"category": "cloud"' in json_out
    assert '"rule_id": "AWS-IAM-WILDCARD-ACTION"' in json_out
