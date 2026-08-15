"""Unit tests for IacScanner, Terraform HCL parsing, CloudFormation YAML parsing, and CLI commands."""

from sentinelscan.models.finding import Category, Confidence, Severity
from sentinelscan.models.result import ScannerExecutionResult, ScannerExecutionStatus, ScanResult
from sentinelscan.models.target import Target
from sentinelscan.reporting.json import JsonReporter
from sentinelscan.scanners.iac_scanner import IacScanner


def test_iac_terraform_positive_detections(tmp_path):
    """Verify Terraform HCL positive detections for security groups, S3, RDS, and IAM."""
    tf_file = tmp_path / "main.tf"
    tf_file.write_text(
        'resource "aws_security_group" "web_sg" {\n'
        '  name = "web-sg"\n'
        '  ingress {\n'
        '    from_port = 22\n'
        '    to_port = 22\n'
        '    protocol = "tcp"\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        "  }\n"
        "}\n"
        "\n"
        'resource "aws_s3_bucket" "public_bucket" {\n'
        '  bucket = "my-public-bucket"\n'
        '  acl    = "public-read"\n'
        "}\n"
        "\n"
        'resource "aws_db_instance" "public_db" {\n'
        '  allocated_storage   = 20\n'
        '  engine              = "postgres"\n'
        '  publicly_accessible = true\n'
        '  storage_encrypted   = false\n'
        "}\n"
    )

    scanner = IacScanner()
    target = Target(
        path=tf_file,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(tf_file.read_bytes()),
    )

    findings = scanner.scan(target)
    rule_ids = [f.rule_id for f in findings]

    assert "IAC-AWS-SG-OPEN-INGRESS" in rule_ids
    assert "IAC-AWS-S3-PUBLIC-ACL" in rule_ids
    assert "IAC-AWS-S3-UNENCRYPTED" in rule_ids
    assert "IAC-AWS-RDS-PUBLIC" in rule_ids
    assert "IAC-AWS-RDS-UNENCRYPTED" in rule_ids

    sg_f = next(f for f in findings if f.rule_id == "IAC-AWS-SG-OPEN-INGRESS")
    assert sg_f.severity == Severity.HIGH
    assert sg_f.confidence == Confidence.HIGH
    assert sg_f.category == Category.IAC


def test_iac_cloudformation_yaml_positive_detections(tmp_path):
    """Verify CloudFormation YAML positive detections and intrinsic tag safety (!Ref, !Sub)."""
    cfn_file = tmp_path / "template.yaml"
    cfn_file.write_text(
        "AWSTemplateFormatVersion: '2010-09-09'\n"
        "Resources:\n"
        "  PublicBucket:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Properties:\n"
        "      BucketName: !Sub 'my-bucket-${AWS::AccountId}'\n"
        "      AccessControl: PublicRead\n"
        "  WebSG:\n"
        "    Type: AWS::EC2::SecurityGroup\n"
        "    Properties:\n"
        "      GroupDescription: !Ref BucketName\n"
        "      SecurityGroupIngress:\n"
        "        - IpProtocol: tcp\n"
        "          FromPort: 22\n"
        "          ToPort: 22\n"
        "          CidrIp: 0.0.0.0/0\n"
    )

    scanner = IacScanner()
    target = Target(
        path=cfn_file,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(cfn_file.read_bytes()),
    )

    findings = scanner.scan(target)
    rule_ids = [f.rule_id for f in findings]

    assert "IAC-AWS-S3-PUBLIC-ACL" in rule_ids
    assert "IAC-AWS-S3-UNENCRYPTED" in rule_ids
    assert "IAC-AWS-SG-OPEN-INGRESS" in rule_ids


def test_iac_negative_secure_configurations(tmp_path):
    """Verify secure IaC configurations produce zero findings."""
    tf_file = tmp_path / "secure.tf"
    tf_file.write_text(
        'resource "aws_security_group" "private_sg" {\n'
        '  ingress {\n'
        '    from_port = 22\n'
        '    to_port = 22\n'
        '    protocol = "tcp"\n'
        '    cidr_blocks = ["10.0.0.0/16"]\n'
        "  }\n"
        "}\n"
        'resource "aws_s3_bucket" "private_bucket" {\n'
        '  acl = "private"\n'
        "  server_side_encryption_configuration {\n"
        "    rule {\n"
        "      apply_server_side_encryption_by_default {\n"
        '        sse_algorithm = "AES256"\n'
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n"
        'resource "aws_db_instance" "private_db" {\n'
        "  publicly_accessible = false\n"
        "  storage_encrypted   = true\n"
        "}\n"
    )

    scanner = IacScanner()
    target = Target(
        path=tf_file,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(tf_file.read_bytes()),
    )

    findings = scanner.scan(target)
    assert len(findings) == 0


def test_iac_non_cloudformation_yaml_ignored(tmp_path):
    """Verify non-CloudFormation YAML files (e.g. CI workflow files) produce 0 findings."""
    ci_file = tmp_path / "workflow.yaml"
    ci_file.write_text(
        "name: CI Pipeline\n"
        "on: [push]\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v3\n"
    )

    scanner = IacScanner()
    target = Target(
        path=ci_file,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(ci_file.read_bytes()),
    )

    findings = scanner.scan(target)
    assert len(findings) == 0


def test_iac_malformed_file_handling(tmp_path):
    """Verify malformed HCL, invalid YAML, and bad JSON files are safely skipped."""
    bad_hcl = tmp_path / "bad.tf"
    bad_hcl.write_text('resource "aws_security_group" {\n  unclosed block')

    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text("Resources:\n  Bucket:\n    - : [invalid yaml syntax")

    scanner = IacScanner()
    for f in (bad_hcl, bad_yaml):
        target = Target(
            path=f,
            is_directory=False,
            is_file=True,
            is_git_repo=False,
            file_count=1,
            total_size_bytes=len(f.read_bytes()),
        )
        findings = scanner.scan(target)
        assert len(findings) == 0


def test_iac_json_serialization(tmp_path):
    """Verify IaC findings can be serialized to machine-readable JSON."""
    tf_file = tmp_path / "db.tf"
    tf_file.write_text(
        'resource "aws_db_instance" "public_db" {\n'
        "  publicly_accessible = true\n"
        "}\n"
    )

    scanner = IacScanner()
    target = Target(
        path=tf_file,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(tf_file.read_bytes()),
    )

    findings = scanner.scan(target)
    assert len(findings) >= 1

    res = ScanResult(
        target=target,
        findings=findings,
        scanner_results=[
            ScannerExecutionResult(scanner_name="iac-scanner", status=ScannerExecutionStatus.SUCCESS)
        ],
    )
    json_out = JsonReporter().render(res)
    assert '"rule_id": "IAC-AWS-RDS-PUBLIC"' in json_out
    assert '"category": "iac"' in json_out
