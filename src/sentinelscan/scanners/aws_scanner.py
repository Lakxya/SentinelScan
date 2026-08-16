"""AWS Security Posture Scanner analyzing static IAM policies, resource policies, and local AWS configuration."""

import configparser
import json
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from sentinelscan.models.finding import Category, Confidence, Finding, Location, Severity
from sentinelscan.models.target import Target
from sentinelscan.scanners.base import BaseScanner
from sentinelscan.scanners.secret_scanner import mask_token

logger = logging.getLogger("sentinelscan.scanners.aws_scanner")

# Maximum file size to scan (5 MB)
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024

# Directories ignored during recursive filesystem traversal
EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "build",
    "dist",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".sentinelscan",
}

# Sensitive data reading or decryption actions
SENSITIVE_ACTIONS = {
    "s3:getobject",
    "kms:decrypt",
    "secretsmanager:getsecretvalue",
    "ssm:getparameter",
    "ssm:getparameters",
    "ssm:getparametersbypath",
    "dynamodb:getitem",
    "dynamodb:batchgetitem",
}

# Sensitive KMS actions
KMS_CRYPTO_ACTIONS = {
    "kms:decrypt",
    "kms:generatedatakey",
    "kms:generatedatakeypair",
    "kms:reencrypt",
    "kms:reencryptfrom",
    "kms:reencryptto",
    "kms:*",
}

# AWS Access Key ID regex pattern
AWS_KEY_ID_PATTERN = re.compile(r"^AKIA[0-9A-Z]{16}$")


@dataclass
class AwsPolicyResource:
    """Dataclass representing a parsed AWS policy document or config file."""

    resource_type: str  # "IAM_POLICY", "S3_POLICY", "KMS_POLICY", "AWS_CREDENTIALS", "AWS_CONFIG"
    name: str
    statements: list[dict[str, Any]]
    raw_data: dict[str, Any] | configparser.ConfigParser
    fpath: Path
    start_line: int


class AwsPolicyParser:
    """Parser for AWS IAM policies, S3/KMS resource policies, and local AWS configuration files."""

    @staticmethod
    def parse_file(fpath: Path) -> list[AwsPolicyResource]:
        resources: list[AwsPolicyResource] = []
        fname_lower = fpath.name.lower()

        # Handle local .aws/credentials or .aws/config or aws-config.ini
        if fname_lower in ("credentials", "config", "aws-config.ini") or fpath.parent.name == ".aws":
            config_res = AwsPolicyParser._parse_aws_config_file(fpath)
            if config_res:
                resources.append(config_res)
            return resources

        # Read JSON/YAML content
        try:
            with open(fpath, "r", encoding="utf-8", errors="strict") as f:
                content = f.read()
        except Exception as e:  # noqa: BLE001
            logger.debug("Failed to read file %s: %s", fpath, e)
            return resources

        if not content.strip():
            return resources

        # Try parsing JSON first, then YAML
        doc = None
        try:
            doc = json.loads(content)
        except Exception:  # noqa: BLE001
            try:
                doc = yaml.safe_load(content)
            except Exception:  # noqa: BLE001
                doc = None

        if not isinstance(doc, dict):
            return resources

        # Validate IAM / Resource Policy structure (Must contain Version and Statement)
        version = doc.get("Version")
        statement_node = doc.get("Statement")

        if not version or statement_node is None:
            return resources

        version_str = str(version).strip()
        if version_str not in ("2012-10-17", "2008-10-17"):
            return resources

        statements: list[dict[str, Any]] = []
        if isinstance(statement_node, dict):
            statements.append(statement_node)
        elif isinstance(statement_node, list):
            statements.extend([s for s in statement_node if isinstance(s, dict)])

        res_type = "IAM_POLICY"
        if "s3:" in content.lower() or "arn:aws:s3:::" in content.lower():
            res_type = "S3_POLICY"
        elif "kms:" in content.lower() or "kms:decrypt" in content.lower():
            res_type = "KMS_POLICY"

        resources.append(
            AwsPolicyResource(
                resource_type=res_type,
                name=fpath.name,
                statements=statements,
                raw_data=doc,
                fpath=fpath,
                start_line=1,
            )
        )

        return resources

    @staticmethod
    def _parse_aws_config_file(fpath: Path) -> AwsPolicyResource | None:
        try:
            config = configparser.ConfigParser()
            config.read(fpath, encoding="utf-8")

            res_type = "AWS_CREDENTIALS" if "credentials" in fpath.name.lower() else "AWS_CONFIG"
            return AwsPolicyResource(
                resource_type=res_type,
                name=fpath.name,
                statements=[],
                raw_data=config,
                fpath=fpath,
                start_line=1,
            )
        except Exception as e:  # noqa: BLE001
            logger.debug("Failed to parse INI config file %s: %s", fpath, e)
            return None


class AwsScanner(BaseScanner):
    """AWS security posture scanner analyzing static IAM policies, resource policies, and local AWS configuration."""

    @property
    def name(self) -> str:
        return "aws-scanner"

    @property
    def category(self) -> Category:
        return Category.CLOUD

    @property
    def description(self) -> str:
        return "AWS security posture scanner analyzing static IAM policies, resource policies, and local AWS configuration."

    def is_available(self, target: Target) -> bool:
        return True

    def scan(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        if target.is_file:
            self._scan_aws_file(target.path, findings)
            return findings

        for root, dirs, files in os.walk(target.path, topdown=True, followlinks=False):
            dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
            root_path = Path(root)

            for fname in files:
                fpath = root_path / fname

                if fpath.is_symlink():
                    try:
                        resolved = fpath.resolve()
                        if not resolved.exists() or not str(resolved).startswith(str(target.path)):
                            continue
                    except OSError:
                        continue

                ext = fpath.suffix.lower()
                fname_lower = fname.lower()
                if ext in (".json", ".yaml", ".yml") or fname_lower in ("credentials", "config", "aws-config.ini") or fpath.parent.name == ".aws":
                    self._scan_aws_file(fpath, findings)

        return findings

    def _scan_aws_file(self, fpath: Path, findings: list[Finding]) -> None:
        try:
            stat = fpath.stat()
            if stat.st_size > MAX_FILE_SIZE_BYTES:
                return

            with open(fpath, "rb") as f:
                header = f.read(1024)
                if b"\x00" in header:
                    return
        except (OSError, PermissionError):
            return

        resources = AwsPolicyParser.parse_file(fpath)
        for res in resources:
            if res.resource_type in ("AWS_CREDENTIALS", "AWS_CONFIG"):
                self._evaluate_local_aws_config(res, findings)
            else:
                self._evaluate_policy_statements(res, findings)

    def _evaluate_policy_statements(self, res: AwsPolicyResource, findings: list[Finding]) -> None:
        for idx, stmt in enumerate(res.statements, start=1):
            effect = str(stmt.get("Effect", "")).strip()

            # Explicit Effect: Deny statements must NEVER generate allow-based wildcard findings
            if effect != "Allow":
                continue

            actions = self._normalize_list_or_str(stmt.get("Action"))
            resources = self._normalize_list_or_str(stmt.get("Resource"))
            principal = stmt.get("Principal")
            condition = stmt.get("Condition")

            # 1. AWS-IAM-WILDCARD-ACTION
            if "*" in actions:
                findings.append(
                    Finding(
                        scanner="aws-scanner",
                        category=Category.CLOUD,
                        rule_id="AWS-IAM-WILDCARD-ACTION",
                        title=f"IAM Policy Grants Full Wildcard Action in {res.name}",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        description=f"IAM policy statement #{idx} in '{res.name}' grants Effect: Allow with Action: '*'.",
                        impact="Full wildcard action grants unrestricted administrative access across all AWS service APIs.",
                        remediation="Restrict Action permissions to specific required API calls (e.g. s3:GetObject).",
                        location=Location(file_path=res.fpath, start_line=res.start_line),
                        resource_id=f"{res.name}:Statement[{idx}]",
                    )
                )

            # 2. AWS-IAM-WILDCARD-RESOURCE
            if "*" in resources or "arn:aws:s3:::*" in resources:
                has_sensitive_action = any(act.lower() in SENSITIVE_ACTIONS for act in actions)
                if has_sensitive_action:
                    findings.append(
                        Finding(
                            scanner="aws-scanner",
                            category=Category.CLOUD,
                            rule_id="AWS-IAM-WILDCARD-RESOURCE",
                            title=f"Sensitive Action Granted on Wildcard Resource in {res.name}",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            description=f"IAM statement #{idx} grants sensitive data access actions on Resource: '*'.",
                            impact="Allows reading sensitive data or secrets across all current and future cloud resources.",
                            remediation="Scope Resource ARNs to specific resource instances (e.g. arn:aws:s3:::my-bucket/*).",
                            location=Location(file_path=res.fpath, start_line=res.start_line),
                            resource_id=f"{res.name}:Statement[{idx}]",
                        )
                    )

            # 3. AWS-IAM-PASSROLE-WILDCARD
            has_passrole = any(act.lower() == "iam:passrole" for act in actions)
            if has_passrole and ("*" in resources or "arn:aws:iam::*:role/*" in resources):
                findings.append(
                    Finding(
                        scanner="aws-scanner",
                        category=Category.CLOUD,
                        rule_id="AWS-IAM-PASSROLE-WILDCARD",
                        title=f"iam:PassRole Granted on Wildcard Resource in {res.name}",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description=f"IAM statement #{idx} grants Action: 'iam:PassRole' on Resource: '*'.",
                        impact="Allows an attacker to pass high-privilege service roles to EC2/Lambda instances, enabling privilege escalation.",
                        remediation="Restrict iam:PassRole to specific required service role ARNs.",
                        location=Location(file_path=res.fpath, start_line=res.start_line),
                        resource_id=f"{res.name}:Statement[{idx}]",
                    )
                )

            # 4. AWS-S3-PUBLIC-POLICY & AWS-S3-UNENCRYPTED-POLICY
            if res.resource_type == "S3_POLICY" or any(a.lower().startswith("s3:") for a in actions):
                # Public principal check
                if self._is_wildcard_principal(principal):
                    has_condition = isinstance(condition, dict) and len(condition) > 0
                    sev = Severity.MEDIUM if has_condition else Severity.CRITICAL
                    conf = Confidence.MEDIUM if has_condition else Confidence.HIGH
                    desc_extra = " Statement includes Condition restrictions." if has_condition else ""

                    findings.append(
                        Finding(
                            scanner="aws-scanner",
                            category=Category.CLOUD,
                            rule_id="AWS-S3-PUBLIC-POLICY",
                            title=f"S3 Policy Allows Public Access in {res.name}",
                            severity=sev,
                            confidence=conf,
                            description=f"S3 policy statement #{idx} allows Principal: '*'.{desc_extra}",
                            impact="Exposes S3 bucket contents publicly to unauthenticated internet users.",
                            remediation="Remove wildcard Principal or enforce StringEquals conditions (e.g. aws:PrincipalOrgID).",
                            location=Location(file_path=res.fpath, start_line=res.start_line),
                            resource_id=f"{res.name}:Statement[{idx}]",
                        )
                    )

                # Unencrypted transport check
                if self._lacks_secure_transport(stmt):
                    findings.append(
                        Finding(
                            scanner="aws-scanner",
                            category=Category.CLOUD,
                            rule_id="AWS-S3-UNENCRYPTED-POLICY",
                            title=f"S3 Policy Lacks SSL Transport Enforcement in {res.name}",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            description=f"S3 policy statement #{idx} does not enforce aws:SecureTransport SSL condition.",
                            impact="Transmitting S3 data over unencrypted HTTP exposes data to network interception and tampering.",
                            remediation="Enforce aws:SecureTransport: true condition on S3 bucket policy statements.",
                            location=Location(file_path=res.fpath, start_line=res.start_line),
                            resource_id=f"{res.name}:Statement[{idx}]",
                        )
                    )

            # 5. AWS-KMS-WILDCARD-PRINCIPAL
            if (res.resource_type == "KMS_POLICY" or any(a.lower().startswith("kms:") for a in actions)) and self._is_wildcard_principal(principal):
                has_kms_crypto = any(act.lower() in KMS_CRYPTO_ACTIONS for act in actions)
                if has_kms_crypto:
                    findings.append(
                        Finding(
                            scanner="aws-scanner",
                            category=Category.CLOUD,
                            rule_id="AWS-KMS-WILDCARD-PRINCIPAL",
                            title=f"KMS Key Policy Allows Anonymous Principal in {res.name}",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            description=f"KMS key policy statement #{idx} grants cryptographic actions to Principal: '*'.",
                            impact="Exposes customer master keys (CMKs) to public decryption or cryptographic manipulation.",
                            remediation="Restrict KMS key policy principals to trusted IAM roles or AWS account IDs.",
                            location=Location(file_path=res.fpath, start_line=res.start_line),
                            resource_id=f"{res.name}:Statement[{idx}]",
                        )
                    )

    def _evaluate_local_aws_config(self, res: AwsPolicyResource, findings: list[Finding]) -> None:
        if not isinstance(res.raw_data, configparser.ConfigParser):
            return

        config = res.raw_data
        for section in config.sections():
            # 1. AWS-LOCAL-PLAINTEXT-CREDENTIALS
            if config.has_option(section, "aws_secret_access_key"):
                secret_key = config.get(section, "aws_secret_access_key", fallback="")
                key_id = config.get(section, "aws_access_key_id", fallback="")
                if secret_key and not secret_key.startswith(("${", "CHANGE", "YOUR")):
                    masked_secret = mask_token(secret_key)
                    masked_id = mask_token(key_id) if key_id else "STATIC_KEY"
                    findings.append(
                        Finding(
                            scanner="aws-scanner",
                            category=Category.CLOUD,
                            rule_id="AWS-LOCAL-PLAINTEXT-CREDENTIALS",
                            title=f"Long-Term AWS Credentials in Local File [{section}]",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            description=f"Local file '{res.name}' section [{section}] stores static access key ID '{masked_id}' with secret key '{masked_secret}'.",
                            impact="Long-term access keys stored on disk are vulnerable to malware and repository leakage.",
                            remediation="Use temporary IAM role credentials (aws sso login or AWS IAM Identity Center).",
                            location=Location(file_path=res.fpath, start_line=res.start_line),
                            resource_id=f"{res.name}:[{section}]",
                            metadata={"profile": section, "masked_key_id": masked_id, "masked_secret": masked_secret},
                        )
                    )

            # 2. AWS-LOCAL-CONFIG-NO-MFA
            # Elevated profiles contain role_arn or source_profile used to assume elevated roles
            is_elevated_profile = config.has_option(section, "role_arn") or config.has_option(section, "source_profile")
            has_mfa = config.has_option(section, "mfa_serial")
            if is_elevated_profile and not has_mfa:
                findings.append(
                    Finding(
                        scanner="aws-scanner",
                        category=Category.CLOUD,
                        rule_id="AWS-LOCAL-CONFIG-NO-MFA",
                        title=f"Elevated AWS Profile Lacks MFA Requirement [{section}]",
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        description=f"Local config profile [{section}] assumes a role (role_arn) without declaring mfa_serial.",
                        impact="Assuming privileged IAM roles without multi-factor authentication increases account takeover risk.",
                        remediation="Add mfa_serial = arn:aws:iam::<account>:mfa/<user> to elevated config profiles.",
                        location=Location(file_path=res.fpath, start_line=res.start_line),
                        resource_id=f"{res.name}:[{section}]",
                        metadata={"profile": section},
                    )
                )

    def _normalize_list_or_str(self, val: Any) -> list[str]:
        if isinstance(val, str):
            return [val]
        if isinstance(val, list):
            return [str(item) for item in val]
        return []

    def _is_wildcard_principal(self, principal: Any) -> bool:
        if principal == "*":
            return True
        if isinstance(principal, dict):
            aws_p = principal.get("AWS")
            if aws_p == "*" or (isinstance(aws_p, list) and "*" in aws_p):
                return True
        return False

    def _lacks_secure_transport(self, stmt: dict[str, Any]) -> bool:
        condition = stmt.get("Condition")
        if not isinstance(condition, dict):
            return True

        # Check for Bool condition matching aws:SecureTransport: false or missing true
        bool_cond = condition.get("Bool", {})
        if isinstance(bool_cond, dict):
            sec_transport = bool_cond.get("aws:SecureTransport")
            if str(sec_transport).lower() == "false":
                return True
            if str(sec_transport).lower() == "true":
                return False

        return True
