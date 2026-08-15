"""Infrastructure-as-Code (IaC) Security Scanner analyzing Terraform HCL, CloudFormation, and SAM templates."""

import json
import logging
import os
from pathlib import Path
from typing import Any

import hcl2  # type: ignore[import-untyped]
import yaml  # type: ignore[import-untyped]

from sentinelscan.models.finding import Category, Confidence, Finding, Location, Severity
from sentinelscan.models.target import Target
from sentinelscan.scanners.base import BaseScanner

logger = logging.getLogger("sentinelscan.scanners.iac_scanner")

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

# Sensitive network ports
SENSITIVE_PORTS = {22, 3389, 3306, 5432, 1433, 27017, 6379}


def _strip_quotes(val: Any) -> str:
    """Helper to strip surrounding double or single quotes from string values."""
    s = str(val).strip()
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        return s[1:-1]
    return s


class CloudFormationSafeLoader(yaml.SafeLoader):  # type: ignore[misc]
    """YAML SafeLoader inheriting from SafeLoader to handle CloudFormation intrinsic tags safely."""

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[str, Any]:
        mapping: dict[str, Any] = super().construct_mapping(node, deep=deep)
        mapping["__line__"] = node.start_mark.line + 1
        return mapping



def _cfn_tag_constructor(loader: Any, tag_suffix: str, node: Any) -> Any:
    """Safely transform CloudFormation intrinsic function tags into dictionary representations."""
    clean_tag = tag_suffix.lstrip("!")
    if clean_tag == "Ref":
        val = loader.construct_scalar(node) if isinstance(node, yaml.ScalarNode) else loader.construct_sequence(node)
        return {"Ref": val}
    elif clean_tag == "Sub":
        val = loader.construct_scalar(node) if isinstance(node, yaml.ScalarNode) else loader.construct_sequence(node)
        return {"Fn::Sub": val}
    elif clean_tag == "GetAtt":
        val = loader.construct_scalar(node) if isinstance(node, yaml.ScalarNode) else loader.construct_sequence(node)
        return {"Fn::GetAtt": val}
    elif clean_tag == "FindInMap":
        val = loader.construct_sequence(node)
        return {"Fn::FindInMap": val}
    elif clean_tag == "Join":
        val = loader.construct_sequence(node)
        return {"Fn::Join": val}
    elif clean_tag == "Select":
        val = loader.construct_sequence(node)
        return {"Fn::Select": val}
    elif clean_tag == "ImportValue":
        val = loader.construct_scalar(node) if isinstance(node, yaml.ScalarNode) else loader.construct_sequence(node)
        return {"Fn::ImportValue": val}
    elif clean_tag in ("Condition", "Equals", "And", "Or", "Not", "If"):
        val = loader.construct_scalar(node) if isinstance(node, yaml.ScalarNode) else loader.construct_sequence(node)
        return {f"Fn::{clean_tag}": val}

    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    elif isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    return None


# Register intrinsic tag multi-constructors
CloudFormationSafeLoader.add_multi_constructor("!", _cfn_tag_constructor)


def _find_tf_resource_line(fpath: Path, resource_type: str, resource_name: str) -> int:
    """Extract line number for a specific Terraform resource block from source text."""
    try:
        with open(fpath, "r", encoding="utf-8", errors="strict") as f:
            for idx, line in enumerate(f, start=1):
                clean = line.strip()
                if clean.startswith("resource") and f'"{resource_type}"' in clean and f'"{resource_name}"' in clean:
                    return idx
    except Exception as e:  # noqa: BLE001
        logger.debug("Failed line lookup for resource %s.%s: %s", resource_type, resource_name, e)
    return 1


class IacScanner(BaseScanner):
    """Infrastructure-as-Code (IaC) security scanner analyzing Terraform HCL, CloudFormation, and SAM templates."""

    @property
    def name(self) -> str:
        return "iac-scanner"

    @property
    def category(self) -> Category:
        return Category.IAC

    @property
    def description(self) -> str:
        return "Infrastructure-as-Code security scanner analyzing Terraform HCL, CloudFormation, and SAM templates locally."

    def is_available(self, target: Target) -> bool:
        return True

    def scan(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        if target.is_file:
            self._scan_file(target.path, findings)
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

                self._scan_file(fpath, findings)

        return findings

    def _scan_file(self, fpath: Path, findings: list[Finding]) -> None:
        """Inspect a single target file, delegating to Terraform or CloudFormation analyzer."""
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

        suffix = fpath.suffix.lower()
        if suffix == ".tf":
            self._scan_terraform_file(fpath, findings)
        elif suffix in (".yaml", ".yml", ".json"):
            self._scan_cloudformation_file(fpath, findings)

    def _scan_terraform_file(self, fpath: Path, findings: list[Finding]) -> None:
        """Parse Terraform file using python-hcl2 and analyze declared AWS security resources."""
        try:
            with open(fpath, "r", encoding="utf-8", errors="strict") as f:
                content = hcl2.load(f)
        except Exception as e:  # noqa: BLE001
            logger.debug("HCL parse error skipping file %s: %s", fpath, e)
            return

        if not isinstance(content, dict) or "resource" not in content:
            return

        resources_list = content.get("resource", [])
        if not isinstance(resources_list, list):
            return

        for res_block in resources_list:
            if not isinstance(res_block, dict):
                continue

            for raw_res_type, res_instances in res_block.items():
                res_type = _strip_quotes(raw_res_type)
                instances_list: list[dict[str, Any]] = []
                if isinstance(res_instances, list):
                    for inst in res_instances:
                        if isinstance(inst, dict):
                            instances_list.append(inst)
                elif isinstance(res_instances, dict):
                    instances_list.append(res_instances)

                for inst in instances_list:
                    for raw_res_name, config in inst.items():
                        res_name = _strip_quotes(raw_res_name)
                        if not isinstance(config, dict):
                            continue

                        line_num = _find_tf_resource_line(fpath, res_type, res_name)
                        self._analyze_tf_resource(fpath, res_type, res_name, config, line_num, findings)

    def _analyze_tf_resource(
        self,
        fpath: Path,
        res_type: str,
        res_name: str,
        config: dict[str, Any],
        line_num: int,
        findings: list[Finding],
    ) -> None:
        # 1. aws_security_group open ingress
        if res_type == "aws_security_group":
            ingress_list = config.get("ingress", [])
            if isinstance(ingress_list, dict):
                ingress_list = [ingress_list]

            for ing in ingress_list if isinstance(ingress_list, list) else []:
                if not isinstance(ing, dict):
                    continue

                cidrs = ing.get("cidr_blocks", [])
                ipv6_cidrs = ing.get("ipv6_cidr_blocks", [])
                from_port = ing.get("from_port")
                to_port = ing.get("to_port")
                protocol = _strip_quotes(ing.get("protocol", "")).lower()

                has_open_v4 = any("0.0.0.0/0" in _strip_quotes(c) for c in (cidrs if isinstance(cidrs, list) else [cidrs]))
                has_open_v6 = any("::/0" in _strip_quotes(c) for c in (ipv6_cidrs if isinstance(ipv6_cidrs, list) else [ipv6_cidrs]))

                if has_open_v4 or has_open_v6:
                    is_all_ports = protocol == "-1" or (from_port == 0 and to_port == 65535) or (from_port == 0 and to_port == 0)
                    is_sensitive_port = False
                    if from_port is not None and to_port is not None:
                        try:
                            fp, tp = int(from_port), int(to_port)
                            is_sensitive_port = any(p in range(fp, tp + 1) for p in SENSITIVE_PORTS)
                        except (ValueError, TypeError):
                            pass

                    if is_all_ports or is_sensitive_port:
                        findings.append(
                            Finding(
                                scanner="iac-scanner",
                                category=Category.IAC,
                                rule_id="IAC-AWS-SG-OPEN-INGRESS",
                                title="Security Group Open Ingress to World",
                                severity=Severity.HIGH,
                                confidence=Confidence.HIGH,
                                description=f"Security group '{res_name}' allows unrestricted ingress from 0.0.0.0/0 or ::/0 on sensitive or all ports.",
                                impact="Exposes infrastructure ports directly to internet scans and unauthorized remote access.",
                                remediation="Restrict security group ingress cidr_blocks to known internal corporate IP ranges or bastion hosts.",
                                location=Location(file_path=fpath, start_line=line_num, end_line=line_num),
                                resource_id=f"aws_security_group.{res_name}",
                                metadata={"resource": f"aws_security_group.{res_name}"},
                            )
                        )

        # 2. aws_s3_bucket public ACL & unencrypted
        elif res_type == "aws_s3_bucket":
            acl = _strip_quotes(config.get("acl", ""))
            if acl in ("public-read", "public-read-write"):
                findings.append(
                    Finding(
                        scanner="iac-scanner",
                        category=Category.IAC,
                        rule_id="IAC-AWS-S3-PUBLIC-ACL",
                        title="Public S3 Bucket ACL Configured",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description=f"S3 bucket '{res_name}' is configured with public ACL '{acl}'.",
                        impact="Exposes S3 bucket objects publicly to unauthenticated internet users.",
                        remediation="Set S3 bucket acl to 'private' and enable account-level S3 Block Public Access.",
                        location=Location(file_path=fpath, start_line=line_num, end_line=line_num),
                        resource_id=f"aws_s3_bucket.{res_name}",
                        metadata={"acl": acl},
                    )
                )

            if "server_side_encryption_configuration" not in config:
                findings.append(
                    Finding(
                        scanner="iac-scanner",
                        category=Category.IAC,
                        rule_id="IAC-AWS-S3-UNENCRYPTED",
                        title="Unencrypted S3 Bucket",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        description=f"S3 bucket '{res_name}' lacks explicit server-side encryption configuration.",
                        impact="Data stored at rest is not guaranteed to be encrypted using KMS or AES-256.",
                        remediation="Add server_side_encryption_configuration block with apply_server_side_encryption_by_default.",
                        location=Location(file_path=fpath, start_line=line_num, end_line=line_num),
                        resource_id=f"aws_s3_bucket.{res_name}",
                    )
                )

        # 3. aws_s3_bucket_public_access_block disabled
        elif res_type == "aws_s3_bucket_public_access_block":
            block_acls = config.get("block_public_acls", True)
            block_policy = config.get("block_public_policy", True)
            if block_acls is False or block_policy is False or str(block_acls).lower() == "false" or str(block_policy).lower() == "false":
                findings.append(
                    Finding(
                        scanner="iac-scanner",
                        category=Category.IAC,
                        rule_id="IAC-AWS-S3-PUBLIC-BLOCK-DISABLED",
                        title="S3 Public Access Block Disabled",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description=f"S3 Public Access Block '{res_name}' explicitly disables public access blocking flags.",
                        impact="Permits bucket policies or ACLs to expose data publicly.",
                        remediation="Set block_public_acls, block_public_policy, ignore_public_acls, and restrict_public_buckets to true.",
                        location=Location(file_path=fpath, start_line=line_num, end_line=line_num),
                        resource_id=f"aws_s3_bucket_public_access_block.{res_name}",
                    )
                )

        # 4. aws_db_instance public & unencrypted
        elif res_type == "aws_db_instance":
            publicly_accessible = config.get("publicly_accessible", False)
            if publicly_accessible is True or str(publicly_accessible).lower() == "true":
                findings.append(
                    Finding(
                        scanner="iac-scanner",
                        category=Category.IAC,
                        rule_id="IAC-AWS-RDS-PUBLIC",
                        title="Publicly Accessible Database Instance",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description=f"RDS DB Instance '{res_name}' is configured with publicly_accessible = true.",
                        impact="Exposes database instance on a public IP address to external connection attempts.",
                        remediation="Set publicly_accessible = false and deploy RDS instance into private database subnets.",
                        location=Location(file_path=fpath, start_line=line_num, end_line=line_num),
                        resource_id=f"aws_db_instance.{res_name}",
                    )
                )

            storage_encrypted = config.get("storage_encrypted", False)
            if storage_encrypted is False or str(storage_encrypted).lower() == "false":
                findings.append(
                    Finding(
                        scanner="iac-scanner",
                        category=Category.IAC,
                        rule_id="IAC-AWS-RDS-UNENCRYPTED",
                        title="Unencrypted RDS Database Storage",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        description=f"RDS DB Instance '{res_name}' does not have storage encryption enabled.",
                        impact="Database storage volume and snapshots are stored unencrypted at rest.",
                        remediation="Set storage_encrypted = true and specify kms_key_id.",
                        location=Location(file_path=fpath, start_line=line_num, end_line=line_num),
                        resource_id=f"aws_db_instance.{res_name}",
                    )
                )

        # 5. aws_iam_policy_document / aws_iam_policy wildcard
        elif res_type in ("aws_iam_policy_document", "aws_iam_policy"):
            self._check_iam_policy_obj(fpath, f"{res_type}.{res_name}", config, line_num, findings)

    def _scan_cloudformation_file(self, fpath: Path, findings: list[Finding]) -> None:
        """Parse CloudFormation / SAM YAML or JSON template and analyze resources."""
        data: Any = None
        try:
            with open(fpath, "r", encoding="utf-8", errors="strict") as f:
                if fpath.suffix.lower() == ".json":
                    data = json.load(f)
                else:
                    data = yaml.load(f, Loader=CloudFormationSafeLoader)
        except Exception as e:  # noqa: BLE001
            logger.debug("Parse error skipping CloudFormation file %s: %s", fpath, e)
            return

        if not isinstance(data, dict) or "Resources" not in data:
            return

        resources = data.get("Resources")
        if not isinstance(resources, dict):
            return

        for res_name, res_config in resources.items():
            if res_name == "__line__" or not isinstance(res_config, dict):
                continue

            res_type = res_config.get("Type", "")
            line_num = res_config.get("__line__", 1)
            props = res_config.get("Properties", {})
            if not isinstance(props, dict):
                props = {}

            self._analyze_cfn_resource(fpath, res_name, res_type, props, line_num, findings)

    def _analyze_cfn_resource(
        self,
        fpath: Path,
        res_name: str,
        res_type: str,
        props: dict[str, Any],
        line_num: int,
        findings: list[Finding],
    ) -> None:
        # 1. SecurityGroup ingress
        if res_type == "AWS::EC2::SecurityGroup":
            ingress_rules = props.get("SecurityGroupIngress", [])
            if isinstance(ingress_rules, dict):
                ingress_rules = [ingress_rules]

            for ing in ingress_rules if isinstance(ingress_rules, list) else []:
                if not isinstance(ing, dict):
                    continue

                cidr_ip = str(ing.get("CidrIp", ""))
                cidr_ipv6 = str(ing.get("CidrIpv6", ""))
                from_port = ing.get("FromPort")
                to_port = ing.get("ToPort")
                protocol = str(ing.get("IpProtocol", "")).lower()

                if cidr_ip == "0.0.0.0/0" or cidr_ipv6 == "::/0":
                    is_all_ports = protocol == "-1" or (from_port == 0 and to_port == 65535)
                    is_sensitive_port = False
                    if from_port is not None and to_port is not None:
                        try:
                            fp, tp = int(from_port), int(to_port)
                            is_sensitive_port = any(p in range(fp, tp + 1) for p in SENSITIVE_PORTS)
                        except (ValueError, TypeError):
                            pass

                    if is_all_ports or is_sensitive_port:
                        findings.append(
                            Finding(
                                scanner="iac-scanner",
                                category=Category.IAC,
                                rule_id="IAC-AWS-SG-OPEN-INGRESS",
                                title="Security Group Open Ingress to World",
                                severity=Severity.HIGH,
                                confidence=Confidence.HIGH,
                                description=f"CloudFormation Security Group '{res_name}' permits unrestricted ingress from {cidr_ip or cidr_ipv6}.",
                                impact="Exposes infrastructure ports directly to internet scans and unauthorized remote access.",
                                remediation="Restrict CidrIp / CidrIpv6 to internal corporate IP ranges.",
                                location=Location(file_path=fpath, start_line=line_num, end_line=line_num),
                                resource_id=f"AWS::EC2::SecurityGroup.{res_name}",
                            )
                        )

        # 2. S3 Bucket ACL & Encryption
        elif res_type == "AWS::S3::Bucket":
            acl = str(props.get("AccessControl", ""))
            if acl in ("PublicRead", "PublicReadWrite"):
                findings.append(
                    Finding(
                        scanner="iac-scanner",
                        category=Category.IAC,
                        rule_id="IAC-AWS-S3-PUBLIC-ACL",
                        title="Public S3 Bucket AccessControl Configured",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description=f"CloudFormation S3 Bucket '{res_name}' AccessControl is set to '{acl}'.",
                        impact="Exposes S3 bucket data publicly to unauthenticated internet users.",
                        remediation="Set AccessControl to Private and configure PublicAccessBlockConfiguration.",
                        location=Location(file_path=fpath, start_line=line_num, end_line=line_num),
                        resource_id=f"AWS::S3::Bucket.{res_name}",
                    )
                )

            if "BucketEncryption" not in props:
                findings.append(
                    Finding(
                        scanner="iac-scanner",
                        category=Category.IAC,
                        rule_id="IAC-AWS-S3-UNENCRYPTED",
                        title="Unencrypted S3 Bucket",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        description=f"CloudFormation S3 Bucket '{res_name}' is missing BucketEncryption properties.",
                        impact="Data stored at rest is not guaranteed to be encrypted using KMS or AES-256.",
                        remediation="Add BucketEncryption configuration block.",
                        location=Location(file_path=fpath, start_line=line_num, end_line=line_num),
                        resource_id=f"AWS::S3::Bucket.{res_name}",
                    )
                )

        # 3. RDS Public & Encryption
        elif res_type == "AWS::RDS::DBInstance":
            publicly_accessible = props.get("PubliclyAccessible", False)
            if publicly_accessible is True or str(publicly_accessible).lower() == "true":
                findings.append(
                    Finding(
                        scanner="iac-scanner",
                        category=Category.IAC,
                        rule_id="IAC-AWS-RDS-PUBLIC",
                        title="Publicly Accessible Database Instance",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description=f"CloudFormation RDS Instance '{res_name}' PubliclyAccessible property is true.",
                        impact="Exposes database instance on a public IP address.",
                        remediation="Set PubliclyAccessible to false and deploy in private subnets.",
                        location=Location(file_path=fpath, start_line=line_num, end_line=line_num),
                        resource_id=f"AWS::RDS::DBInstance.{res_name}",
                    )
                )

            storage_encrypted = props.get("StorageEncrypted", False)
            if storage_encrypted is False or str(storage_encrypted).lower() == "false":
                findings.append(
                    Finding(
                        scanner="iac-scanner",
                        category=Category.IAC,
                        rule_id="IAC-AWS-RDS-UNENCRYPTED",
                        title="Unencrypted RDS Database Storage",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        description=f"CloudFormation RDS Instance '{res_name}' StorageEncrypted property is false.",
                        impact="Database storage volume is stored unencrypted at rest.",
                        remediation="Set StorageEncrypted to true.",
                        location=Location(file_path=fpath, start_line=line_num, end_line=line_num),
                        resource_id=f"AWS::RDS::DBInstance.{res_name}",
                    )
                )

        # 4. IAM Policy / Role
        elif res_type in ("AWS::IAM::Policy", "AWS::IAM::Role", "AWS::IAM::Group"):
            policy_doc = props.get("PolicyDocument")
            if isinstance(policy_doc, dict):
                self._check_iam_policy_obj(fpath, f"{res_type}.{res_name}", policy_doc, line_num, findings)

    def _check_iam_policy_obj(
        self,
        fpath: Path,
        res_id: str,
        policy_obj: dict[str, Any],
        line_num: int,
        findings: list[Finding],
    ) -> None:
        """Inspect IAM policy statement dictionary for wildcard actions and resources."""
        statements = policy_obj.get("statement", policy_obj.get("Statement", []))
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements if isinstance(statements, list) else []:
            if not isinstance(stmt, dict):
                continue

            effect = str(stmt.get("effect", stmt.get("Effect", ""))).lower()
            if effect != "allow":
                continue

            action = stmt.get("action", stmt.get("Action", []))
            resource = stmt.get("resource", stmt.get("Resource", []))

            action_list = [_strip_quotes(a) for a in (action if isinstance(action, list) else [action])]
            resource_list = [_strip_quotes(r) for r in (resource if isinstance(resource, list) else [resource])]

            has_wildcard_action = any(a in ("*", "s3:*", "iam:*", "*:*") for a in action_list)
            if has_wildcard_action:
                findings.append(
                    Finding(
                        scanner="iac-scanner",
                        category=Category.IAC,
                        rule_id="IAC-AWS-IAM-WILDCARD-ACTION",
                        title="IAM Policy Wildcard Action Allowed",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description=f"IAM policy statement in '{res_id}' allows wildcard Action '*'.",
                        impact="Grants administrative or overly broad privilege escalation rights.",
                        remediation="Specify explicit least-privilege IAM actions (e.g. s3:GetObject).",
                        location=Location(file_path=fpath, start_line=line_num, end_line=line_num),
                        resource_id=res_id,
                    )
                )

            has_wildcard_resource = any(r == "*" for r in resource_list)
            if has_wildcard_resource and has_wildcard_action:
                findings.append(
                    Finding(
                        scanner="iac-scanner",
                        category=Category.IAC,
                        rule_id="IAC-AWS-IAM-WILDCARD-RESOURCE",
                        title="IAM Policy Wildcard Resource Allowed",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        description=f"IAM policy statement in '{res_id}' specifies Resource '*' with broad actions.",
                        impact="Applies high-privilege permissions across all resources in the AWS account.",
                        remediation="Restrict Resource ARNs to specific resource instances where possible.",
                        location=Location(file_path=fpath, start_line=line_num, end_line=line_num),
                        resource_id=res_id,
                    )
                )
