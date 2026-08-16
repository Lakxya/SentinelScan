"""Kubernetes Security Scanner analyzing static YAML/JSON manifests for security misconfigurations and RBAC risks."""

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

logger = logging.getLogger("sentinelscan.scanners.k8s_scanner")

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

# Secret variable name patterns in ConfigMaps or Secrets
SECRET_VAR_PATTERN = re.compile(
    r"(?i)(api[_\-]?key|secret|password|passwd|private[_\-]?key|auth[_\-]?token|access[_\-]?token|credentials|aws[_\-]?secret)"
)

# Placeholders to ignore in secret detection
PLACEHOLDER_PATTERN = re.compile(
    r"(?i)^(your[_\-]|\$\{|\$|change_me|example|dummy|placeholder|xxx|todofixme|foo|bar)"
)


@dataclass
class K8sManifestResource:
    """Dataclass representing a parsed Kubernetes API resource manifest."""

    kind: str
    api_version: str
    name: str
    namespace: str | None
    spec: dict[str, Any]
    raw_data: dict[str, Any]
    fpath: Path
    start_line: int
    doc_index: int


class K8sManifestParser:
    """Parser for Kubernetes YAML/JSON manifest files supporting multi-document streams."""

    @staticmethod
    def parse_file(fpath: Path) -> list[K8sManifestResource]:
        resources: list[K8sManifestResource] = []
        try:
            with open(fpath, "r", encoding="utf-8", errors="strict") as f:
                content = f.read()
        except Exception as e:  # noqa: BLE001
            logger.debug("Failed to read Kubernetes manifest file %s: %s", fpath, e)
            return resources

        if not content.strip():
            return resources

        try:
            docs = list(yaml.safe_load_all(content))
        except Exception as e:  # noqa: BLE001
            logger.debug("YAML parsing failed for file %s: %s", fpath, e)
            return resources

        lines = content.splitlines()

        for doc_idx, doc in enumerate(docs):
            if not isinstance(doc, dict):
                continue

            api_version = str(doc.get("apiVersion", "")).strip()
            kind = str(doc.get("kind", "")).strip()

            if not api_version or not kind:
                continue

            metadata = doc.get("metadata", {})
            name = "unnamed"
            namespace = None
            if isinstance(metadata, dict):
                name = str(metadata.get("name", "unnamed"))
                namespace = str(metadata.get("namespace")) if "namespace" in metadata else None

            spec = doc.get("spec", {})
            if not isinstance(spec, dict):
                spec = {}

            start_line = K8sManifestParser._find_resource_start_line(lines, kind, name, doc_idx)

            resources.append(
                K8sManifestResource(
                    kind=kind,
                    api_version=api_version,
                    name=name,
                    namespace=namespace,
                    spec=spec,
                    raw_data=doc,
                    fpath=fpath,
                    start_line=start_line,
                    doc_index=doc_idx,
                )
            )

        return resources

    @staticmethod
    def _find_resource_start_line(lines: list[str], kind: str, name: str, doc_idx: int) -> int:
        current_doc = 0
        for idx, line in enumerate(lines, start=1):
            if line.strip().startswith("---"):
                current_doc += 1
            if current_doc == doc_idx and f"kind: {kind}" in line:
                return idx
        return 1

    @staticmethod
    def extract_pod_spec(resource: K8sManifestResource) -> dict[str, Any] | None:
        """Extract PodSpec dictionary across different Kubernetes workload controllers."""
        kind = resource.kind
        spec = resource.spec

        if kind == "Pod":
            return spec

        if kind in ("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"):
            template = spec.get("template", {})
            if isinstance(template, dict):
                p_spec = template.get("spec", {})
                if isinstance(p_spec, dict):
                    return p_spec

        if kind == "CronJob":
            job_tmpl = spec.get("jobTemplate", {})
            if isinstance(job_tmpl, dict):
                j_spec = job_tmpl.get("spec", {})
                if isinstance(j_spec, dict):
                    tmpl = j_spec.get("template", {})
                    if isinstance(tmpl, dict):
                        p_spec = tmpl.get("spec", {})
                        if isinstance(p_spec, dict):
                            return p_spec

        return None


class KubernetesScanner(BaseScanner):
    """Kubernetes security scanner analyzing static YAML/JSON manifests for security misconfigurations."""

    @property
    def name(self) -> str:
        return "k8s-scanner"

    @property
    def category(self) -> Category:
        return Category.KUBERNETES

    @property
    def description(self) -> str:
        return "Kubernetes security scanner analyzing static YAML/JSON manifests for security misconfigurations and RBAC policy risks."

    def is_available(self, target: Target) -> bool:
        return True

    def scan(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        if target.is_file:
            self._scan_manifest(target.path, findings)
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
                if ext in (".yaml", ".yml", ".json"):
                    self._scan_manifest(fpath, findings)

        return findings

    def _scan_manifest(self, fpath: Path, findings: list[Finding]) -> None:
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

        resources = K8sManifestParser.parse_file(fpath)
        for res in resources:
            self._evaluate_resource_rules(res, findings)

    def _evaluate_resource_rules(self, res: K8sManifestResource, findings: list[Finding]) -> None:
        pod_spec = K8sManifestParser.extract_pod_spec(res)
        if pod_spec is not None:
            self._evaluate_workload_rules(res, pod_spec, findings)

        if res.kind in ("Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"):
            self._evaluate_rbac_rules(res, findings)

        if res.kind == "ConfigMap":
            self._evaluate_configmap_secrets(res, findings)

        if res.kind == "Secret":
            self._evaluate_secret_manifest_data(res, findings)

    def _evaluate_workload_rules(self, res: K8sManifestResource, pod_spec: dict[str, Any], findings: list[Finding]) -> None:
        pod_sec = pod_spec.get("securityContext", {})
        if not isinstance(pod_sec, dict):
            pod_sec = {}

        pod_non_root = pod_sec.get("runAsNonRoot")
        pod_user = pod_sec.get("runAsUser")

        # Check host namespaces
        if pod_spec.get("hostNetwork") is True or pod_spec.get("hostPID") is True or pod_spec.get("hostIPC") is True:
            findings.append(
                Finding(
                    scanner="k8s-scanner",
                    category=Category.KUBERNETES,
                    rule_id="K8S-HOST-NAMESPACES",
                    title=f"Host Namespace Access Enabled on {res.kind}/{res.name}",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description=f"{res.kind} '{res.name}' enables hostNetwork, hostPID, or hostIPC sharing.",
                    impact="Sharing host namespaces bypasses network isolation and enables cross-container process/signal injection.",
                    remediation="Set hostNetwork, hostPID, and hostIPC to false unless building host-level daemon sets.",
                    location=Location(file_path=res.fpath, start_line=res.start_line),
                    resource_id=f"{res.kind}:{res.name}",
                )
            )

        containers = pod_spec.get("containers", [])
        init_containers = pod_spec.get("containers", [])
        all_containers = (containers if isinstance(containers, list) else []) + (
            init_containers if isinstance(init_containers, list) and init_containers != containers else []
        )

        for c in all_containers:
            if not isinstance(c, dict):
                continue

            c_name = str(c.get("name", "unnamed"))
            c_sec = c.get("securityContext", {})
            if not isinstance(c_sec, dict):
                c_sec = {}

            # 1. K8S-PRIVILEGED-CONTAINER
            if c_sec.get("privileged") is True:
                findings.append(
                    Finding(
                        scanner="k8s-scanner",
                        category=Category.KUBERNETES,
                        rule_id="K8S-PRIVILEGED-CONTAINER",
                        title=f"Privileged Container Requested: {c_name}",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        description=f"Container '{c_name}' in {res.kind}/{res.name} sets securityContext.privileged=true.",
                        impact="Privileged containers grant unrestricted access to host devices and Linux kernel capabilities, enabling host escape.",
                        remediation="Remove privileged: true. Grant specific required capabilities via securityContext.capabilities.add.",
                        location=Location(file_path=res.fpath, start_line=res.start_line),
                        resource_id=f"{res.kind}:{res.name}:{c_name}",
                    )
                )

            # 2. K8S-ROOT-CONTAINER
            c_user = c_sec.get("runAsUser")
            c_non_root = c_sec.get("runAsNonRoot")

            if c_user == 0 or c_non_root is False or pod_user == 0 or pod_non_root is False:
                findings.append(
                    Finding(
                        scanner="k8s-scanner",
                        category=Category.KUBERNETES,
                        rule_id="K8S-ROOT-CONTAINER",
                        title=f"Container Explicitly Configured to Run as Root: {c_name}",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description=f"Container '{c_name}' in {res.kind}/{res.name} explicitly configures runAsUser: 0 or runAsNonRoot: false.",
                        impact="Running container processes as root increases blast radius and risk of host compromise if exploited.",
                        remediation="Set securityContext.runAsNonRoot: true and specify an unprivileged runAsUser (e.g. 10001).",
                        location=Location(file_path=res.fpath, start_line=res.start_line),
                        resource_id=f"{res.kind}:{res.name}:{c_name}",
                    )
                )
            elif (
                c_non_root is None
                and pod_non_root is None
                and c_user is None
                and pod_user is None
            ):
                findings.append(
                    Finding(
                        scanner="k8s-scanner",
                        category=Category.KUBERNETES,
                        rule_id="K8S-ROOT-CONTAINER",
                        title=f"Container Lacks Explicit Non-Root Configuration: {c_name}",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        description=f"Container '{c_name}' in {res.kind}/{res.name} lacks runAsNonRoot or runAsUser specification and may default to root.",
                        impact="Containers defaulting to root inherit privileges of the base container image user.",
                        remediation="Explicitly define securityContext.runAsNonRoot: true at container or Pod level.",
                        location=Location(file_path=res.fpath, start_line=res.start_line),
                        resource_id=f"{res.kind}:{res.name}:{c_name}",
                    )
                )

            # 3. K8S-MISSING-RESOURCE-LIMITS
            resources = c.get("resources", {})
            limits = resources.get("limits", {}) if isinstance(resources, dict) else {}
            if not isinstance(limits, dict) or not limits.get("cpu") or not limits.get("memory"):
                findings.append(
                    Finding(
                        scanner="k8s-scanner",
                        category=Category.KUBERNETES,
                        rule_id="K8S-MISSING-RESOURCE-LIMITS",
                        title=f"Missing Resource Limits for Container: {c_name}",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        description=f"Container '{c_name}' in {res.kind}/{res.name} lacks CPU or memory resource limits.",
                        impact="Containers without resource limits can consume all node CPU/memory, causing Denial of Service to neighboring workloads.",
                        remediation="Define resources.limits.cpu and resources.limits.memory for all containers.",
                        location=Location(file_path=res.fpath, start_line=res.start_line),
                        resource_id=f"{res.kind}:{res.name}:{c_name}",
                    )
                )

            # 4. K8S-ALLOW-PRIVILEGE-ESCALATION
            if c_sec.get("allowPrivilegeEscalation") is True or c_sec.get("allowPrivilegeEscalation") is None:
                findings.append(
                    Finding(
                        scanner="k8s-scanner",
                        category=Category.KUBERNETES,
                        rule_id="K8S-ALLOW-PRIVILEGE-ESCALATION",
                        title=f"Privilege Escalation Allowed for Container: {c_name}",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        description=f"Container '{c_name}' in {res.kind}/{res.name} allows privilege escalation (allowPrivilegeEscalation is true or unconfigured).",
                        impact="Child processes inside container can gain more privileges than parent process via setuid binaries.",
                        remediation="Explicitly set securityContext.allowPrivilegeEscalation: false.",
                        location=Location(file_path=res.fpath, start_line=res.start_line),
                        resource_id=f"{res.kind}:{res.name}:{c_name}",
                    )
                )

    def _evaluate_rbac_rules(self, res: K8sManifestResource, findings: list[Finding]) -> None:
        if res.kind in ("Role", "ClusterRole"):
            rules = res.raw_data.get("rules", [])
            if isinstance(rules, list):
                for rule in rules:
                    if isinstance(rule, dict):
                        verbs = rule.get("verbs", [])
                        resources = rule.get("resources", [])
                        if isinstance(verbs, list) and isinstance(resources, list) and "*" in verbs and "*" in resources:
                            findings.append(
                                Finding(
                                    scanner="k8s-scanner",
                                    category=Category.KUBERNETES,
                                    rule_id="K8S-UNBOUNDED-RBAC-CLUSTER-ADMIN",
                                    title=f"Unbounded RBAC Wildcard Rule in {res.kind}/{res.name}",
                                    severity=Severity.HIGH,
                                    confidence=Confidence.HIGH,
                                    description=f"{res.kind} '{res.name}' grants wildcard verbs ['*'] over wildcard resources ['*'].",
                                    impact="Wildcard RBAC rules grant full administrative control over cluster resources, violating least privilege.",
                                    remediation="Scope RBAC rules to specific required API groups, resources, and verbs.",
                                    location=Location(file_path=res.fpath, start_line=res.start_line),
                                    resource_id=f"{res.kind}:{res.name}",
                                )
                            )
                            break

        if res.kind in ("RoleBinding", "ClusterRoleBinding"):
            role_ref = res.raw_data.get("roleRef", {})
            if isinstance(role_ref, dict):
                ref_name = str(role_ref.get("name", ""))
                if ref_name == "cluster-admin":
                    findings.append(
                        Finding(
                            scanner="k8s-scanner",
                            category=Category.KUBERNETES,
                            rule_id="K8S-UNBOUNDED-RBAC-CLUSTER-ADMIN",
                            title=f"Binding to cluster-admin Role in {res.kind}/{res.name}",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            description=f"{res.kind} '{res.name}' binds subjects directly to the 'cluster-admin' superuser role.",
                            impact="Bypasses fine-grained access control, granting full superuser permissions to bound service accounts or users.",
                            remediation="Bind service accounts to dedicated fine-grained Roles/ClusterRoles instead of cluster-admin.",
                            location=Location(file_path=res.fpath, start_line=res.start_line),
                            resource_id=f"{res.kind}:{res.name}",
                        )
                    )

    def _evaluate_configmap_secrets(self, res: K8sManifestResource, findings: list[Finding]) -> None:
        data = res.raw_data.get("data", {})
        if isinstance(data, dict):
            for k, v in data.items():
                k_str = str(k)
                v_str = str(v)
                if SECRET_VAR_PATTERN.search(k_str) and v_str and not PLACEHOLDER_PATTERN.search(v_str):
                    masked_val = mask_token(v_str)
                    findings.append(
                        Finding(
                            scanner="k8s-scanner",
                            category=Category.KUBERNETES,
                            rule_id="K8S-SECRET-IN-CONFIGMAP",
                            title=f"Hardcoded Secret in ConfigMap/{res.name} (Key: {k_str})",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            description=f"ConfigMap '{res.name}' contains sensitive key '{k_str}' with value '{masked_val}'.",
                            impact="ConfigMaps store data unencrypted in plain text and are accessible to non-admin cluster readers.",
                            remediation="Move sensitive credentials to Kubernetes Secret resources or external secret managers (Vault/AWS Secrets Manager).",
                            location=Location(file_path=res.fpath, start_line=res.start_line),
                            resource_id=f"ConfigMap:{res.name}:{k_str}",
                            metadata={"key": k_str, "masked_val": masked_val},
                        )
                    )

    def _evaluate_secret_manifest_data(self, res: K8sManifestResource, findings: list[Finding]) -> None:
        string_data = res.raw_data.get("stringData", {})
        data = res.raw_data.get("data", {})

        if isinstance(string_data, dict) and len(string_data) > 0:
            for k, v in string_data.items():
                k_str = str(k)
                v_str = str(v)
                masked_val = mask_token(v_str)
                findings.append(
                    Finding(
                        scanner="k8s-scanner",
                        category=Category.KUBERNETES,
                        rule_id="K8S-PLAIN-TEXT-SECRET-DATA",
                        title=f"Raw Unencrypted stringData in Secret/{res.name} (Key: {k_str})",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        description=f"Kubernetes Secret '{res.name}' stores raw unencrypted stringData key '{k_str}'.",
                        impact="Committing raw secret data in manifest files risks leaking credentials in source control repositories.",
                        remediation="Use SealedSecrets, Vault, or SOPS for git-managed secret workflows. Avoid raw stringData in repository manifests.",
                        location=Location(file_path=res.fpath, start_line=res.start_line),
                        resource_id=f"Secret:{res.name}:{k_str}",
                        metadata={"key": k_str, "masked_val": masked_val},
                    )
                )

        if isinstance(data, dict) and len(data) > 0:
            for k, v in data.items():
                k_str = str(k)
                v_str = str(v)
                masked_val = mask_token(v_str)
                findings.append(
                    Finding(
                        scanner="k8s-scanner",
                        category=Category.KUBERNETES,
                        rule_id="K8S-PLAIN-TEXT-SECRET-DATA",
                        title=f"Unencrypted Base64 Data Key in Secret/{res.name} (Key: {k_str})",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        description=f"Kubernetes Secret '{res.name}' stores base64-encoded data key '{k_str}'. Base64 is encoding, not encryption.",
                        impact="Base64 encoding is easily decoded by unauthorized readers. Manifest credentials in Git create supply chain risk.",
                        remediation="Store secrets using SealedSecrets, External Secrets Operator, or SOPS encryption before committing.",
                        location=Location(file_path=res.fpath, start_line=res.start_line),
                        resource_id=f"Secret:{res.name}:{k_str}",
                        metadata={"key": k_str, "masked_val": masked_val},
                    )
                )
