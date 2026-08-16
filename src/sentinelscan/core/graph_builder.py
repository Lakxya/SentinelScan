"""Architecture Graph Builder discovering resource nodes and relationships from static codebase assets and scanner findings."""

import json
import logging
import os
import re
from pathlib import Path

import yaml  # type: ignore[import-untyped]

from sentinelscan.models.finding import Finding
from sentinelscan.models.graph import ArchitectureGraph, Edge, EdgeType, Node, NodeType
from sentinelscan.models.result import ScanResult
from sentinelscan.models.target import Target
from sentinelscan.scanners.secret_scanner import mask_token

logger = logging.getLogger("sentinelscan.core.graph_builder")

# Maximum file size to scan for graph building (5 MB)
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024

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


class ArchitectureGraphBuilder:
    """Builder class constructing deterministic architecture graphs from static codebase files and scanner findings."""

    def build(self, target: Target, scan_result: ScanResult | None = None) -> ArchitectureGraph:
        """Construct ArchitectureGraph for target directory or file and optional scan results.

        Args:
            target: Target instance containing path and target metadata.
            scan_result: Optional ScanResult containing findings from executed scanners.

        Returns:
            ArchitectureGraph containing discovered nodes and relationship edges.
        """
        graph = ArchitectureGraph()

        # 1. Discover resources and relationships from static project files
        if target.is_file:
            self._process_file(target.path, graph)
        else:
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

                    self._process_file(fpath, graph)

        # 2. Associate existing scanner findings if available
        if scan_result and scan_result.findings:
            self._associate_findings(scan_result.findings, graph)

        return graph

    def _process_file(self, fpath: Path, graph: ArchitectureGraph) -> None:
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

        fname_lower = fpath.name.lower()
        ext = fpath.suffix.lower()

        if ext == ".tf":
            self._parse_terraform(fpath, graph)
        elif ext in (".yaml", ".yml") or fname_lower in ("caddyfile", ".htaccess", "httpd.conf", "nginx.conf"):
            self._parse_yaml_manifests(fpath, graph)
        elif ext == ".json":
            self._parse_json_manifests(fpath, graph)
        elif fname_lower == "dockerfile" or fname_lower.startswith("dockerfile."):
            self._parse_dockerfile(fpath, graph)

    def _parse_terraform(self, fpath: Path, graph: ArchitectureGraph) -> None:
        try:
            import hcl2  # type: ignore[import-untyped]

            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                data = hcl2.load(f)
        except Exception:  # noqa: BLE001
            return

        if not isinstance(data, dict):
            return

        resources = data.get("resource", [])
        if not isinstance(resources, list):
            return

        for res_entry in resources:
            if not isinstance(res_entry, dict):
                continue

            for raw_res_type, name_dict in res_entry.items():
                res_type = str(raw_res_type).strip("\"'")
                if not isinstance(name_dict, dict):
                    continue

                for raw_res_name, config in name_dict.items():
                    res_name = str(raw_res_name).strip("\"'")
                    node_id = f"tf:{res_type}.{res_name}"
                    graph.add_node(
                        Node(
                            id=node_id,
                            node_type=NodeType.TERRAFORM_RESOURCE,
                            name=f"{res_type}.{res_name}",
                            category="iac",
                            file_path=fpath,
                            start_line=1,
                            metadata={"resource_type": res_type, "resource_name": res_name},
                        )
                    )

                    # Extract references to other terraform resources
                    config_str = str(config)
                    ref_matches = re.findall(r"\b([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+)\b", config_str)
                    for raw_ref_type, raw_ref_name in ref_matches:
                        ref_type = raw_ref_type.strip("\"'")
                        ref_name = raw_ref_name.strip("\"'")
                        if ref_type != res_type or ref_name != res_name:
                            target_ref_id = f"tf:{ref_type}.{ref_name}"
                            edge_type = EdgeType.ATTACHED_TO if "policy_attachment" in res_type else EdgeType.REFERENCES
                            graph.add_edge(
                                Edge(
                                    source_id=node_id,
                                    target_id=target_ref_id,
                                    edge_type=edge_type,
                                    label=edge_type.value,
                                )
                            )

    def _parse_yaml_manifests(self, fpath: Path, graph: ArchitectureGraph) -> None:
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                docs = list(yaml.safe_load_all(f))
        except Exception:  # noqa: BLE001
            return

        for doc in docs:
            if not isinstance(doc, dict):
                continue

            kind = str(doc.get("kind", ""))
            metadata = doc.get("metadata", {})
            if not kind or not isinstance(metadata, dict):
                continue

            name = str(metadata.get("name", ""))
            namespace = str(metadata.get("namespace", "default"))
            if not name:
                continue

            # Kubernetes Workloads
            if kind in ("Deployment", "StatefulSet", "DaemonSet", "Pod", "Job", "CronJob"):
                node_id = f"k8s:{kind}:{namespace}/{name}"
                graph.add_node(
                    Node(
                        id=node_id,
                        node_type=NodeType.K8S_WORKLOAD,
                        name=f"{kind}/{name}",
                        category="kubernetes",
                        file_path=fpath,
                        start_line=1,
                        metadata={"kind": kind, "namespace": namespace, "name": name},
                    )
                )

                # Inspect container spec for Secret, ConfigMap, ServiceAccount references
                pod_spec = doc.get("spec", {})
                if kind in ("Deployment", "StatefulSet", "DaemonSet") and isinstance(pod_spec, dict):
                    pod_spec = pod_spec.get("template", {}).get("spec", {})

                if isinstance(pod_spec, dict):
                    sa_name = pod_spec.get("serviceAccountName") or pod_spec.get("serviceAccount")
                    if sa_name:
                        sa_node_id = f"k8s:ServiceAccount:{namespace}/{sa_name}"
                        graph.add_node(
                            Node(
                                id=sa_node_id,
                                node_type=NodeType.K8S_SERVICE_ACCOUNT,
                                name=f"ServiceAccount/{sa_name}",
                                category="kubernetes",
                                file_path=fpath,
                                start_line=1,
                            )
                        )
                        graph.add_edge(
                            Edge(
                                source_id=node_id,
                                target_id=sa_node_id,
                                edge_type=EdgeType.USES_SERVICE_ACCOUNT,
                                label="USES_SERVICE_ACCOUNT",
                            )
                        )

                    # Inspect envFrom and volumes for Secret/ConfigMap
                    containers = pod_spec.get("containers", [])
                    if isinstance(containers, list):
                        for c in containers:
                            if not isinstance(c, dict):
                                continue
                            env_from = c.get("envFrom", [])
                            if isinstance(env_from, list):
                                for ef in env_from:
                                    if not isinstance(ef, dict):
                                        continue
                                    secret_ref = ef.get("secretRef", {}).get("name")
                                    if secret_ref:
                                        sec_node_id = f"k8s:Secret:{namespace}/{secret_ref}"
                                        graph.add_node(
                                            Node(
                                                id=sec_node_id,
                                                node_type=NodeType.K8S_SECRET,
                                                name=f"Secret/{secret_ref}",
                                                category="kubernetes",
                                                file_path=fpath,
                                            )
                                        )
                                        graph.add_edge(
                                            Edge(
                                                source_id=node_id,
                                                target_id=sec_node_id,
                                                edge_type=EdgeType.USES_SECRET,
                                                label="USES_SECRET",
                                            )
                                        )

                                    cm_ref = ef.get("configMapRef", {}).get("name")
                                    if cm_ref:
                                        cm_node_id = f"k8s:ConfigMap:{namespace}/{cm_ref}"
                                        graph.add_node(
                                            Node(
                                                id=cm_node_id,
                                                node_type=NodeType.K8S_CONFIGMAP,
                                                name=f"ConfigMap/{cm_ref}",
                                                category="kubernetes",
                                                file_path=fpath,
                                            )
                                        )
                                        graph.add_edge(
                                            Edge(
                                                source_id=node_id,
                                                target_id=cm_node_id,
                                                edge_type=EdgeType.USES_CONFIGMAP,
                                                label="USES_CONFIGMAP",
                                            )
                                        )

            # Kubernetes Service
            elif kind == "Service":
                svc_node_id = f"k8s:Service:{namespace}/{name}"
                graph.add_node(
                    Node(
                        id=svc_node_id,
                        node_type=NodeType.K8S_SERVICE,
                        name=f"Service/{name}",
                        category="kubernetes",
                        file_path=fpath,
                        start_line=1,
                    )
                )

            # Kubernetes Secret / ConfigMap
            elif kind in ("Secret", "ConfigMap"):
                sec_type = NodeType.K8S_SECRET if kind == "Secret" else NodeType.K8S_CONFIGMAP
                res_node_id = f"k8s:{kind}:{namespace}/{name}"
                graph.add_node(
                    Node(
                        id=res_node_id,
                        node_type=sec_type,
                        name=f"{kind}/{name}",
                        category="kubernetes",
                        file_path=fpath,
                        start_line=1,
                    )
                )

    def _parse_json_manifests(self, fpath: Path, graph: ArchitectureGraph) -> None:
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                doc = json.load(f)
        except Exception:  # noqa: BLE001
            return

        if not isinstance(doc, dict):
            return

        # AWS IAM Policy JSON
        if ("Version" in doc and ("Statement" in doc or "statement" in doc)) or "Statement" in doc:
            policy_name = fpath.stem
            node_id = f"aws:iam_policy:{policy_name}"
            graph.add_node(
                Node(
                    id=node_id,
                    node_type=NodeType.AWS_IAM_POLICY,
                    name=f"IAM Policy ({policy_name})",
                    category="cloud",
                    file_path=fpath,
                    start_line=1,
                )
            )

            # Extract S3 bucket or KMS key references from Statement Resource
            statements = doc.get("Statement") or doc.get("statement")
            if isinstance(statements, dict):
                statements = [statements]

            if isinstance(statements, list):
                for stmt in statements:
                    if not isinstance(stmt, dict):
                        continue
                    res = stmt.get("Resource") or stmt.get("resource")
                    if isinstance(res, str) and "arn:aws:s3:::" in res:
                        bucket_name = res.replace("arn:aws:s3:::", "").split("/")[0]
                        b_id = f"aws:s3_bucket:{bucket_name}"
                        graph.add_node(
                            Node(
                                id=b_id,
                                node_type=NodeType.AWS_S3_BUCKET,
                                name=f"S3 Bucket ({bucket_name})",
                                category="cloud",
                                file_path=fpath,
                            )
                        )
                        graph.add_edge(
                            Edge(
                                source_id=node_id,
                                target_id=b_id,
                                edge_type=EdgeType.REFERENCES,
                                label="REFERENCES",
                            )
                        )

    def _parse_dockerfile(self, fpath: Path, graph: ArchitectureGraph) -> None:
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:  # noqa: BLE001
            return

        for line in content.splitlines():
            line_str = line.strip()
            if line_str.upper().startswith("FROM "):
                parts = line_str.split()
                if len(parts) >= 2:
                    base_img = parts[1]
                    img_id = f"docker:image:{base_img}"
                    graph.add_node(
                        Node(
                            id=img_id,
                            node_type=NodeType.DOCKER_IMAGE,
                            name=f"Docker Image ({base_img})",
                            category="container",
                            file_path=fpath,
                            start_line=1,
                        )
                    )

    def _associate_findings(self, findings: list[Finding], graph: ArchitectureGraph) -> None:
        for finding in findings:
            finding_node_id = f"finding:{finding.fingerprint}"
            masked_desc = mask_token(finding.description) if finding.description else ""

            loc_path = finding.location.file_path if finding.location else None
            loc_line = finding.location.start_line if (finding.location and finding.location.start_line) else 1

            finding_node = Node(
                id=finding_node_id,
                node_type=NodeType.SECURITY_FINDING,
                name=f"Finding: {finding.rule_id}",
                category=finding.category.value if hasattr(finding.category, "value") else str(finding.category),
                file_path=loc_path,
                start_line=loc_line,
                metadata={
                    "rule_id": finding.rule_id,
                    "severity": finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
                    "confidence": finding.confidence.value if hasattr(finding.confidence, "value") else str(finding.confidence),
                    "description": masked_desc,
                },
            )
            graph.add_node(finding_node)

            # Match finding to resource node by resource_id or file_path
            matched = False
            if finding.resource_id:
                for node_id, node in list(graph.nodes.items()):
                    if node.node_type == NodeType.SECURITY_FINDING:
                        continue
                    if node_id == finding.resource_id or node.name == finding.resource_id:
                        graph.add_edge(
                            Edge(
                                source_id=node_id,
                                target_id=finding_node_id,
                                edge_type=EdgeType.HAS_FINDING,
                                label="HAS_FINDING",
                            )
                        )
                        matched = True

            if not matched and loc_path:
                norm_finding_path = str(loc_path).replace("\\", "/").lower()
                for node_id, node in list(graph.nodes.items()):
                    if node.node_type == NodeType.SECURITY_FINDING:
                        continue
                    if node.file_path:
                        norm_node_path = str(node.file_path).replace("\\", "/").lower()
                        if norm_node_path == norm_finding_path:
                            graph.add_edge(
                                Edge(
                                    source_id=node_id,
                                    target_id=finding_node_id,
                                    edge_type=EdgeType.HAS_FINDING,
                                    label="HAS_FINDING",
                                )
                            )
