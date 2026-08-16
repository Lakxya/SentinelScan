"""Attack-Path & Risk Correlation Engine for potential vulnerability path discovery."""

import logging
from collections import deque

from sentinelscan.models.attack_path import AttackPath, AttackStep
from sentinelscan.models.finding import Confidence, Severity
from sentinelscan.models.graph import ArchitectureGraph, Node, NodeType
from sentinelscan.models.result import ScanResult
from sentinelscan.scanners.secret_scanner import mask_token

logger = logging.getLogger("sentinelscan.core.attack_path_engine")

ENTRY_NODE_TYPES = {
    NodeType.NETWORK_SERVICE,
    NodeType.DOCKER_IMAGE,
    NodeType.AWS_S3_BUCKET,
    NodeType.FILE_TARGET,
}

TARGET_NODE_TYPES = {
    NodeType.K8S_SECRET,
    NodeType.AWS_IAM_ROLE,
    NodeType.AWS_IAM_POLICY,
    NodeType.AWS_KMS_KEY,
    NodeType.SECURITY_FINDING,
}

SEVERITY_SCORES = {
    Severity.CRITICAL: 9.0,
    Severity.HIGH: 7.0,
    Severity.MEDIUM: 4.0,
    Severity.LOW: 2.0,
    Severity.INFO: 1.0,
}


class AttackPathEngine:
    """Analytical engine discovering potential attack paths and correlated risk paths across architecture graphs."""

    def __init__(self, max_depth: int = 5) -> None:
        self.max_depth = max_depth

    def discover_paths(self, graph: ArchitectureGraph, scan_result: ScanResult | None = None) -> list[AttackPath]:
        """Discover potential attack paths within an architecture graph.

        Args:
            graph: ArchitectureGraph containing nodes and edges.
            scan_result: Optional ScanResult containing normalized security findings.

        Returns:
            list[AttackPath]: Deduplicated list of potential attack paths.
        """
        if not graph.nodes or not graph.edges:
            return []

        # Map adjacency list for graph traversal
        adj: dict[str, list[tuple[str, str]]] = {node_id: [] for node_id in graph.nodes}
        for edge in graph.edges:
            if edge.source_id in adj:
                adj[edge.source_id].append((edge.target_id, edge.edge_type.value))

        # Identify Entry Nodes and Target Nodes
        entry_nodes = [node for node in graph.nodes.values() if self._is_entry_node(node)]
        target_nodes = [node for node in graph.nodes.values() if self._is_target_node(node)]

        discovered_paths: list[AttackPath] = []
        seen_fingerprints: set[str] = set()

        for entry in entry_nodes:
            paths_from_entry = self._find_paths_bfs(entry.id, target_nodes, graph, adj, seen_fingerprints)
            discovered_paths.extend(paths_from_entry)

        # If no specific graph paths found, correlate findings into fallback risk chains if findings exist
        if not discovered_paths and scan_result and scan_result.findings:
            fallback = self._create_finding_correlation_paths(scan_result)
            discovered_paths.extend(fallback)

        # Sort paths by risk score descending
        discovered_paths.sort(key=lambda p: p.composite_risk_score, reverse=True)
        return discovered_paths

    def _is_entry_node(self, node: Node) -> bool:
        if node.node_type in ENTRY_NODE_TYPES:
            return True
        return "network" in node.name.lower() or "docker" in node.name.lower() or "public" in node.name.lower()

    def _is_target_node(self, node: Node) -> bool:
        if node.node_type in TARGET_NODE_TYPES:
            return True
        return "secret" in node.name.lower() or "iam" in node.name.lower() or "policy" in node.name.lower()

    def _find_paths_bfs(
        self,
        start_id: str,
        target_nodes: list[Node],
        graph: ArchitectureGraph,
        adj: dict[str, list[tuple[str, str]]],
        seen_fingerprints: set[str],
    ) -> list[AttackPath]:
        target_ids = {node.id for node in target_nodes if node.id != start_id}
        paths: list[AttackPath] = []

        queue: deque[list[str]] = deque([[start_id]])

        while queue:
            current_path = queue.popleft()
            current_id = current_path[-1]

            # Enforce max traversal depth limit of 5
            if len(current_path) > self.max_depth:
                continue

            if current_id in target_ids and len(current_path) > 1:
                attack_path = self._construct_attack_path(current_path, graph)
                if attack_path.fingerprint not in seen_fingerprints:
                    seen_fingerprints.add(attack_path.fingerprint)
                    paths.append(attack_path)

            for neighbor_id, _ in adj.get(current_id, []):
                if neighbor_id not in current_path:  # Prevent cycles
                    queue.append(list(current_path) + [neighbor_id])

        return paths

    def _construct_attack_path(self, path_node_ids: list[str], graph: ArchitectureGraph) -> AttackPath:
        steps: list[AttackStep] = []
        max_sev = Severity.LOW
        conf_levels: list[Confidence] = []

        for idx, node_id in enumerate(path_node_ids, start=1):
            node = graph.nodes[node_id]
            desc = mask_token(node.metadata.get("description", f"{node.node_type.value} asset '{node.name}'."))

            finding_fp = node.metadata.get("fingerprint")
            rule_id = node.metadata.get("rule_id")
            sev_str = node.metadata.get("severity")

            if sev_str:
                try:
                    sev_enum = Severity(sev_str)
                    if SEVERITY_SCORES.get(sev_enum, 0) > SEVERITY_SCORES.get(max_sev, 0):
                        max_sev = sev_enum
                except ValueError:
                    pass

            steps.append(
                AttackStep(
                    step_number=idx,
                    node_id=node.id,
                    node_name=node.name,
                    node_type=node.node_type.value,
                    description=desc,
                    finding_fingerprint=finding_fp,
                    rule_id=rule_id,
                    severity=sev_str,
                )
            )
            conf_levels.append(Confidence.HIGH if sev_str else Confidence.MEDIUM)

        entry_node = graph.nodes[path_node_ids[0]]
        target_node = graph.nodes[path_node_ids[-1]]

        title = f"Potential Path: {entry_node.name} to {target_node.name}"
        remediation = "Restrict network access and enforce principle of least privilege."

        # Compute composite risk score (0.0 to 10.0 scale)
        base_score = SEVERITY_SCORES.get(max_sev, 4.0)
        depth_bonus = min(2.0, (len(steps) - 1) * 0.5)
        risk_score = min(10.0, base_score + depth_bonus)

        composite_conf = Confidence.HIGH if all(c == Confidence.HIGH for c in conf_levels) else Confidence.MEDIUM

        path_id_hash = AttackPath(
            path_id="",
            title=title,
            entry_node_id=entry_node.id,
            target_node_id=target_node.id,
            steps=steps,
            composite_severity=max_sev,
            confidence=composite_conf,
            composite_risk_score=risk_score,
            remediation_summary=remediation,
        ).fingerprint

        return AttackPath(
            path_id=f"AP-{path_id_hash}",
            title=title,
            entry_node_id=entry_node.id,
            target_node_id=target_node.id,
            steps=steps,
            composite_severity=max_sev,
            confidence=composite_conf,
            composite_risk_score=risk_score,
            remediation_summary=remediation,
        )

    def _create_finding_correlation_paths(self, scan_result: ScanResult) -> list[AttackPath]:
        """Correlate independent findings into fallback potential attack paths if findings exist."""
        paths: list[AttackPath] = []
        if not scan_result.findings:
            return paths

        high_findings = [f for f in scan_result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        if not high_findings:
            return paths

        first_finding = high_findings[0]
        step1 = AttackStep(
            step_number=1,
            node_id=f"finding:{first_finding.fingerprint}",
            node_name=first_finding.title,
            node_type="security_finding",
            description=mask_token(first_finding.description),
            finding_fingerprint=first_finding.fingerprint,
            rule_id=first_finding.rule_id,
            severity=first_finding.severity.value,
        )

        path_obj = AttackPath(
            path_id=f"AP-{first_finding.fingerprint[:16]}",
            title=f"Correlated Potential Path: {first_finding.rule_id}",
            entry_node_id=f"finding:{first_finding.fingerprint}",
            target_node_id=first_finding.resource_id or "target_asset",
            steps=[step1],
            composite_severity=first_finding.severity,
            confidence=first_finding.confidence,
            composite_risk_score=SEVERITY_SCORES.get(first_finding.severity, 5.0),
            remediation_summary=first_finding.remediation,
        )
        paths.append(path_obj)
        return paths
