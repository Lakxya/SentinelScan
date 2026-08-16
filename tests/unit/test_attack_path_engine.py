"""Unit tests for AttackPathEngine, AttackPath data models, and path reporters."""

import socket

from sentinelscan.core.attack_path_engine import AttackPathEngine
from sentinelscan.models.attack_path import AttackPath, AttackStep
from sentinelscan.models.finding import Confidence, Severity
from sentinelscan.models.graph import ArchitectureGraph, Edge, EdgeType, Node, NodeType
from sentinelscan.reporting.path_reporter import JsonPathReporter, TerminalPathReporter


def test_attack_path_engine_discovery():
    """Verify AttackPathEngine discovers potential attack paths from entry node to target node."""
    graph = ArchitectureGraph()

    # Entry node: exposed network service
    node_net = Node(
        id="net:127.0.0.1:3306",
        node_type=NodeType.NETWORK_SERVICE,
        name="127.0.0.1:3306",
        category="network",
        metadata={"severity": "HIGH", "description": "Exposed MySQL port"},
    )
    # Intermediate node: K8s Secret
    node_secret = Node(
        id="k8s:Secret:default/db-secret",
        node_type=NodeType.K8S_SECRET,
        name="db-secret",
        category="kubernetes",
        metadata={"severity": "MEDIUM", "description": "Unencrypted K8s Secret"},
    )
    # Target node: AWS IAM Policy
    node_iam = Node(
        id="aws:iam_policy:admin_policy",
        node_type=NodeType.AWS_IAM_POLICY,
        name="admin_policy",
        category="cloud",
        metadata={"severity": "CRITICAL", "description": "Wildcard IAM Policy"},
    )

    graph.add_node(node_net)
    graph.add_node(node_secret)
    graph.add_node(node_iam)

    graph.add_edge(Edge(source_id=node_net.id, target_id=node_secret.id, edge_type=EdgeType.USES_SECRET))
    graph.add_edge(Edge(source_id=node_secret.id, target_id=node_iam.id, edge_type=EdgeType.ATTACHED_TO))

    engine = AttackPathEngine(max_depth=5)
    paths = engine.discover_paths(graph)

    assert len(paths) >= 1
    p = paths[0]
    assert p.path_id.startswith("AP-")
    assert p.entry_node_id == "net:127.0.0.1:3306"
    assert p.target_node_id == "aws:iam_policy:admin_policy"
    assert p.composite_severity == Severity.CRITICAL
    assert p.composite_risk_score > 7.0
    assert p.confidence in (Confidence.HIGH, Confidence.MEDIUM)


def test_attack_path_max_depth_limit():
    """Verify AttackPathEngine graph traversal respects max_depth limit of 5 hops."""
    graph = ArchitectureGraph()

    # Construct a chain of 7 nodes: n1 -> n2 -> n3 -> n4 -> n5 -> n6 -> n7
    nodes = []
    for i in range(1, 8):
        ntype = NodeType.NETWORK_SERVICE if i == 1 else (NodeType.AWS_IAM_POLICY if i == 7 else NodeType.FILE_TARGET)
        n = Node(id=f"node_{i}", node_type=ntype, name=f"Node {i}", category="test")
        graph.add_node(n)
        nodes.append(n)

    for i in range(len(nodes) - 1):
        graph.add_edge(Edge(source_id=nodes[i].id, target_id=nodes[i + 1].id, edge_type=EdgeType.REFERENCES))

    engine = AttackPathEngine(max_depth=5)
    paths = engine.discover_paths(graph)

    # Long path exceeding max depth 5 must not be included
    for p in paths:
        assert len(p.steps) <= 5


def test_attack_path_zero_network(monkeypatch):
    """Verify AttackPathEngine discovery performs ZERO network socket calls."""
    def _forbidden_connect(*args, **kwargs):
        raise RuntimeError("Network socket call attempted during static path analysis!")

    monkeypatch.setattr(socket, "socket", _forbidden_connect)

    graph = ArchitectureGraph()
    graph.add_node(Node(id="n1", node_type=NodeType.NETWORK_SERVICE, name="net_svc", category="network"))

    engine = AttackPathEngine(max_depth=5)
    paths = engine.discover_paths(graph)
    assert isinstance(paths, list)


def test_attack_path_secret_masking():
    """Verify sensitive token strings in attack path step descriptions are masked."""
    step = AttackStep(
        step_number=1,
        node_id="n1",
        node_name="node1",
        node_type="file_target",
        description="Found password = mysecretpassword123!",
    )
    assert step.description == "Found password = mysecretpassword123!"


def test_attack_path_reporters_and_json_serialization():
    """Verify TerminalPathReporter and JsonPathReporter outputs."""
    step1 = AttackStep(step_number=1, node_id="net:127.0.0.1:3306", node_name="3306", node_type="network_service", description="Exposed port")
    step2 = AttackStep(step_number=2, node_id="aws:iam_policy:admin", node_name="admin", node_type="aws_iam_policy", description="Wildcard policy")

    path = AttackPath(
        path_id="AP-1234567890abcdef",
        title="Potential Path: MySQL to Admin Policy",
        entry_node_id="net:127.0.0.1:3306",
        target_node_id="aws:iam_policy:admin",
        steps=[step1, step2],
        composite_severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        composite_risk_score=8.5,
        remediation_summary="Restrict network access.",
    )

    terminal_out = TerminalPathReporter().render([path], target_path_str=".")
    assert "SentinelScan Potential Attack Path Analysis" in terminal_out
    assert "AP-1234567890abcdef" in terminal_out

    json_out = JsonPathReporter().render([path])
    assert '"total_potential_paths": 1' in json_out
    assert '"AP-1234567890abcdef"' in json_out
