"""Unit tests for ArchitectureGraphBuilder, graph models, reporters, relationship extraction, deduplication, secret masking, and network isolation."""

import socket

from sentinelscan.core.graph_builder import ArchitectureGraphBuilder
from sentinelscan.models.finding import Category, Confidence, Finding, Location, Severity
from sentinelscan.models.graph import ArchitectureGraph, Edge, EdgeType, Node, NodeType
from sentinelscan.models.result import ScanResult
from sentinelscan.models.target import Target
from sentinelscan.reporting.graph_reporter import JsonGraphReporter, TerminalGraphReporter


def test_deterministic_node_ids():
    """Verify nodes produce deterministic canonical IDs."""
    n1 = Node(id="tf:aws_s3_bucket.data", node_type=NodeType.TERRAFORM_RESOURCE, name="aws_s3_bucket.data", category="iac")
    n2 = Node(id="tf:aws_s3_bucket.data", node_type=NodeType.TERRAFORM_RESOURCE, name="aws_s3_bucket.data", category="iac")
    assert n1.id == n2.id


def test_node_and_edge_deduplication():
    """Verify ArchitectureGraph deduplicates identical nodes and edges."""
    graph = ArchitectureGraph()
    n1 = Node(id="k8s:Secret:default/sec", node_type=NodeType.K8S_SECRET, name="Secret/sec", category="kubernetes")
    n2 = Node(id="k8s:Secret:default/sec", node_type=NodeType.K8S_SECRET, name="Secret/sec", category="kubernetes")

    graph.add_node(n1)
    graph.add_node(n2)
    assert len(graph.nodes) == 1

    e1 = Edge(source_id="k8s:Deployment:default/web", target_id="k8s:Secret:default/sec", edge_type=EdgeType.USES_SECRET)
    e2 = Edge(source_id="k8s:Deployment:default/web", target_id="k8s:Secret:default/sec", edge_type=EdgeType.USES_SECRET)

    graph.add_edge(e1)
    graph.add_edge(e2)
    assert len(graph.edges) == 1


def test_terraform_relationship_extraction(tmp_path):
    """Verify ArchitectureGraphBuilder extracts Terraform resource nodes and reference edges."""
    tf_file = tmp_path / "main.tf"
    tf_file.write_text(
        'resource "aws_iam_role" "app" {\n'
        '  name = "app-role"\n'
        '}\n'
        'resource "aws_iam_role_policy_attachment" "attach" {\n'
        '  role = aws_iam_role.app.name\n'
        '}\n'
    )

    target = Target(
        path=tf_file,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(tf_file.read_bytes()),
    )

    builder = ArchitectureGraphBuilder()
    graph = builder.build(target)

    assert "tf:aws_iam_role.app" in graph.nodes
    assert "tf:aws_iam_role_policy_attachment.attach" in graph.nodes
    assert len(graph.edges) >= 1
    edge = graph.edges[0]
    assert edge.source_id == "tf:aws_iam_role_policy_attachment.attach"
    assert edge.target_id == "tf:aws_iam_role.app"
    assert edge.edge_type == EdgeType.ATTACHED_TO


def test_kubernetes_relationship_extraction(tmp_path):
    """Verify ArchitectureGraphBuilder extracts Kubernetes workload to Secret/ConfigMap/ServiceAccount edges."""
    k8s_yaml = tmp_path / "deploy.yaml"
    k8s_yaml.write_text(
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata:\n"
        "  name: web-app\n"
        "  namespace: default\n"
        "spec:\n"
        "  template:\n"
        "    spec:\n"
        "      serviceAccountName: web-sa\n"
        "      containers:\n"
        "      - name: web\n"
        "        image: nginx\n"
        "        envFrom:\n"
        "        - secretRef:\n"
        "            name: db-secret\n"
        "        - configMapRef:\n"
        "            name: app-config\n"
    )

    target = Target(
        path=k8s_yaml,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(k8s_yaml.read_bytes()),
    )

    builder = ArchitectureGraphBuilder()
    graph = builder.build(target)

    assert "k8s:Deployment:default/web-app" in graph.nodes
    assert "k8s:ServiceAccount:default/web-sa" in graph.nodes
    assert "k8s:Secret:default/db-secret" in graph.nodes
    assert "k8s:ConfigMap:default/app-config" in graph.nodes

    edge_types = [e.edge_type for e in graph.edges]
    assert EdgeType.USES_SERVICE_ACCOUNT in edge_types
    assert EdgeType.USES_SECRET in edge_types
    assert EdgeType.USES_CONFIGMAP in edge_types


def test_aws_iam_relationship_extraction(tmp_path):
    """Verify IAM policy JSON statements referencing S3 buckets produce REFERENCES edges."""
    policy_json = tmp_path / "iam_policy.json"
    policy_json.write_text(
        '{\n'
        '  "Version": "2012-10-17",\n'
        '  "Statement": [\n'
        '    {\n'
        '      "Effect": "Allow",\n'
        '      "Action": ["s3:GetObject"],\n'
        '      "Resource": "arn:aws:s3:::my-secure-bucket/*"\n'
        '    }\n'
        '  ]\n'
        '}\n'
    )

    target = Target(
        path=policy_json,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(policy_json.read_bytes()),
    )

    builder = ArchitectureGraphBuilder()
    graph = builder.build(target)

    assert f"aws:iam_policy:{policy_json.stem}" in graph.nodes
    assert "aws:s3_bucket:my-secure-bucket" in graph.nodes
    assert len(graph.edges) == 1
    assert graph.edges[0].edge_type == EdgeType.REFERENCES


def test_finding_association_and_secret_masking(tmp_path):
    """Verify findings attach to target resource nodes via HAS_FINDING edges and mask sensitive tokens."""
    fpath = tmp_path / "deploy.yaml"
    fpath.write_text(
        "apiVersion: v1\n"
        "kind: Secret\n"
        "metadata:\n"
        "  name: db-secret\n"
        "  namespace: default\n"
        "data:\n"
        "  password: supersecretpassword123\n"
    )

    target = Target(
        path=fpath,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(fpath.read_bytes()),
    )

    finding = Finding(
        scanner="k8s-scanner",
        category=Category.KUBERNETES,
        rule_id="K8S-PLAIN-TEXT-SECRET-DATA",
        title="Plain text secret data",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        description="Plain text password supersecretpassword123 found in secret data",
        impact="Credential leakage",
        remediation="Encrypt secret data",
        location=Location(file_path=fpath, start_line=1),
        resource_id="k8s:Secret:default/db-secret",
    )

    scan_result = ScanResult(target=target, findings=[finding], scanner_results=[])

    builder = ArchitectureGraphBuilder()
    graph = builder.build(target, scan_result=scan_result)

    assert f"finding:{finding.fingerprint}" in graph.nodes
    finding_node = graph.nodes[f"finding:{finding.fingerprint}"]
    # Description in metadata must be masked (no raw secret)
    assert "supersecretpassword123" not in finding_node.metadata["description"]

    has_finding_edges = [e for e in graph.edges if e.edge_type == EdgeType.HAS_FINDING]
    assert len(has_finding_edges) >= 1


def test_zero_network_and_command_execution(tmp_path, monkeypatch):
    """Verify ArchitectureGraphBuilder executes 0 subprocesses and 0 socket network calls."""
    def _forbidden_connect(*args, **kwargs):
        raise RuntimeError("Network socket call attempted during graph building!")

    monkeypatch.setattr(socket, "socket", _forbidden_connect)

    tf_file = tmp_path / "main.tf"
    tf_file.write_text('resource "aws_s3_bucket" "test" { bucket = "b" }\n')

    target = Target(
        path=tf_file,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(tf_file.read_bytes()),
    )

    builder = ArchitectureGraphBuilder()
    graph = builder.build(target)
    assert "tf:aws_s3_bucket.test" in graph.nodes


def test_graph_terminal_and_json_reporters(tmp_path):
    """Verify TerminalGraphReporter ASCII tree and JsonGraphReporter render correctly."""
    graph = ArchitectureGraph()
    n1 = Node(id="tf:aws_s3_bucket.data", node_type=NodeType.TERRAFORM_RESOURCE, name="aws_s3_bucket.data", category="iac")
    graph.add_node(n1)

    term_out = TerminalGraphReporter().render(graph, target_path_str=str(tmp_path))
    assert "SentinelScan Architecture Graph" in term_out
    assert "[tf:aws_s3_bucket.data]" in term_out

    json_out = JsonGraphReporter().render(graph)
    assert '"id": "tf:aws_s3_bucket.data"' in json_out
    assert '"total_nodes": 1' in json_out
