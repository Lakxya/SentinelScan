"""Unit tests for KubernetesScanner, K8sManifestParser, security rules, and CLI integration."""

from sentinelscan.models.finding import Category, Confidence, Severity
from sentinelscan.models.result import ScannerExecutionResult, ScannerExecutionStatus, ScanResult
from sentinelscan.models.target import Target
from sentinelscan.reporting.json import JsonReporter
from sentinelscan.scanners.k8s_scanner import K8sManifestParser, KubernetesScanner


def test_k8s_manifest_parser_multi_document_yaml(tmp_path):
    """Verify K8sManifestParser correctly parses multi-document YAML files separated by '---'."""
    manifest = tmp_path / "k8s-multi.yaml"
    manifest.write_text(
        "apiVersion: v1\n"
        "kind: Service\n"
        "metadata:\n"
        "  name: web-service\n"
        "spec:\n"
        "  ports:\n"
        "    - port: 80\n"
        "---\n"
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata:\n"
        "  name: web-deployment\n"
        "spec:\n"
        "  replicas: 2\n"
        "  template:\n"
        "    spec:\n"
        "      containers:\n"
        "        - name: web\n"
        "          image: nginx:1.25\n"
    )

    resources = K8sManifestParser.parse_file(manifest)
    assert len(resources) == 2

    assert resources[0].kind == "Service"
    assert resources[0].name == "web-service"
    assert resources[0].doc_index == 0

    assert resources[1].kind == "Deployment"
    assert resources[1].name == "web-deployment"
    assert resources[1].doc_index == 1


def test_k8s_positive_security_detections(tmp_path):
    """Verify KubernetesScanner positive detections for privileged container, host namespaces, and missing resource limits."""
    manifest = tmp_path / "pod-insecure.yaml"
    manifest.write_text(
        "apiVersion: v1\n"
        "kind: Pod\n"
        "metadata:\n"
        "  name: insecure-pod\n"
        "spec:\n"
        "  hostNetwork: true\n"
        "  containers:\n"
        "    - name: app\n"
        "      image: myapp:1.0\n"
        "      securityContext:\n"
        "        privileged: true\n"
    )

    scanner = KubernetesScanner()
    target = Target(
        path=manifest,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(manifest.read_bytes()),
    )

    findings = scanner.scan(target)
    rule_ids = [f.rule_id for f in findings]

    assert "K8S-PRIVILEGED-CONTAINER" in rule_ids
    assert "K8S-HOST-NAMESPACES" in rule_ids
    assert "K8S-MISSING-RESOURCE-LIMITS" in rule_ids
    assert "K8S-ALLOW-PRIVILEGE-ESCALATION" in rule_ids
    assert "K8S-ROOT-CONTAINER" in rule_ids

    priv_finding = next(f for f in findings if f.rule_id == "K8S-PRIVILEGED-CONTAINER")
    assert priv_finding.severity == Severity.CRITICAL
    assert priv_finding.confidence == Confidence.HIGH
    assert priv_finding.category == Category.KUBERNETES


def test_k8s_root_container_confidence_nuances(tmp_path):
    """Verify runAsUser: 0 produces Confidence.HIGH while unconfigured root produces Confidence.MEDIUM."""
    manifest = tmp_path / "pods-root.yaml"
    manifest.write_text(
        "apiVersion: v1\n"
        "kind: Pod\n"
        "metadata:\n"
        "  name: pod-explicit-root\n"
        "spec:\n"
        "  containers:\n"
        "    - name: c1\n"
        "      image: nginx\n"
        "      securityContext:\n"
        "        runAsUser: 0\n"
        "---\n"
        "apiVersion: v1\n"
        "kind: Pod\n"
        "metadata:\n"
        "  name: pod-unconfigured-root\n"
        "spec:\n"
        "  containers:\n"
        "    - name: c2\n"
        "      image: nginx\n"
    )

    scanner = KubernetesScanner()
    target = Target(
        path=manifest,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=2,
        total_size_bytes=len(manifest.read_bytes()),
    )

    findings = scanner.scan(target)
    root_findings = [f for f in findings if f.rule_id == "K8S-ROOT-CONTAINER"]
    assert len(root_findings) == 2

    explicit_root = next(f for f in root_findings if "c1" in f.title)
    assert explicit_root.confidence == Confidence.HIGH

    default_root = next(f for f in root_findings if "c2" in f.title)
    assert default_root.confidence == Confidence.MEDIUM


def test_k8s_workload_security_context_inheritance(tmp_path):
    """Verify Pod-level runAsNonRoot: true is inherited by containers across Deployments and CronJobs."""
    manifest = tmp_path / "deployment-inherited.yaml"
    manifest.write_text(
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata:\n"
        "  name: secure-deploy\n"
        "spec:\n"
        "  template:\n"
        "    spec:\n"
        "      securityContext:\n"
        "        runAsNonRoot: true\n"
        "        runAsUser: 10001\n"
        "      containers:\n"
        "        - name: app\n"
        "          image: myapp:1.0\n"
        "          securityContext:\n"
        "            allowPrivilegeEscalation: false\n"
        "          resources:\n"
        "            limits:\n"
        "              cpu: '1'\n"
        "              memory: 512Mi\n"
    )

    scanner = KubernetesScanner()
    target = Target(
        path=manifest,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(manifest.read_bytes()),
    )

    findings = scanner.scan(target)
    rule_ids = [f.rule_id for f in findings]

    assert "K8S-ROOT-CONTAINER" not in rule_ids
    assert "K8S-ALLOW-PRIVILEGE-ESCALATION" not in rule_ids
    assert len(findings) == 0


def test_k8s_rbac_unbounded_permissions_and_cluster_admin(tmp_path):
    """Verify RBAC detection of wildcard verbs/resources and cluster-admin role bindings."""
    manifest = tmp_path / "rbac.yaml"
    manifest.write_text(
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: ClusterRole\n"
        "metadata:\n"
        "  name: superuser-role\n"
        "rules:\n"
        "  - apiGroups: ['*']\n"
        "    resources: ['*']\n"
        "    verbs: ['*']\n"
        "---\n"
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: ClusterRoleBinding\n"
        "metadata:\n"
        "  name: admin-binding\n"
        "roleRef:\n"
        "  apiGroup: rbac.authorization.k8s.io\n"
        "  kind: ClusterRole\n"
        "  name: cluster-admin\n"
        "subjects:\n"
        "  - kind: ServiceAccount\n"
        "    name: default\n"
        "    namespace: default\n"
    )

    scanner = KubernetesScanner()
    target = Target(
        path=manifest,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=2,
        total_size_bytes=len(manifest.read_bytes()),
    )

    findings = scanner.scan(target)
    rbac_findings = [f for f in findings if f.rule_id == "K8S-UNBOUNDED-RBAC-CLUSTER-ADMIN"]
    assert len(rbac_findings) == 2


def test_k8s_configmap_and_secret_masking(tmp_path):
    """Verify ConfigMap embedded secrets and Secret manifest stringData/data are masked."""
    manifest = tmp_path / "secrets-cm.yaml"
    manifest.write_text(
        "apiVersion: v1\n"
        "kind: ConfigMap\n"
        "metadata:\n"
        "  name: app-config\n"
        "data:\n"
        "  AWS_SECRET_ACCESS_KEY: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "---\n"
        "apiVersion: v1\n"
        "kind: Secret\n"
        "metadata:\n"
        "  name: db-secret\n"
        "stringData:\n"
        "  DB_PASSWORD: supersecretpassword123!\n"
    )

    scanner = KubernetesScanner()
    target = Target(
        path=manifest,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=2,
        total_size_bytes=len(manifest.read_bytes()),
    )

    findings = scanner.scan(target)

    cm_finding = next(f for f in findings if f.rule_id == "K8S-SECRET-IN-CONFIGMAP")
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in cm_finding.description
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in str(cm_finding.metadata)

    sec_finding = next(f for f in findings if f.rule_id == "K8S-PLAIN-TEXT-SECRET-DATA")
    assert "supersecretpassword123!" not in sec_finding.description
    assert "supersecretpassword123!" not in str(sec_finding.metadata)


def test_k8s_non_k8s_yaml_ignored(tmp_path):
    """Verify non-Kubernetes YAML files (CI pipelines, Docker Compose) are ignored safely."""
    manifest = tmp_path / "ci-pipeline.yaml"
    manifest.write_text(
        "name: CI Pipeline\n"
        "on: [push]\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v3\n"
    )

    scanner = KubernetesScanner()
    target = Target(
        path=manifest,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(manifest.read_bytes()),
    )

    findings = scanner.scan(target)
    assert len(findings) == 0


def test_k8s_json_serialization(tmp_path):
    """Verify Kubernetes findings serialize cleanly to structured JSON format."""
    manifest = tmp_path / "pod.json"
    manifest.write_text(
        '{\n'
        '  "apiVersion": "v1",\n'
        '  "kind": "Pod",\n'
        '  "metadata": { "name": "insecure-pod" },\n'
        '  "spec": {\n'
        '    "containers": [{ "name": "app", "image": "nginx" }]\n'
        '  }\n'
        '}\n'
    )

    scanner = KubernetesScanner()
    target = Target(
        path=manifest,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(manifest.read_bytes()),
    )

    findings = scanner.scan(target)
    assert len(findings) >= 1

    res = ScanResult(
        target=target,
        findings=findings,
        scanner_results=[
            ScannerExecutionResult(scanner_name="k8s-scanner", status=ScannerExecutionStatus.SUCCESS)
        ],
    )
    json_out = JsonReporter().render(res)
    assert '"category": "kubernetes"' in json_out
    assert '"rule_id": "K8S-ROOT-CONTAINER"' in json_out
