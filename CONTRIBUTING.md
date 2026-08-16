# Contributing to SentinelScan 🤝

Thank you for your interest in contributing to **SentinelScan**! We welcome contributions from security engineers, developers, and open-source enthusiasts.

---

## 🛠️ 1. Local Development Setup

### Prerequisites
- **Python 3.11+**
- `git`
- `pip`

### Step 1: Clone Repository
```bash
git clone https://github.com/sentinelscan/sentinelscan.git
cd SentinelScan
```

### Step 2: Create a Virtual Environment
```bash
python -m venv .venv
# On macOS/Linux:
source .venv/bin/activate
# On Windows (PowerShell):
.venv\Scripts\Activate.ps1
```

### Step 3: Install in Editable Mode with Dev Dependencies
```bash
pip install -e ".[dev]"
```

---

## 🧪 2. Running Tests & Code Quality Checks

Before submitting code, ensure that all unit tests, linters, and type checkers pass cleanly.

### Run Unit and Integration Tests
```bash
python -m pytest
```

### Run Linting & Formatting Checks
```bash
python -m ruff check .
```

### Run Type Checking
```bash
python -m mypy src/sentinelscan
```

---

## 🔌 3. Adding New Secret Detectors

When adding a new secret detector to `src/sentinelscan/scanners/secret_scanner.py`:

1. **Add Detector Method**: Add a method `_detect_<secret_name>(self, line: str, line_num: int, fpath: Path, findings: list[Finding])`.
2. **Use Pre-compiled Regex**: Pre-compile patterns in `__init__`.
3. **Always Mask Secret Values**: Call `mask_token()` or substitute credentials with `[REDACTED]`. **NEVER store or pass raw secret strings to `Finding` constructors, descriptions, impacts, remediations, or metadata.**
4. **Register Method in `_analyze_line`**: Add your detector method to the `detectors` list in `_analyze_line()`.
5. **Add Automated Secret Leak Tests**: Write unit tests in `tests/unit/test_secret_scanner.py` explicitly asserting `assert raw_secret not in str(f.to_dict())` and `assert raw_secret not in json_output`.

---

## 🔍 4. Adding New SAST Rules

When adding a new Python SAST rule to `src/sentinelscan/scanners/sast_scanner.py`:

1. **Extend `PythonSecurityASTVisitor`**: Add inspection logic to AST visitor methods (`visit_Call`, `visit_Import`, `visit_Attribute`, etc.).
2. **Use Deterministic Rule IDs**: Format rule IDs as `SAST-PY-<CHECK-NAME>` (e.g. `SAST-PY-EVAL`, `SAST-PY-MD5`).
3. **Avoid Low-Value False Positives**: Do NOT flag benign functions or standard process executions without security concerns. Distinguish safe list arguments from shell execution (`shell=True`).
4. **Never Execute Target Code**: Parse trees structurally via `ast.parse()`. Never call, evaluate, or import target code.
5. **Add Comprehensive Unit Tests**: Write unit tests in `tests/unit/test_sast_scanner.py` including positive, negative, syntax error, and zero-execution tests.

---

## 🏗️ 5. Adding New IaC Rules

When adding a new IaC security rule to `src/sentinelscan/scanners/iac_scanner.py`:

1. **Target Resource Types**: Implement detection logic in `_analyze_tf_resource` (for Terraform) and `_analyze_cfn_resource` (for CloudFormation/SAM).
2. **Use Deterministic Rule IDs**: Format rule IDs as `IAC-AWS-<CHECK-NAME>` (e.g. `IAC-AWS-SG-OPEN-INGRESS`, `IAC-AWS-S3-PUBLIC-ACL`).
3. **Safe Parsing**: Rely on `python-hcl2` for `.tf` files and `CloudFormationSafeLoader` for `.yaml` files. Never attempt unsafe string splitting or regex parsing of complex structures.
4. **Set Appropriate Confidence**: Set `Confidence.HIGH` for literal values (e.g. `cidr_blocks = ["0.0.0.0/0"]`), and `Confidence.MEDIUM` if values are passed via variables.
5. **Add Comprehensive Unit Tests**: Write unit tests in `tests/unit/test_iac_scanner.py`.

---

## 🏗️ 6. Adding New SCA Parsers & Ecosystem Support

When extending `src/sentinelscan/scanners/sca_scanner.py` with new package ecosystem parsers:

1. **Zero Command Execution**: Never call package manager CLI binaries (`pip`, `npm`, `cargo`, `go`, `composer`). Parse lockfiles and manifest text using safe parsers (`json`, `tomllib`, `re`).
2. **Metadata Privacy**: Outbound vulnerability API queries must contain ONLY package names and version strings.
3. **Use OSV Two-Stage Lookup**: Query Stage 1 batch endpoint (`/v1/querybatch`) and Stage 2 advisory detail endpoint (`/v1/vulns/{id}`).
4. **Cache Index & Details**: Store query indexes and advisory objects in `OsvCacheManager` (`~/.sentinelscan/cache/osv/`).
5. **Support `--offline` Mode**: Respect `self.offline` flag and avoid socket calls when offline mode is enabled.
6. **Add Unit Tests**: Write unit tests in `tests/unit/test_sca_scanner.py`.

---

## 🏗️ 7. Adding New Docker Security Rules

When extending `src/sentinelscan/scanners/docker_scanner.py` with new Dockerfile rules:

1. **Zero Container Execution**: Never call `docker build`, `docker run`, `docker pull`, or Docker daemon APIs. Treat Dockerfiles purely as static text.
2. **Multi-Stage Build Awareness**: Runtime rules (`USER`, `HEALTHCHECK`) must evaluate ONLY the final stage (`max_stage_index`), ignoring intermediate builder stages.
3. **Digest Pinning**: Recognize immutable SHA256 image digests (`@sha256:`) as fully pinned base images.
4. **Mask Secret Values**: Never include raw secret values in findings constructed from `ENV` or `ARG` instructions. Use `mask_token()`.
5. **Add Unit Tests**: Write unit tests in `tests/unit/test_docker_scanner.py`.

---

## 🏗️ 8. Adding New Kubernetes Security Rules

When extending `src/sentinelscan/scanners/k8s_scanner.py` with new Kubernetes manifest rules:

1. **Zero Cluster Execution**: Never call `kubectl`, `helm`, `kustomize`, or Kubernetes API server endpoints. Treat manifests strictly as static YAML/JSON text.
2. **Workload Controller Navigation**: Extract Pod specs across all workload controllers using `K8sManifestParser.extract_pod_spec()` (`Pod`, `Deployment`, `StatefulSet`, `DaemonSet`, `ReplicaSet`, `Job`, `CronJob`).
3. **Pod Inheritance & Confidence Nuances**: Pod-level securityContext settings (e.g. `runAsNonRoot: true`) are inherited by containers. Set `Confidence.HIGH` for explicit `runAsUser: 0`/`runAsNonRoot: false` and `Confidence.MEDIUM` when defaulting.
4. **Mask Secret Values**: Never include raw secret values from ConfigMap or `Secret` manifests (`stringData`/`data`) in findings. Use `mask_token()`.
5. **Add Unit Tests**: Write unit tests in `tests/unit/test_k8s_scanner.py`.

---

## 🏗️ 9. Adding New AWS Security Rules

When extending `src/sentinelscan/scanners/aws_scanner.py` with new AWS posture rules:

1. **Zero AWS API & CLI Execution**: Never call AWS API endpoints or invoke `aws`, `cdk`, or `sam` CLI binaries. Treat policies strictly as static JSON/YAML text and INI configs.
2. **IAM Policy Structural Validation**: Validate presence of `Version` and `Statement` nodes before analyzing documents.
3. **Statement Object & List Support**: Handle `Statement` declared as a dictionary object or a list of dictionaries.
4. **Explicit `Effect: Deny` Exclusions**: Deny statements are explicit security enforcement boundaries and MUST NOT generate allow-based wildcard findings.
5. **Mask Secret Values**: Never include raw secret access keys from `.aws/credentials` or configuration files in findings. Use `mask_token()`.
6. **Add Unit Tests**: Write unit tests in `tests/unit/test_aws_scanner.py`.

---




- **Never commit real credentials**: Synthetic test credentials in unit tests must be non-operational example strings.
- **Detector Isolation**: Wrap individual detector execution so an exception in one detector does not abort other detectors or crash the scanner.
- **Safe Filesystem Access**: Honor file size caps (5 MB) and binary file checks.

---

## 📝 5. Commit & Pull Request Guidelines

1. **Create a Feature Branch**:
   ```bash
   git checkout -b feature/add-slack-webhook-detector
   ```
2. **Write Meaningful Commit Messages**:
   - `feat(secrets): add Slack webhook detector to SecretScanner`
   - `test(secrets): add automated secret leak prevention tests`
3. **Run Full Verification Before Pushing**:
   ```bash
   python -m pytest; python -m ruff check .; python -m mypy src/sentinelscan
   ```
4. **Open a Pull Request**: Provide a description of changes and verification results.
