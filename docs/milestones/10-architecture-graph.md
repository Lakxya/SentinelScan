# Milestone 10 - Architecture Graph Capability

- **Status**: `COMPLETED`
- **Release Version**: `v1.0.0`
- **Focus**: Building a local, read-only Architecture Graph capability (`ArchitectureGraphBuilder`) that discovers relationships between infrastructure (Terraform), cloud (AWS IAM/S3/KMS), containers (Docker), Kubernetes workloads, application configurations, and SentinelScan security findings.

---

## 🎯 1. Goals

Implement a terminal-friendly Architecture Graph module (`ArchitectureGraphBuilder`) that constructs an asset graph (`ArchitectureGraph`) containing deterministic nodes (`Node`) and directed relationship edges (`Edge`), links findings from existing scanners (`ScanResult.findings`), renders ASCII tree views in terminal (`sentinelscan graph <path>`) and machine-readable JSON (`--json`), while preserving all zero-network, zero-subprocess, read-only, and secret-masking commitments.

---

## 🛠️ 2. Actual Capabilities Implemented

### 2.1 Graph Data Model (`src/sentinelscan/models/graph.py`)
- **Node Model (`Node`)**: Stable deterministic IDs (e.g. `tf:aws_s3_bucket.prod_bucket`, `k8s:Deployment:default/web-deploy`, `aws:iam_policy:app_policy`, `docker:image:nginx:1.25`, `finding:<fingerprint>`).
- **Edge Model (`Edge`)**: Directed relationships (`REFERENCES`, `ATTACHED_TO`, `USES_SECRET`, `USES_CONFIGMAP`, `USES_SERVICE_ACCOUNT`, `EXPOSES`, `BUILDS_FROM`, `HAS_FINDING`).
- **ArchitectureGraph Container**: In-memory graph container with node/edge deduplication and dictionary serialization.

### 2.2 Relationship Extraction Engine (`src/sentinelscan/core/graph_builder.py`)
- **Terraform / IaC**: ${resource} references and policy attachment extraction.
- **Kubernetes Workloads**: Inspects `envFrom.secretRef`, `envFrom.configMapRef`, `serviceAccountName`, and `spec.selector`.
- **AWS IAM**: Policy JSON statement resource parsing linking policies to S3 buckets and KMS keys.
- **Docker**: Dockerfile base image dependency parsing (`FROM`).
- **Finding Association**: Consumes existing scanner findings and links `finding:<fingerprint>` nodes to resource nodes via `HAS_FINDING` edges.
- **Secret Value Masking**: Sanitizes sensitive finding metadata using `mask_token()`.

### 2.3 Terminal ASCII Tree & JSON Reporters (`src/sentinelscan/reporting/graph_reporter.py`)
- **`TerminalGraphReporter`**: Formats parent-child-grandchild relationships into clean ASCII trees.
- **`JsonGraphReporter`**: Outputs machine-readable JSON representation.

### 2.4 Security & Privacy Safeguards
- **Terminal CLI Exclusivity**: SentinelScan is strictly a terminal CLI tool. Zero web interfaces or dashboards.
- **Zero Socket Access**: 100% offline static graph construction.
- **Zero Subprocess Execution**: Never runs `terraform`, `kubectl`, `helm`, `docker`, or `aws`.
- **Zero Secret Exposure**: Secret values in finding metadata are masked via `mask_token()`.
- **Read-Only**: Target files and configurations are never modified.

---

## 📁 3. Files Created & Modified

- `src/sentinelscan/models/graph.py` (New `NodeType`, `EdgeType`, `Node`, `Edge`, `ArchitectureGraph` data models)
- `src/sentinelscan/core/graph_builder.py` (New `ArchitectureGraphBuilder` relationship discovery engine)
- `src/sentinelscan/reporting/graph_reporter.py` (New `TerminalGraphReporter` and `JsonGraphReporter`)
- `src/sentinelscan/models/__init__.py` (Exported graph models)
- `src/sentinelscan/cli/commands.py` (Added `handle_graph()`)
- `src/sentinelscan/cli/main.py` (Added `graph` subcommand parser)
- `src/sentinelscan/cli/__init__.py` (Exported `handle_graph`)
- `tests/unit/test_graph.py` (Unit test suite covering node IDs, deduplication, relationships, finding association, secret masking, zero-network assertions, and reporters)
- `tests/unit/test_cli.py` (Added CLI test for `graph` subcommand)
- `README.md`, `IMPLEMENTATION.md`, `CONTRIBUTING.md`, `docs/ROADMAP.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY_PRINCIPLES.md` (Updated documentation)

---

## 4. Test & Verification Results

- **`pytest`**: **98 passing tests** (2.01s).
- **`ruff check .`**: All checks passed cleanly (**0 errors**).
- **`mypy src/sentinelscan`**: Success with **0 type issues** across 32 source files.
- **Manual Verification**: Executed `sentinelscan graph .`, `sentinelscan graph . --json`, `sentinelscan scan .`.

---

## 5. Known Limitations at Milestone 10 Completion

- Relationship discovery is strictly deterministic based on local static code ASTs and manifest fields. It does not infer unstated dynamic runtime topologies or live network traffic.
