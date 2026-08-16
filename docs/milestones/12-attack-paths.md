# Milestone 12 - Attack-Path & Risk Correlation

- **Status**: `COMPLETED`
- **Release Version**: `v1.2.0`
- **Focus**: Analytical Attack-Path & Risk Correlation engine (`AttackPathEngine`) discovering potential multi-step risk chains (e.g. Exposed Network Service $\rightarrow$ Plaintext K8s Secret $\rightarrow$ Wildcard AWS IAM Role) across `ArchitectureGraph` assets and scanner findings.

---

## 🎯 1. Goals

Implement a production-oriented Attack-Path & Risk Correlation engine (`AttackPathEngine`) that correlates findings across all 9 security domains and `ArchitectureGraph` relationships into potential attack paths (`AttackPath`), incorporating explicit confidence ratings (`LOW`, `MEDIUM`, `HIGH`), max traversal depth bounds of 5 hops, non-assertive path terminology, and terminal ASCII tree rendering (`sentinelscan paths <path>`) and JSON output (`--json`), while preserving all 100% offline, read-only, and secret-masking commitments.

---

## 🛠️ 2. Actual Capabilities Implemented

### 2.1 Non-Assertive Potential Path Data Models (`src/sentinelscan/models/attack_path.py`)
- **`AttackStep`**: Represents an individual step in a chain (`step_number`, `node_id`, `node_name`, `node_type`, `description`, `finding_fingerprint`, `rule_id`, `severity`).
- **`AttackPath`**: Dataclass representing a potential attack chain (`path_id`, `title`, `entry_node_id`, `target_node_id`, `steps`, `composite_severity`, `confidence`, `composite_risk_score`, `remediation_summary`). Uses deterministic 16-character SHA-256 fingerprints (`AP-<hash>`).

### 2.2 Graph Traversal & Risk Correlation Engine (`src/sentinelscan/core/attack_path_engine.py`)
- **Depth-Bounded Traversal (Max Depth 5)**: Enforces `max_depth = 5` hops to prevent speculatively long paths or graph cycles.
- **Entry & Target Identification**: Discovers entry nodes (`NETWORK_SERVICE`, `DOCKER_IMAGE`, public S3 buckets, unauthenticated DAST endpoints) and high-impact target nodes (`K8S_SECRET`, wildcard IAM policies).
- **Composite Risk & Confidence Scoring**: Calculates composite risk score (0.0 to 10.0 scale) and confidence rating (`LOW`, `MEDIUM`, `HIGH`).
- **Path Deduplication**: Prunes redundant sub-paths via deterministic path hash matching.
- **Secret Masking**: Sanitizes finding descriptions in step metadata via `mask_token()`.

### 2.3 Terminal & JSON Path Reporters (`src/sentinelscan/reporting/path_reporter.py`)
- **`TerminalPathReporter`**: Formats potential attack paths into clean CLI text trees.
- **`JsonPathReporter`**: Outputs machine-readable JSON representation.

### 2.4 Security & Privacy Safeguards
- **Terminal CLI Exclusivity**: SentinelScan is strictly a terminal CLI tool. Zero web interfaces or dashboards.
- **100% Offline Static Traversal**: `sentinelscan scan .` and `sentinelscan paths .` perform **zero network socket calls**.
- **Zero Subprocess Execution**: Never executes external scanner tools or binaries.
- **Zero Exploitation**: Analytical graph traversal. Never sends attack payloads, SQL injection vectors, or brute-force passwords.
- **Secret Value Masking**: Sensitive finding strings are sanitized via `mask_token()`.

---

## 📁 3. Files Created & Modified

- `src/sentinelscan/models/attack_path.py` (New `AttackStep` and `AttackPath` models with `confidence` attribute)
- `src/sentinelscan/core/attack_path_engine.py` (New `AttackPathEngine` graph traversal & risk correlator with max depth 5 bound)
- `src/sentinelscan/reporting/path_reporter.py` (New `TerminalPathReporter` and `JsonPathReporter`)
- `tests/unit/test_attack_path_engine.py` (New test suite covering entry/target discovery, max depth 5 BFS traversal, confidence scoring, risk scoring, deduplication, secret masking, and JSON output)
- `docs/milestones/12-attack-paths.md` (New release document)
- `src/sentinelscan/models/__init__.py` (Exported attack path models)
- `src/sentinelscan/cli/commands.py` (Added `handle_paths()`)
- `src/sentinelscan/cli/main.py` (Added `paths` subcommand parser)
- `src/sentinelscan/cli/__init__.py` (Exported `handle_paths`)
- `tests/unit/test_cli.py` (Added `test_cli_paths_command`)
- `README.md`, `IMPLEMENTATION.md`, `CONTRIBUTING.md`, `docs/ROADMAP.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY_PRINCIPLES.md` (Updated documentation)

---

## 4. Test & Verification Results

- **`pytest`**: **106 passing tests** (4.58s).
- **`ruff check .`**: All checks passed cleanly (**0 errors**).
- **`mypy src/sentinelscan`**: Success with **0 type issues** across 35 source files.
- **Manual Verification**: Executed `sentinelscan paths .`, `sentinelscan paths . --json`, `sentinelscan scan .`.

---

## 5. Known Limitations at Milestone 12 Completion

- `AttackPathEngine` performs analytical graph traversal across static code ASTs, manifest relationships, and scanner findings. It identifies potential correlated risk paths and does not claim exploitability or perform dynamic runtime exploitation.
