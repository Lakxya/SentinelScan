# SentinelScan - Technical Architecture Specification

This document details the actual, verified technical architecture implemented in SentinelScan (`v1.3.0`).

---

## 🏛️ 1. Architectural Overview

SentinelScan is built around a decoupled pipeline model where target discovery, scanner registration, security analysis, finding normalization, architecture graph construction, attack-path correlation, posture scoring, and reporting formatters operate as independent layers.

```
+-------------------------------------------------------------------+
|                            CLI Layer                              |
|   (sentinelscan scan | secrets | sast | iac | sca | docker | k8s  |
|    | aws | dast | graph | network | paths | posture)              |
+-------------------------------------------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
|                        Project Discoverer                         |
|      (Path Validation, Filesystem Metadata, Tech Indicators)       |
+-------------------------------------------------------------------+
                                  |
                                  v Target
+-------------------------------------------------------------------+
|                           Scan Engine                             |
|    (Queries ScannerRegistry & Enforces Fault Isolation for 9 Scanners)|
+-------------------------------------------------------------------+
                                  |
                                  v list[Finding]
+-------------------------------------------------------------------+
|                  ArchitectureGraphBuilder & Engine                |
|       (Constructs ArchitectureGraph & Discovers AttackPaths)      |
+-------------------------------------------------------------------+
                                  |
                                  v Graph + AttackPaths + Findings
+-------------------------------------------------------------------+
|                       Posture & Remediation Engine                |
|    - PostureEngine: Explainable scoring & domain breakdowns       |
|    - RemediationEngine: Deduplicated & prioritized fix advice     |
+-------------------------------------------------------------------+
                                  |
                                  v PostureScore + RemediationAdvice
+-------------------------------------------------------------------+
|                          Reporting Layer                          |
| (ConsoleReporter, JsonReporter, PathReporter, PostureReporter)    |
+-------------------------------------------------------------------+
```

---

## 🧩 2. Layer Specifications

### 2.1 CLI Layer (`src/sentinelscan/cli/`)
- `main.py`: Argument parser constructed using standard Python `argparse`. Subcommands include `scan`, `secrets`, `sast`, `iac`, `sca`, `docker`, `k8s`, `aws`, `dast`, `graph`, `network`, `paths`, and `posture`.
- `commands.py`: Orchestrates discovery, engine instantiation, reporter selection, and status exit code handling (`0` = success, `1` = user/path error, `2` = system error).

### 2.2 Project Discovery Layer (`src/sentinelscan/core/discovery.py`)
- `ProjectDiscoverer`: Inspects target file or directory paths.
- Computes file counts and total byte sizes while skipping ignored directories (`.git`, `.venv`, `node_modules`, `build`, etc.).
- Identifies technology indicators based on manifest files and extensions (`python`, `javascript`, `docker`, `kubernetes`, `iac-terraform`, `aws-cloud`).

### 2.3 Core Scan Engine & Isolation (`src/sentinelscan/core/engine.py`)
- `ScanEngine`: Queries `ScannerRegistry` for active scanners.
- Executes `is_available(target)` check per scanner.
- Wraps each scanner execution inside an exception boundary (`try ... except Exception`).
- **Scanner Failure Isolation**: An unhandled exception in one scanner module records `ScannerExecutionStatus.FAILED` with the error message and timing, while allowing remaining scanners to run safely.

### 2.4 Scanner Abstraction & Registry (`src/sentinelscan/scanners/`)
- `BaseScanner` (`base.py`): Abstract Base Class defining required properties (`name`, `category`, `description`) and methods (`is_available`, `scan`).
- `ScannerRegistry` (`registry.py`): Synchronous registry storing scanner instances. Automatically registers all 9 default security scanners: `SecretScanner`, `SastScanner`, `IacScanner`, `ScaScanner`, `DockerScanner`, `KubernetesScanner`, `AwsScanner`, `DastScanner`, `NetworkScanner`.

### 2.5 Architecture Graph & Relationship Mining (`src/sentinelscan/core/graph_builder.py`)
- `ArchitectureGraphBuilder`: Static AST and manifest parser discovering resource nodes (`NodeType`) and relationship edges (`EdgeType`) across Terraform dependencies, Kubernetes workloads to Secrets/ConfigMaps/ServiceAccounts, AWS IAM policies to S3 buckets, Docker base images, and scanner security findings.

### 2.6 Attack-Path & Risk Correlation Engine (`src/sentinelscan/core/attack_path_engine.py`)
- `AttackPathEngine`: BFS depth-bounded graph traversal engine discovering potential multi-step risk chains (max depth 5 hops) linking entry nodes to high-impact target assets with confidence ratings (`LOW`, `MEDIUM`, `HIGH`) and path hash deduplication (`AP-<hash>`).

### 2.7 Posture Scoring & Remediation Guidance Engine (`src/sentinelscan/core/posture_engine.py`)
- `PostureEngine`: Explainable security posture scoring engine calculating overall score (0-100 scale), letter grades (`A+` to `F`), domain score breakdowns, deduction traceability, and anti-double-counting caps.
- `RemediationEngine`: Deduplicates and prioritizes remediation advice across rule IDs and resource targets based on severity, confidence, affected location count, and attack-path involvement.

### 2.8 Data & Domain Models (`src/sentinelscan/models/`)
- `Location`: `file_path`, `start_line`, `end_line`. Intentionally omits raw source code snippets to prevent credential leaks.
- `Finding`: Unified dataclass containing `scanner`, `category`, `rule_id`, `title`, `severity`, `confidence`, `description`, `impact`, `remediation`, `location`, `resource_id`, `tags`, `related_finding_ids`, and `metadata`. Auto-computes 16-character SHA-256 `fingerprint` and deterministic `finding_id` (`FS-<hash>`).
- `ArchitectureGraph`, `Node`, `Edge`: Resource graph data models.
- `AttackStep`, `AttackPath`: Potential attack path data models.
- `DeductionTrace`, `DomainScore`, `RemediationAdvice`, `PostureScore`: Posture scoring data models.

### 2.9 Reporting Layer (`src/sentinelscan/reporting/`)
- `BaseReporter` (`base.py`): Abstract report formatter interface.
- `ConsoleReporter` (`console.py`): Formatted terminal output for general scans.
- `JsonReporter` (`json.py`): Formatted machine-readable JSON output for general scans.
- `TerminalGraphReporter` / `JsonGraphReporter` (`graph_reporter.py`): ASCII tree and JSON output for architecture graphs.
- `TerminalPathReporter` / `JsonPathReporter` (`path_reporter.py`): Terminal ASCII text trees and JSON output for potential attack paths.
- `TerminalPostureReporter` / `JsonPostureReporter` (`posture_reporter.py`): Terminal ASCII text trees and JSON output for posture scores and remediation reports.

---

## 🔒 3. Security Boundaries & Privacy Commitments

1. **Terminal CLI Exclusivity**: SentinelScan is strictly a terminal CLI tool. Zero web interfaces, dashboards, or web servers.
2. **100% Offline Static Default Scans**: Running `sentinelscan scan .`, `sentinelscan graph .`, `sentinelscan paths .`, or `sentinelscan posture .` performs 100% offline static analysis. Network sockets are **NEVER** accessed.
3. **Authorized Active Assessment**: Active network checks run **ONLY** when explicitly requested via `sentinelscan network <target-host>`. Performs single read-only stdlib TCP connect checks (`socket.create_connection`) with bounded timeouts (0.5s per port).
4. **Zero Subprocess Execution**: Uses stdlib `socket`, `ssl`, and AST parsers. Never runs `nmap`, `masscan`, `nc`, or external tools.
5. **Zero Raw Secret Leakage**: Secret values are strictly masked using `mask_token()` before constructing finding objects, path step metadata, or posture remediation summaries.
