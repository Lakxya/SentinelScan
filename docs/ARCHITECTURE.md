# SentinelScan - Technical Architecture Specification

This document details the actual, verified technical architecture implemented in SentinelScan (`v0.2.0`).

---

## 🏛️ 1. Architectural Overview

SentinelScan is built around a decoupled pipeline model where target discovery, scanner registration, security analysis, finding normalization, and reporting formatters operate as independent layers.

```
+-------------------------------------------------------------------+
|                            CLI Layer                              |
|          (sentinelscan scan <path> | sentinelscan secrets <path>) |
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
|          (Queries ScannerRegistry & Enforces Fault Isolation)     |
+-------------------------------------------------------------------+
      |                           |                           |
      v                           v                           v
+--------------+           +--------------+           +--------------+
| BaseScanner  |           | SecretScanner|           | (Future      |
| Interface    |           | Module       |           | Scanners)    |
+--------------+           +--------------+           +--------------+
      |                           |                           |
      +---------------------------+---------------------------+
                                  |
                                  v list[Finding]
+-------------------------------------------------------------------+
|                          Scan Result                              |
|    (Target Info, Aggregated Findings, Per-Scanner Exec Status)    |
+-------------------------------------------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
|                          Reporting Layer                          |
|         (ConsoleReporter [Terminal] | JsonReporter [JSON])        |
+-------------------------------------------------------------------+
```

---

## 🧩 2. Layer Specifications

### 2.1 CLI Layer (`src/sentinelscan/cli/`)
- `main.py`: Argument parser constructed using standard Python `argparse`. Subcommands include `scan` and `secrets`.
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
- `ScannerRegistry` (`registry.py`): Synchronous registry storing scanner instances. Automatically registers `SecretScanner` by default (can be disabled via `register_defaults=False` for isolated tests).

### 2.5 Data & Domain Models (`src/sentinelscan/models/`)
- `Location`: `file_path`, `start_line`, `end_line`. Intentionally omits raw source code snippets to prevent credential leaks.
- `Finding`: Unified dataclass containing `scanner`, `category`, `rule_id`, `title`, `severity`, `confidence`, `description`, `impact`, `remediation`, `location`, `resource_id`, `tags`, `related_finding_ids`, and `metadata`. Auto-computes 16-character SHA-256 `fingerprint` and deterministic `finding_id` (`FS-<hash>`).
- `Target`: Metadata representation of the scan subject.
- `ScannerExecutionResult`: Captures individual scanner status (`SUCCESS`, `UNAVAILABLE`, `FAILED`, `SKIPPED`), finding count, duration, and error message.
- `ScanResult`: Container object aggregating target info, findings list, and scanner execution results.

### 2.6 Reporting Layer (`src/sentinelscan/reporting/`)
- `BaseReporter` (`base.py`): Abstract report formatter interface (`render(result: ScanResult) -> str`).
- `ConsoleReporter` (`console.py`): Formats clean terminal output with discovery metrics, scanner execution tags (`[OK]`, `[ERR]`, `[N/A]`), finding details, and execution timing.
- `JsonReporter` (`json.py`): Formats machine-readable JSON output and executes recursive data sanitization (`sanitize_sensitive_data`) to prevent raw credential leakage.

### 2.7 Exception Hierarchy (`src/sentinelscan/core/exceptions.py`)
```
SentinelScanError
 ├── InvalidTargetError
 │    └── TargetNotFoundError
 ├── ScannerError
 │    ├── ScannerAlreadyRegisteredError
 │    └── ScannerNotFoundError
 └── ReportGenerationError
```

---

## 🔌 3. How Future Scanners Plug In

Adding a new scanner module (e.g., SAST, SCA, Container, IaC, Cloud) does not require modifying core engine logic:

1. Create a new module class under `src/sentinelscan/scanners/` inheriting from `BaseScanner`.
2. Implement required properties (`name`, `category`, `description`) and method `scan(target: Target) -> list[Finding]`.
3. Register the scanner instance into `ScannerRegistry`.
4. `ScanEngine` will automatically discover, validate availability, execute, and aggregate findings from the new scanner.
