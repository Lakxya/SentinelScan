# SentinelScan - Technical Implementation & Architecture Guide

This document provides a comprehensive technical overview of **SentinelScan**, its current baseline architecture, data models, scanner isolation model, CLI control flow, and developer guide for extending the codebase with new security scanner modules.

---

## 🌐 1. Project Vision

SentinelScan is envisioned as an open-source, local-first security engineering CLI. It bridges static application security, infrastructure assessment, software supply chain checks, cloud posture analysis, and attack-path risk correlation into a single, cohesive developer-first tool.

### Core Security & Architectural Principles
1. **Local-First & Safe Defaults**: All processing occurs locally. Cloud assessments are read-only by default. Active dynamic testing requires explicit user authorization.
2. **Credential Safety**: Secret values, tokens, or private keys must never be logged, printed, or saved in finding artifacts or console reports.
3. **No Raw Code Snippets**: The `Location` model records only file paths and line numbers (`start_line`, `end_line`), avoiding raw source snippet storage to prevent accidental data leaks.
4. **Scanner Failure Isolation**: Scanners run inside exception boundaries. An unexpected failure in one scanner module records a `FAILED` status but **never terminates** the overall scan execution.
5. **Correlation Readiness**: Every `Finding` includes a deterministic fingerprint (`FS-<hash>`), resource target identifier, and tags to allow future attack-path correlation without requiring model rewrites.
6. **No Fake Findings**: The baseline architecture provides pure infrastructure and models without placeholder security findings.

---

## 📁 2. Repository Structure

```
SentinelScan/
├── src/
│   └── sentinelscan/
│       ├── __init__.py            # Root package exports
│       ├── cli/
│       │   ├── __init__.py
│       │   ├── main.py            # Argparse entrypoint and main() execution
│       │   └── commands.py        # Handlers for 'scan' and 'version'
│       ├── core/
│       │   ├── __init__.py
│       │   ├── discovery.py       # ProjectDiscoverer (path validation & tech detection)
│       │   ├── engine.py          # ScanEngine (scanner execution & fault isolation)
│       │   └── exceptions.py      # SentinelScan exception hierarchy
│       ├── scanners/
│       │   ├── __init__.py
│       │   ├── base.py            # Abstract BaseScanner interface
│       │   └── registry.py        # Synchronous ScannerRegistry
│       ├── models/
│       │   ├── __init__.py
│       │   ├── finding.py         # Category, Severity, Confidence, Location, Finding
│       │   ├── target.py          # Target metadata model
│       │   └── result.py          # ScannerExecutionResult, ScanResult
│       ├── reporting/
│       │   ├── __init__.py
│       │   ├── base.py            # BaseReporter interface
│       │   ├── console.py         # Formatted terminal ConsoleReporter
│       │   └── json.py            # Machine-readable JsonReporter & redaction
│       └── utils/
│           ├── __init__.py
│           └── logging.py         # Structured logging configuration
│
├── tests/
│   ├── unit/                      # Fast isolated unit tests
│   │   ├── test_cli.py
│   │   ├── test_discovery.py
│   │   ├── test_engine.py
│   │   ├── test_models.py
│   │   ├── test_scanners.py
│   │   └── test_reporting.py
│   └── integration/               # End-to-end pipeline integration tests
│       └── test_scan_flow.py
│
├── docs/                          # Project documentation
├── examples/                      # Contributor examples
│   └── mock_scanner.py            # Reference scanner extension example
├── pyproject.toml                 # Packaging & setuptools build config
├── README.md                      # Project overview & roadmap
├── CONTRIBUTING.md                # Development setup & contributor workflow
├── IMPLEMENTATION.md              # Technical architecture documentation
├── LICENSE                        # MIT License
└── .gitignore                     # Git ignore rules
```

---

## 🧬 3. Core Models & Abstractions

### 3.1 Finding Model (`src/sentinelscan/models/finding.py`)
The `Finding` class normalizes security discoveries across all security domains:

- `scanner`: String identifier of the originating scanner.
- `category`: Domain enum (`SAST`, `SCA`, `DAST`, `SECRET`, `CONTAINER`, `KUBERNETES`, `IAC`, `CLOUD`, `NETWORK`, `ARCHITECTURE`).
- `rule_id`: Identifier for the triggered security rule.
- `title`: Short title of the vulnerability or misconfiguration.
- `severity`: Standardized rating (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
- `confidence`: Confidence level (`HIGH`, `MEDIUM`, `LOW`).
- `description`: Technical explanation of the issue.
- `impact`: Potential security risk or exposure impact.
- `remediation`: Clear, actionable steps to fix the issue.
- `location`: Optional `Location` instance (`file_path`, `start_line`, `end_line`).
- `resource_id`: String identifier for target resources (e.g. AWS ARN, container image name, host:port).
- `tags`: List of classification keywords.
- `related_finding_ids`: List of finding IDs linked for future attack-path graph correlation.
- `fingerprint`: 16-character SHA-256 hash computed deterministically from `scanner`, `rule_id`, `location`, `resource_id`, and `title`.
- `finding_id`: Formatted identifier (`FS-<fingerprint>`).

### 3.2 Target Model (`src/sentinelscan/models/target.py`)
`Target` encapsulates discovered information about the scan subject:
- Path details (`path`, `is_directory`, `is_file`, `is_git_repo`).
- Content size and file count.
- `detected_indicators`: List of detected tech frameworks (`python`, `javascript`, `docker`, `kubernetes`, `iac-terraform`, `aws-cloud`).

### 3.3 Scan Execution Result (`src/sentinelscan/models/result.py`)
`ScanResult` separates finding count from scanner health status:

- `ScannerExecutionStatus`: Enum with values `SUCCESS`, `UNAVAILABLE`, `FAILED`, `SKIPPED`.
- `ScannerExecutionResult`: Contains `scanner_name`, `status`, `finding_count`, `error_message`, and `duration_seconds`.
- **Key Guarantee**: A scanner returning 0 findings is marked as `SUCCESS` with `finding_count=0`. A scanner throwing an unhandled exception is marked as `FAILED` with `error_message`.

---

## ⚙️ 4. Scanner Abstraction & Registry

### 4.1 BaseScanner Interface (`src/sentinelscan/scanners/base.py`)
All scanner modules inherit from `BaseScanner`:

```python
from abc import ABC, abstractmethod
from sentinelscan.models.finding import Category, Finding
from sentinelscan.models.target import Target

class BaseScanner(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for scanner."""
        pass

    @property
    @abstractmethod
    def category(self) -> Category:
        """Category domain."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Description of checks."""
        pass

    def is_available(self, target: Target) -> bool:
        """Return True if target contains required files or prerequisites."""
        return True

    @abstractmethod
    def scan(self, target: Target) -> list[Finding]:
        """Execute scan and return findings."""
        pass
```

### 4.2 Simple ScannerRegistry (`src/sentinelscan/scanners/registry.py`)
In accordance with design requirements, `ScannerRegistry` is kept synchronous, lightweight, and simple for the initial milestone. It provides:
- `register(scanner: BaseScanner)`: Registers a scanner instance, raising `ScannerAlreadyRegisteredError` if duplicate names exist.
- `get(name: str)`: Looks up a scanner by name, raising `ScannerNotFoundError` if missing.
- `list_all()`: Returns registered scanners list.

---

## 🛠️ 5. Step-by-Step: Adding a New Scanner Module

To add a new scanner module (for example, a custom Secret detector):

1. **Create scanner file**: Add a new file under `src/sentinelscan/scanners/` (e.g., `secret_scanner.py`).
2. **Implement BaseScanner**:
   ```python
   from sentinelscan.models.finding import Category, Confidence, Finding, Location, Severity
   from sentinelscan.models.target import Target
   from sentinelscan.scanners.base import BaseScanner

   class SecretScanner(BaseScanner):
       @property
       def name(self) -> str:
           return "secret-detector"

       @property
       def category(self) -> Category:
           return Category.SECRET

       @property
       def description(self) -> str:
           return "Scans files for embedded high-entropy tokens."

       def is_available(self, target: Target) -> bool:
           return target.file_count > 0

       def scan(self, target: Target) -> list[Finding]:
           findings = []
           # Implement inspection logic safely without capturing raw secret values in finding output
           return findings
   ```
3. **Register scanner**: Register your scanner class with `ScannerRegistry` during initialization or plugin loading.
4. **Write unit tests**: Add unit tests under `tests/unit/` verifying `is_available()` behavior, finding generation, and error resilience.

---

## 🔬 6. Testing Strategy

The test suite is built using `pytest` and structured into unit and integration tiers:

- **Unit Tests (`tests/unit/`)**:
  - `test_cli.py`: Parser option parsing, version output, exit code 1 on non-existent targets.
  - `test_discovery.py`: Target path verification, file vs directory classification, tech indicator recognition.
  - `test_engine.py`: Scanner failure isolation, execution timing, status classification.
  - `test_models.py`: Deterministic fingerprint computation, `Location` field constraints, zero findings vs failure distinction.
  - `test_scanners.py`: `ScannerRegistry` lifecycle and duplicate protection.
  - `test_reporting.py`: JSON format validation and recursive sensitive data sanitization (`sanitize_sensitive_data`).
- **Integration Tests (`tests/integration/`)**:
  - `test_scan_flow.py`: Complete pipeline execution from discovery through scanner execution to report output.

---

## 🎯 7. Current Limitations & Next Steps

### Current Limitations
- Security scanner modules (SAST, SCA, DAST, Secrets, Cloud, Container) are not populated yet; only infrastructure, interfaces, discovery, engine, models, and reporters are present.
- Output currently targets terminal console text and JSON; SARIF and HTML report renderers will be added in future milestones.

### Recommended Next Milestone (Milestone 2)
Implement the first active scanner modules:
1. **Secret & Credential Detection Module**: High-entropy token detection with regex rule engine and secret value masking.
2. **Basic SAST Scanner Module**: Python AST analysis for high-risk functions (e.g. `eval()`, `exec()`, `shell=True`).
