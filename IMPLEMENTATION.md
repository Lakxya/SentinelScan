# SentinelScan - Technical Implementation & Architecture Guide

This document provides a comprehensive technical overview of **SentinelScan**, its baseline architecture, data models, scanner isolation model, CLI control flow, and technical breakdown of the **Secret & Credential Detection Scanner** (Milestone 1).

---

## 🌐 1. Project Vision

SentinelScan is an open-source, local-first security engineering CLI bridging static application security, infrastructure assessment, software supply chain checks, cloud posture analysis, and attack-path risk correlation into a single tool.

### Core Principles & Safety Guarantees
1. **Local-First Filesystem Assessment**: The `SecretScanner` performs local filesystem analysis and does not make external network requests or transmit discovered data. Future network-enabled scanners must use explicit authorization, least privilege, safe defaults, and documented network boundaries.

2. **Strict Credential Leak Prevention**: Raw secret values are **NEVER** stored in `Finding` objects, descriptions, impacts, remediations, metadata, `Location`, logs, exceptions, console reports, or JSON output. Discovered values are strictly masked.
3. **Location Snippet Safety**: `Location` records `file_path`, `start_line`, and `end_line` without raw source code snippets to avoid accidental data leakage.
4. **Detector & Scanner Isolation**: Scanners and detectors execute within exception boundaries. An unexpected failure in one detector logs a warning and permits remaining detectors to run without aborting the scan.
5. **Correlation Readiness**: Every `Finding` includes a deterministic fingerprint (`FS-<hash>`), resource target identifier, and tags for future attack-path correlation.

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
│       │   └── commands.py        # Handlers for 'scan', 'secrets', and 'version'
│       ├── core/
│       │   ├── __init__.py
│       │   ├── discovery.py       # ProjectDiscoverer (path validation & tech detection)
│       │   ├── engine.py          # ScanEngine (scanner execution & fault isolation)
│       │   └── exceptions.py      # SentinelScan exception hierarchy
│       ├── scanners/
│       │   ├── __init__.py
│       │   ├── base.py            # Abstract BaseScanner interface
│       │   ├── registry.py        # ScannerRegistry
│       │   └── secret_scanner.py  # SecretScanner module & detectors
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
│   │   ├── test_reporting.py
│   │   └── test_secret_scanner.py # Comprehensive SecretScanner test suite
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

## 🔒 3. Secret Scanner Technical Design (Milestone 1)

### 3.1 Detector Strategy & Rule Matrix
The `SecretScanner` module uses pre-compiled regular expressions and Shannon entropy analysis:

| Rule ID | Domain / Type | Pattern Strategy | Severity | Default Confidence |
| :--- | :--- | :--- | :--- | :--- |
| `SECRET-AWS-ACCESS-KEY` | AWS IAM | `(AKIA\|ASIA\|ABIA\|ACCA)[0-9A-Z]{16}` | `CRITICAL` | `HIGH` |
| `SECRET-AWS-SECRET-KEY` | AWS IAM | Variable assignment context (`AWS_SECRET_ACCESS_KEY`, etc.) + 40-char string | `CRITICAL` | `HIGH` |
| `SECRET-PRIVATE-KEY` | Cryptographic Keys | `-----BEGIN (?:RSA \|EC \|DSA \|OPENSSH )?PRIVATE KEY-----` | `CRITICAL` | `HIGH` |
| `SECRET-GITHUB-TOKEN` | GitHub Auth | `(ghp_\|gho_\|ghu_\|ghs_\|ghr_)[a-zA-Z0-9]{36}` or `github_pat_[a-zA-Z0-9_]{82}` | `CRITICAL` | `HIGH` |
| `SECRET-JWT` | Web Auth | `eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}` | `HIGH` | `HIGH` |
| `SECRET-API-KEY` | API Services | Service patterns (Slack `xox[baprs]-`, Stripe `sk_live_`, Google `AIzaSy`, SendGrid `SG.`) | `HIGH` | `HIGH` |
| `SECRET-DATABASE-CREDENTIAL` | Databases | URLs `(postgres\|mysql\|mongodb\|redis)://user:pass@host` | `CRITICAL` | `HIGH` |
| `SECRET-GENERIC` | Generic Secrets | Suspicious variable names (`API_KEY`, `SECRET`, `PASSWORD`) + string + Entropy $H \ge 3.6$ | `MEDIUM` | `MEDIUM` / `LOW` |

### 3.2 Shannon Entropy Calculation
Entropy is computed in bits per character:
$$H = -\sum_{i=1}^{N} P(x_i) \log_2 P(x_i)$$

High entropy is **never** used alone to generate `CRITICAL` findings. Instead, it serves as supporting evidence for generic secret variable assignments. Strings with entropy $H < 3.6$ or matching common placeholders (`example`, `placeholder`, `12345678`, `your_key_here`) are filtered out.

### 3.3 Credential Masking Engine
- **Short tokens (<= 8 chars)**: `raw[0] + "*" * (n-2) + raw[-1]` (e.g. `s***t`)
- **Medium tokens (9-16 chars)**: `raw[:2] + "*" * (n-4) + raw[-2:]`
- **Long tokens (> 16 chars)**: `raw[:4] + "*" * (n-8) + raw[-4:]` (e.g. `AKIA************CDEF`)
- **Database URLs**: Password portion replaced with `[REDACTED]` (e.g. `postgresql://user:[REDACTED]@localhost:5432/db`)
- **Private Keys**: Replaced with fixed string `"[PRIVATE KEY REDACTED]"`

### 3.4 Filesystem Safety & Performance Rules
- **Binary Exclusion**: Files with binary extensions (`.png`, `.jpg`, `.pdf`, `.exe`, `.pyc`, `.zip`, etc.) or containing null bytes `\x00` in the first 1024 bytes are skipped.
- **File Size Cap**: Files larger than 5 MB (`5 * 1024 * 1024` bytes) are skipped.
- **Directory Exclusions**: `.git`, `.venv`, `node_modules`, `build`, `dist`, `__pycache__`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `.sentinelscan` are excluded from recursive directory traversal.
- **Symlink Protection**: Traversal avoids external or broken symlinks (`follow_symlinks=False`).
- **Encoding Safety**: Text files are read with `errors="ignore"` to handle non-UTF-8 bytes without throwing unhandled exceptions.

---

## 🛠️ 4. CLI Commands & Execution Flow

SentinelScan provides two primary scan entrypoints:

1. **`sentinelscan scan <path>`**: Runs target discovery and executes all active registered scanners (including `SecretScanner`).
2. **`sentinelscan secrets <path>`**: Runs target discovery and executes dedicated `SecretScanner` analysis.

---

## 🔬 5. Testing Strategy

The test suite covers positive detections, false positive exclusions, filesystem edge cases, detector isolation, and automated secret leak prevention:

- `test_secret_scanner.py`:
  - `test_entropy_calculation`: Validates Shannon entropy values.
  - `test_mask_token_helper`: Verifies token masking outputs.
  - `test_aws_access_key_detection_and_leak_prevention`: Asserts raw secret values never appear in finding repr, description, impact, remediation, metadata, console output, or JSON.
  - `test_aws_secret_key_requires_context`: Verifies context requirements for AWS secret keys.
  - `test_private_key_safety`: Ensures PEM keys output fixed `[PRIVATE KEY REDACTED]`.
  - `test_database_url_credential_masking`: Verifies password stripping in database URLs.
  - `test_generic_secret_detection_and_placeholder_negative`: Verifies generic secret matching and placeholder filtering.
  - `test_filesystem_safety_binary_and_large_files`: Validates skipping of binary, large, and unreadable files.
  - `test_detector_isolation`: Proves failure in one detector function does not abort other detectors.

---

## 🎯 6. Next Steps

- **Milestone 2 (SAST / Static Code Analysis)**: Python AST static analyzer flagging dangerous functions (`eval()`, `exec()`, `shell=True`).
