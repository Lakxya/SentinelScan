# SentinelScan - Testing & Quality Assurance Guide

This document outlines the testing strategy, test suite structure, quality standards, and security leak verification procedures for SentinelScan.

---

## 🧪 1. Testing Commands

Run the full automated test suite using `pytest`:

```bash
python -m pytest
```

Run test suite with verbose output:

```bash
python -m pytest -v
```

Run code formatting and linting checks:

```bash
python -m ruff check .
```

Run static type checking:

```bash
python -m mypy src/sentinelscan
```

Run all quality checks in sequence:

```bash
python -m pytest; python -m ruff check .; python -m mypy src/sentinelscan
```

---

## 📁 2. Test Suite Structure

```
tests/
├── unit/
│   ├── test_cli.py            # CLI argument parsing, flags, and command handlers
│   ├── test_discovery.py       # Path validation, tech indicator detection
│   ├── test_engine.py          # ScanEngine, timing, and fault isolation
│   ├── test_models.py         # Location, Finding, Target, ScanResult
│   ├── test_reporting.py      # ConsoleReporter, JsonReporter, data sanitization
│   ├── test_scanners.py       # ScannerRegistry lifecycle
│   └── test_secret_scanner.py # SecretScanner rules, entropy, and leak prevention
└── integration/
    └── test_scan_flow.py      # End-to-end target discovery to report pipeline
```

---

## 🔒 3. Security-Sensitive Testing & Secret Leak Verification

When testing scanners (especially `SecretScanner` or future credential detectors):

### 1. Use Synthetic Non-Operational Credentials Only
Never commit real API keys, AWS credentials, or private keys. Always use synthetic test constants clearly identifiable as test data (e.g. `SYNTHETIC_AWS_KEY = "AKIA1234567890ABCDEF"`).

### 2. Mandatory Secret Leak Prevention Assertions
Every secret detection test MUST explicitly verify that the raw synthetic secret value does NOT appear anywhere in the generated output or data structures:

```python
# Assert raw secret is NOT in Finding fields
assert raw_secret not in finding.description
assert raw_secret not in finding.impact
assert raw_secret not in finding.remediation
assert raw_secret not in str(finding.metadata)
assert raw_secret not in repr(finding)

# Assert raw secret is NOT in rendered report outputs
console_output = ConsoleReporter().render(scan_result)
json_output = JsonReporter().render(scan_result)

assert raw_secret not in console_output
assert raw_secret not in json_output
```

---

## ✍️ 4. How to Write Tests for a New Scanner

When contributing a new scanner module, create a corresponding test file under `tests/unit/test_<scanner_name>.py`.

### Example Test Structure for a New Scanner Module

```python
"""Unit tests for SampleCustomScanner."""

from pathlib import Path
from sentinelscan.models.finding import Category, Severity
from sentinelscan.models.target import Target
from sentinelscan.scanners.registry import ScannerRegistry
from sentinelscan.scanners.sample_scanner import SampleCustomScanner


def test_sample_scanner_positive(tmp_path):
    """Verify scanner correctly identifies vulnerability pattern."""
    test_file = tmp_path / "app.py"
    test_file.write_text("eval(user_input)\n")

    scanner = SampleCustomScanner()
    target = Target(
        path=test_file,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(test_file.read_bytes()),
    )

    findings = scanner.scan(target)
    assert len(findings) == 1
    assert findings[0].rule_id == "SAST-EVAL"
    assert findings[0].category == Category.SAST
    assert findings[0].severity == Severity.HIGH


def test_sample_scanner_negative(tmp_path):
    """Verify scanner ignores benign code pattern."""
    test_file = tmp_path / "safe.py"
    test_file.write_text("print('hello world')\n")

    scanner = SampleCustomScanner()
    target = Target(
        path=test_file,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(test_file.read_bytes()),
    )

    findings = scanner.scan(target)
    assert len(findings) == 0
```

---

## 🚦 5. CI/CD Quality Expectations

Before pushing a pull request or creating a commit, ensure:
1. `pytest` executes 100% passing tests without errors.
2. `ruff check .` reports 0 warnings or errors.
3. `mypy src/sentinelscan` reports success with 0 type issues across all source files.
4. CLI commands (`sentinelscan scan .`, `sentinelscan secrets .`) run cleanly.
