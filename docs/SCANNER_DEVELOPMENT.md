# SentinelScan - Scanner Development Guide

This document is the definitive developer guide for creating, extending, testing, and registering new security scanner modules in SentinelScan.

---

## 🚀 1. The 13-Step Scanner Development Lifecycle

Follow these 13 steps sequentially when adding a new security scanner module:

```
 1. Create Module File
 2. Implement BaseScanner
 3. Define Category Domain
 4. Define Stable Rule IDs
 5. Register with ScannerRegistry
 6. Implement Detection Logic
 7. Produce Finding Objects
 8. Enforce Error Isolation
 9. Write Comprehensive Tests
10. Update Documentation
11. Run Toolchain Quality Checks
12. Review Security & Privacy Constraints
13. Commit Changes
```

---

## 📋 2. Step-by-Step Implementation Guide

### Step 1: Create Scanner Module File
Create a new Python module under `src/sentinelscan/scanners/` (e.g., `sast_scanner.py`).

### Step 2: Implement BaseScanner Interface
Inherit from `BaseScanner` (`src/sentinelscan/scanners/base.py`).

```python
from sentinelscan.models.finding import Category, Confidence, Finding, Location, Severity
from sentinelscan.models.target import Target
from sentinelscan.scanners.base import BaseScanner


class SastScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "sast-scanner"

    @property
    def category(self) -> Category:
        return Category.SAST

    @property
    def description(self) -> str:
        return "Static application security testing analyzer for high-risk code patterns."

    def is_available(self, target: Target) -> bool:
        return "python" in target.detected_indicators or target.is_file

    def scan(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        # Implement scanning logic
        return findings
```

### Step 3: Select Category Domain
Choose the appropriate `Category` enum value from `src/sentinelscan/models/finding.py`:
- `Category.SAST`
- `Category.SCA`
- `Category.DAST`
- `Category.SECRET`
- `Category.CONTAINER`
- `Category.KUBERNETES`
- `Category.IAC`
- `Category.CLOUD`
- `Category.NETWORK`
- `Category.ARCHITECTURE`

### Step 4: Define Stable & Deterministic Rule IDs
Establish rule ID conventions formatted as `<DOMAIN>-<SPECIFIC-CHECK>` (e.g. `SAST-PYTHON-EVAL`, `SECRET-AWS-ACCESS-KEY`, `CONTAINER-RUN-AS-ROOT`). Rule IDs must be deterministic and permanent across releases.

### Step 5: Register Scanner Module
Add scanner registration to `ScannerRegistry._register_defaults()` in `src/sentinelscan/scanners/registry.py`.

### Step 6: Implement Detection Logic
Parse files safely. Check file extensions, header bytes, and avoid scanning binary or large files.

### Step 7: Construct Normalized Finding Objects
Instantiate `Finding` objects with standard fields:
- `scanner`: `self.name`
- `category`: `self.category`
- `rule_id`: Stable rule ID
- `title`: Concise vulnerability title
- `severity`: `Severity.CRITICAL` | `HIGH` | `MEDIUM` | `LOW` | `INFO`
- `confidence`: `Confidence.HIGH` | `MEDIUM` | `LOW`
- `description`: Explanation of security issue
- `impact`: Exposure impact
- `remediation`: Actionable remediation instructions
- `location`: `Location(file_path=path, start_line=line_num, end_line=line_num)`

### Step 8: Enforce Error Isolation
Wrap individual detector loops or file inspections in `try ... except Exception as e:` so a single unhandled file error does not abort the entire scan.

### Step 9: Add Unit and Integration Tests
Add tests under `tests/unit/test_<scanner_name>.py`. Test positive detections, false-positive exclusions, binary file skipping, and error handling.

### Step 10: Update Documentation
Record the scanner in `README.md`, `IMPLEMENTATION.md`, `docs/ROADMAP.md`, and relevant milestone documents in `docs/milestones/`.

### Step 11: Run Toolchain Quality Checks
```bash
python -m pytest; python -m ruff check .; python -m mypy src/sentinelscan
```

### Step 12: Review Security & Privacy Constraints
- Confirm raw credentials or raw source snippets are NOT present in findings.
- Verify no network requests or remote API calls are executed.

### Step 13: Commit Changes
Commit with clean conventional commit message (e.g. `feat(scanners): add initial Python SAST scanner module`).

---

## ⚙️ 3. Core Rules for Scanner Authors

### False Positives
- Filter out common placeholders (`example`, `placeholder`, `123456`, `test`).
- When uncertain, lower the `Confidence` rating (`Confidence.LOW`) rather than generating aggressive `CRITICAL` findings.

### Severity & Confidence Matrix
- `CRITICAL`: High-impact active vulnerabilities (e.g. valid AWS keys, active private keys, remote code execution).
- `HIGH`: Major security issues (e.g. hardcoded API tokens, unencrypted storage).
- `MEDIUM`: Misconfigurations or risky practices (e.g. high-entropy generic variable assignments).
- `LOW` / `INFO`: Code quality or informational security hygiene.

### Performance & Filesystem Safety
- **Max File Size**: Skip files exceeding 5 MB (`MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024`).
- **Binary Check**: Skip files with null bytes `\x00` in initial 1024 header bytes.
- **Directory Exclusions**: Respect `EXCLUDED_DIRS` (`.git`, `.venv`, `node_modules`, `build`, etc.).
- **Symlinks**: Do not follow external symlinks (`follow_symlinks=False`).
