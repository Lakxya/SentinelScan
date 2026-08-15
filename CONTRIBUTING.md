# Contributing to SentinelScan 🤝

Thank you for your interest in contributing to **SentinelScan**! We welcome contributions from security engineers, developers, and open-source enthusiasts.

This guide provides instructions for setting up your development environment, running tests, linting, adding new scanner modules, and submitting pull requests.

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
pytest
```

To run with verbose coverage output:
```bash
pytest -v
```

### Run Linting & Formatting Checks
We use **Ruff** for fast linting and code formatting checks.

```bash
# Check code style and common errors
ruff check .

# Automatically fix auto-fixable lint issues
ruff check --fix .

# Check formatting
ruff format --check .
```

### Run Type Checking
We use **mypy** for strict static type verification.

```bash
mypy src/sentinelscan
```

---

## 🔌 3. Adding a New Scanner Module

SentinelScan is designed to make adding scanner modules straightforward.

### Guidelines for New Scanners
1. **Inherit from `BaseScanner`**: Located in `sentinelscan.scanners.base`.
2. **Implement Required Properties**:
   - `name`: Lowercase string identifier (e.g. `python-sast`, `tf-sec-checker`).
   - `category`: Select appropriate `Category` enum (`Category.SAST`, `Category.SECRET`, `Category.IAC`, etc.).
   - `description`: Human-readable summary of checks.
3. **Implement `is_available(target: Target) -> bool`**: Return `False` if required tools or file types are missing.
4. **Implement `scan(target: Target) -> list[Finding]`**: Perform assessment and return normalized `Finding` objects.
5. **Never Store Raw Secrets**: Never include actual secret credentials or private key content in descriptions, titles, or metadata.
6. **No Raw Code Snippets**: Populate `Location(file_path=path, start_line=line)` without attaching raw source code snippets.

Reference Example: Check `examples/mock_scanner.py` for a working implementation example.

---

## 🔒 4. Security Principles & Guidelines

When contributing code to SentinelScan:
- **Never hardcode secrets**: Do not commit API keys, tokens, or sample credentials into tests or source files.
- **Safe Defaults**: All operations must operate safely on local environments without modifying target files.
- **Isolated Execution**: Ensure scanner logic catches domain-specific errors gracefully and does not rely on global mutable state.

---

## 📝 5. Commit & Pull Request Guidelines

1. **Create a Feature Branch**:
   ```bash
   git checkout -b feature/add-secret-scanner
   ```
2. **Write Meaningful Commit Messages**:
   - `feat(scanners): add initial high-entropy secret scanner module`
   - `fix(cli): resolve exit code handling for invalid target paths`
   - `test(reporting): add unit test for JSON credential sanitization`
3. **Run Full Verification Before Pushing**:
   ```bash
   pytest && ruff check . && mypy src/sentinelscan
   ```
4. **Open a Pull Request**: Provide a clear description of changes, motivation, and verification steps.
