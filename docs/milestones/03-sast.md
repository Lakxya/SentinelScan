# Milestone 03 - Static Application Security Testing (SAST) Scanner

- **Status**: `COMPLETED`
- **Release Version**: `v0.3.0`
- **Focus**: Building a local-first Python SAST analyzer using AST parsing, structural node inspection, 8 deterministic security rules, strict UTF-8 decoding, zero code execution guarantees, and `sentinelscan sast` CLI command.

---

## 🎯 1. Goals

Implement a static code analysis scanner (`SastScanner`) integrating into SentinelScan's `BaseScanner` interface, inspecting Python AST trees without executing, evaluating, calling, or importing target source code.

---

## 🛠️ 2. Actual Capabilities Implemented

### 2.1 Implemented Detectors & Rule IDs
1. **Dynamic Code Execution (`eval()`)** (`SAST-PY-EVAL`): Detects `eval(...)` call nodes (`CRITICAL`, `HIGH`).
2. **Dynamic Code Execution (`exec()`)** (`SAST-PY-EXEC`): Detects `exec(...)` call nodes (`CRITICAL`, `HIGH`).
3. **Shell Command Execution (`shell=True`)** (`SAST-PY-SHELL-TRUE`): Detects `subprocess.*(..., shell=True)` call nodes (`HIGH`, `HIGH`).
4. **Command Execution (`os.system()`)** (`SAST-PY-OS-SYSTEM`): Detects `os.system(...)` call nodes (`HIGH`, `MEDIUM`).
5. **Unsafe Deserialization (`pickle.load()`)** (`SAST-PY-PICKLE-LOAD`): Detects `pickle.load(...)` call nodes (`HIGH`, `HIGH`).
6. **Unsafe Deserialization (`pickle.loads()`)** (`SAST-PY-PICKLE-LOADS`): Detects `pickle.loads(...)` call nodes (`HIGH`, `HIGH`).
7. **Weak Cryptographic Hash (`MD5`)** (`SAST-PY-MD5`): Detects `hashlib.md5(...)` call nodes (`MEDIUM`, `HIGH`).
8. **Weak Cryptographic Hash (`SHA-1`)** (`SAST-PY-SHA1`): Detects `hashlib.sha1(...)` call nodes (`MEDIUM`, `HIGH`).

*Note: Ordinary `subprocess.run(["ls", "-la"])` calls without `shell=True` produce zero findings to eliminate false positives.*

### 2.2 Security & Safety Principles Implemented
- **Zero Code Execution**: Code is parsed into abstract syntax trees using Python's standard-library `ast.parse()`. Target code is **NEVER** imported, evaluated, or executed.
- **Strict Decoding Policy**: Python source files are decoded strictly (`errors="strict"`). If `UnicodeDecodeError` occurs, a non-sensitive diagnostic warning is logged and the file is safely skipped without mangling source bytes.
- **Filesystem Safety Rules**: Binary files (null byte `\x00` check), files > 5 MB, excluded build/VCS directories, and external symlinks are automatically skipped.
- **Location Snippet Safety**: `Location` records `file_path`, `start_line`, and `end_line` without emitting raw source code snippets.

### 2.3 CLI Integration
- `SastScanner` registered in `ScannerRegistry` by default (`sentinelscan scan .` automatically runs SAST alongside `SecretScanner`).
- Dedicated CLI command added: `sentinelscan sast <path>` with `--json` and `--verbose` options.

---

## 📁 3. Files Created & Modified

- `src/sentinelscan/scanners/sast_scanner.py` (New SastScanner module & AST visitor)
- `src/sentinelscan/scanners/registry.py` (Auto-registered SastScanner by default)
- `src/sentinelscan/scanners/__init__.py` (Exported SastScanner)
- `src/sentinelscan/cli/main.py` (Added `sast` subcommand parser)
- `src/sentinelscan/cli/commands.py` (Added `handle_sast()`)
- `tests/unit/test_sast_scanner.py` (Comprehensive unit test suite for SAST rules, strict decoding, syntax errors, and zero-execution safeguards)
- `tests/unit/test_cli.py` (Added CLI tests for `sast` command)
- `README.md`, `IMPLEMENTATION.md`, `CONTRIBUTING.md`, `docs/ROADMAP.md` (Updated documentation)

---

## 🧪 4. Test & Verification Results

- **`pytest`**: **38 passing tests** (0.42s) covering positive/negative matches, zero false positives for benign subprocess calls, strict UTF-8 decoding error handling, zero execution proof, syntax error handling, line numbers, and reporter output.
- **`ruff check .`**: 0 errors.
- **`mypy src/sentinelscan`**: 0 issues across 23 source files.
- **Manual Verification**: Executed `sentinelscan --help`, `sentinelscan scan .`, `sentinelscan sast .`, `sentinelscan sast . --json`.

---

## 📌 5. Known Limitations at Milestone 03 Completion

- Initial SAST rules focus strictly on Python source files via `ast.parse()`. Multilingual SAST (JavaScript/Go/Java) will be added in future milestones.
- Inter-procedural data flow tracking (taint tracking across complex function boundaries) is not included in this initial baseline milestone and will be added in future graph analysis releases.
