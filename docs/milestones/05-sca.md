# Milestone 05 - Software Composition Analysis (SCA) Scanner

- **Status**: `COMPLETED`
- **Release Version**: `v0.5.0`
- **Focus**: Building a local-first Software Composition Analysis scanner (`ScaScanner`) discovering vulnerable Python and JavaScript project dependencies via two-stage OSV intelligence, npm SemVer and PyPA PEP 440 version matching, dual local caching, and `sentinelscan sca` CLI command with `--offline` support.

---

## 🎯 1. Goals

Implement a static dependency vulnerability scanner (`ScaScanner`) integrating into SentinelScan's `BaseScanner` interface, inspecting Python (`requirements.txt`, `pyproject.toml`, `poetry.lock`) and JavaScript (`package.json`, `package-lock.json`) manifests without executing `pip`, `npm`, `poetry`, or `yarn` commands, executing project code, transmitting secrets/source code, or modifying target files.

---

## 🛠️ 2. Actual Capabilities Implemented

### 2.1 Ecosystem & Dependency Parsers
- **Python Ecosystem**:
  - `requirements.txt`: Line-by-line parser extracting package name and constraint (`==2.25.0`, `>=1.26.0`), ignoring comments (`#`) and flags (`-r`).
  - `pyproject.toml`: Stdlib `tomllib` parser reading PEP 621 `[project.dependencies]` and Poetry `[tool.poetry.dependencies]`.
  - `poetry.lock`: Stdlib `tomllib` parser extracting exact resolved `[[package]]` entries (names, versions, main vs dev categories).
- **JavaScript / Node.js Ecosystem**:
  - `package.json`: Stdlib `json.loads()` reading `dependencies`, `devDependencies`, `peerDependencies`. Supports scoped packages (`@types/node`, `@babel/core`).
  - `package-lock.json`: Stdlib `json.loads()` supporting v1, v2, and v3 lockfiles (`packages` or `dependencies` entries) with exact resolved versions.

### 2.2 Version Matching & Confidence Rules
- **Python PEP 440 Matching**: PyPA `packaging.version.Version` and `packaging.specifiers.SpecifierSet`.
- **JavaScript npm SemVer Matching**: Pure Python `semver` parser evaluating caret `^`, tilde `~`, comparison operators (`<`, `<=`, `>`, `>=`, `=`), logical OR (`||`), pre-releases (`1.0.0-beta.1`), and scoped package identifiers.
- **Manifest vs Lockfile Confidence**:
  - Exact resolved versions in lockfiles (`poetry.lock`, `package-lock.json`) $\rightarrow$ `Confidence.HIGH`.
  - Version constraint ranges in manifests (`requirements.txt`, `package.json`, `pyproject.toml`) $\rightarrow$ `Confidence.MEDIUM`.

### 2.3 OSV Vulnerability Intelligence & Dual Cache
- **Stage 1 (Batch Index Query)**: `POST https://api.osv.dev/v1/querybatch` maps package metadata (`name`, `ecosystem`, `version`) to lists of vulnerability IDs (`GHSA-xxx`, `CVE-xxx`).
- **Stage 2 (Full Advisory Retrieval)**: `GET https://api.osv.dev/v1/vulns/{id}` fetches full advisory records containing CVSS scores, descriptions, fixed version events, and reference links.
- **Dual Cache Layer**: Cache stored at `~/.sentinelscan/cache/osv/` (`query_index_cache.json` and `vuln_details_cache.json`) with a 24-hour TTL.
- **Strict `--offline` Guarantee**: Passing `--offline` disables all network socket calls and relies 100% on local disk cache.
- **Safe Network Failure**: Network errors with empty cache set `is_network_error = True` and log a diagnostic warning. Network errors are **NEVER** reported as 0 vulnerabilities.

### 2.4 CLI Integration
- `ScaScanner` auto-registered in `ScannerRegistry` by default (`sentinelscan scan .`).
- Dedicated CLI subcommand added: `sentinelscan sca <path>` with `--json`, `--offline`, and `--verbose` options.

---

## 📁 3. Files Created & Modified

- `src/sentinelscan/scanners/sca_scanner.py` (New ScaScanner module, parsers, OSV client, and cache manager)
- `src/sentinelscan/scanners/registry.py` (Auto-registered ScaScanner by default)
- `src/sentinelscan/scanners/__init__.py` (Exported ScaScanner)
- `src/sentinelscan/cli/main.py` (Added `sca` subcommand parser and `--offline` flag)
- `src/sentinelscan/cli/commands.py` (Added `handle_sca()`)
- `pyproject.toml` (Added `packaging>=23.0` and `semver>=3.0.0` dependencies)
- `tests/unit/test_sca_scanner.py` (Comprehensive unit test suite for Python/JS parsers, SemVer matching, OSV two-stage lookup, cache read/write/TTL, `--offline` zero-network guarantee, and status handling)
- `tests/unit/test_cli.py` (Added CLI tests for `sca` command)
- `README.md`, `IMPLEMENTATION.md`, `CONTRIBUTING.md`, `docs/ROADMAP.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY_PRINCIPLES.md` (Updated documentation)

---

## 🧪 4. Test & Verification Results

- **`pytest`**: **55 passing tests** (1.02s) covering Python manifests, JS lockfiles, npm SemVer caret/tilde matching, OSV API two-stage lookup, local cache TTL, offline mode, network failure handling, and CLI flags.
- **`ruff check .`**: 0 errors.
- **`mypy src/sentinelscan`**: 0 issues across 25 source files.
- **Manual Verification**: Executed `sentinelscan --help`, `sentinelscan scan .`, `sentinelscan sca . --offline`, `sentinelscan sca . --json`.

---

## 📌 5. Known Limitations at Milestone 05 Completion

- Manifest files without lockfiles (e.g. `requirements.txt` with `requests>=2.20.0`) cannot prove exact installed versions and are reported with `Confidence.MEDIUM`.
- Does not inspect compiled C/C++ binary dependencies or system shared libraries.
