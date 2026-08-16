# SentinelScan - Security Principles & Privacy Commitments

This document details SentinelScan's security architecture, data handling rules, and privacy guarantees implemented across all 13 milestones (`v1.3.0`).

---

## 🛡️ 1. IMPLEMENTED Security Controls & Guarantees

### 1.1 Strict Secret Leak Prevention
- **Zero Raw Secret Exposure**: Discovered credential values, tokens, or private keys are **NEVER** stored inside `Finding` objects, descriptions, impacts, remediations, metadata, `Location`, logs, exceptions, console reports, JSON output, attack path steps, or posture remediation summaries.
- **Length-Aware Masking**:
  - AWS Access Keys: `AKIA************CDEF`
  - GitHub Tokens: `ghp_********************************7890`
  - Short tokens: `s***t`
- **Fixed Private Key Masking**: PEM private key blocks are replaced with `"[PRIVATE KEY REDACTED]"` without capturing key bytes.
- **Database URL Sanitization**: Passwords in database URLs are stripped and replaced with `[REDACTED]` (e.g. `postgresql://user:[REDACTED]@localhost:5432/db`).

### 1.2 Location Snippet Exclusion
- The `Location` model records `file_path`, `start_line`, and `end_line` only.
- Raw source code snippets are intentionally omitted to prevent accidental data leakage or code exposure in reports.

### 1.3 Local-First Filesystem Assessment & Network Boundaries
- **100% Offline Default Scans**: Standard directory scans (`sentinelscan scan .`), architecture graph construction (`sentinelscan graph .`), potential attack path analysis (`sentinelscan paths .`), and posture scoring (`sentinelscan posture .`) execute 100% offline. Zero network sockets are opened.
- **Authorized Active Network Assessment**: Dynamic network checks run **ONLY** when the user explicitly executes `sentinelscan network <target-host>`. Performs single read-only stdlib TCP connect checks (`socket.create_connection`) with bounded timeouts (0.5s per port) against explicit single-address targets. CIDR range scans are prohibited.
- **Authorized Active DAST Header Inspection**: Active DAST checks run **ONLY** when the user explicitly provides `--target-url <url>`. Performs bounded read-only HEAD/GET requests for response security headers without following cross-host redirects or sending mutating HTTP methods (POST, PUT, DELETE).

### 1.4 Safe Filesystem Operations
- **Read-Only Access**: Scanner code never modifies, writes to, or executes scanned target files.
- **Binary File Skipping**: Automatically skips binary files (null byte `\x00` detection and binary extension matching).
- **File Size Caps**: Files larger than 5 MB are skipped.
- **Symlink Protection**: External symlinks outside the target directory root are ignored (`follow_symlinks=False`).
- **Directory Exclusions**: Build directories, virtualenvs, `.git`, and node_modules are automatically excluded.

### 1.5 Deterministic Findings & Auditing
- Findings generate 16-character SHA-256 fingerprints (`fingerprint`) and unique identifiers (`FS-<hash>`) based on scanner name, rule ID, location, resource ID, and title.
- Scans are reproducible across local environments and CI/CD pipelines.

### 1.6 Exception Isolation & Safe Logging
- Individual detector and scanner exceptions are safely trapped.
- Unhandled errors log standard status messages without dumping raw buffer contents or credentials to stdout/stderr.

---

## 🔮 2. Future Security Principles & Roadmap Goals

| Principle | Scope | Status | Implementation Plan |
| :--- | :--- | :--- | :--- |
| **SARIF Format Support** | CI/CD | PLANNED | Exporting findings to standardized SARIF schemas for GitHub Security tab integration. |
| **Encrypted Local Result Storage** | Storage | PLANNED | Encrypting local scan history cache in `.sentinelscan/`. |
