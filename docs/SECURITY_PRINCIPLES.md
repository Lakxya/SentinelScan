# SentinelScan - Security Principles & Privacy Commitments

This document outlines SentinelScan's security architecture, data handling rules, and privacy guarantees. It clearly distinguishes between **CURRENTLY IMPLEMENTED** security controls and **FUTURE** roadmap goals.

---

## 🛡️ 1. CURRENTLY IMPLEMENTED Security Controls & Guarantees

### 1.1 Strict Secret Leak Prevention
- **Zero Raw Secret Exposure**: Discovered credential values, tokens, or private keys are **NEVER** stored inside `Finding` objects, descriptions, impacts, remediations, metadata, `Location`, logs, exceptions, console reports, or JSON output.
- **Length-Aware Masking**:
  - AWS Access Keys: `AKIA************CDEF`
  - GitHub Tokens: `ghp_********************************7890`
  - Short tokens: `s***t`
- **Fixed Private Key Masking**: PEM private key blocks are replaced with `"[PRIVATE KEY REDACTED]"` without capturing key bytes.
- **Database URL Sanitization**: Passwords in database URLs are stripped and replaced with `[REDACTED]` (e.g. `postgresql://user:[REDACTED]@localhost:5432/db`).

### 1.2 Location Snippet Exclusion
- The `Location` model records `file_path`, `start_line`, and `end_line` only.
- Raw source code snippets are intentionally omitted to prevent accidental data leakage or code exposure in reports.

### 1.3 Local-First & Zero Network Calls
- The scanner operates 100% locally.
- It makes **no network requests**, calls no external validation APIs (such as AWS STS or GitHub API), and never sends discovered data to remote servers.

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

## 🔮 2. FUTURE Security Principles & Roadmap Goals

| Principle | Scope | Status | Implementation Plan |
| :--- | :--- | :--- | :--- |
| **Read-Only Cloud Posture** | AWS / Cloud | PLANNED | Future cloud assessment modules will operate in read-only mode using minimal IAM permissions (`SecurityAudit`). |
| **Explicit Authorization for Active Testing** | DAST / Network | PLANNED | Dynamic testing and network probing will require explicit CLI flag `--authorize-active-testing`. |
| **SARIF Format Support** | CI/CD | PLANNED | Exporting findings to standardized SARIF schemas for GitHub Security tab integration. |
| **Encrypted Local Result Storage** | Storage | PLANNED | Encrypting local scan history cache in `.sentinelscan/`. |
