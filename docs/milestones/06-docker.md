# Milestone 06 - Docker Security Analysis Scanner

- **Status**: `COMPLETED`
- **Release Version**: `v0.6.0`
- **Focus**: Building a static Docker security analyzer (`DockerScanner`) inspecting Dockerfiles for security misconfigurations, root user usage, base image pinning, embedded secrets, dangerous instructions, sensitive port exposures, and missing health checks without executing `docker` CLI commands, connecting to Docker daemons, pulling images, or evaluating container RUN commands.

---

## 🎯 1. Goals

Implement a static Dockerfile scanner (`DockerScanner`) integrating into SentinelScan's `BaseScanner` interface under `Category.CONTAINER`, discovering Dockerfiles (`Dockerfile`, `Dockerfile.*`, `*.dockerfile`), parsing instructions with line numbers, evaluating multi-stage builds, and providing CLI support via `sentinelscan docker <path>`.

---

## 🛠️ 2. Actual Capabilities Implemented

### 2.1 Deterministic Dockerfile Parser
- **Line Continuations & Comments**: Merges multiline instructions joined with backslashes (`\`) into single logical statements while tracking exact original line ranges (`start_line` and `end_line`), ignoring comment lines (`#`).
- **Instruction Casing & Parsing**: Normalizes instruction keywords (`from` $\rightarrow$ `FROM`, `user` $\rightarrow$ `USER`, `copy` $\rightarrow$ `COPY`).
- **Multi-Stage Build Intelligence**: Tracks all `FROM` blocks (`stage_index`, `stage_alias`) and identifies the **final runtime stage**.

### 2.2 Security Rules Implemented

| Rule ID | Title | Severity | Confidence | Target Scope | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`DOCKER-ROOT-USER`** | Container Running as Root User | `HIGH` | `HIGH` | Final Runtime Stage | Missing `USER` instruction or explicit `USER root` / `USER 0`. |
| **`DOCKER-LATEST-TAG`** | Base Image Uses Latest or Untagged Version | `HIGH` | `HIGH` | All `FROM` Stages | Base image uses `:latest` tag or omits version tag (`FROM ubuntu`). |
| **`DOCKER-UNPINNED-BASE`** | Base Image Unpinned by Digest | `LOW` | `HIGH` | All `FROM` Stages | Base image specifies version tag without immutable digest (`FROM python:3.12-slim`). |
| **`DOCKER-ADD-INSTEAD-OF-COPY`** | Dangerous `ADD` Used Instead of `COPY` | `MEDIUM` | `HIGH` | All Instructions | `ADD` instruction used for local file copying instead of `COPY`. |
| **`DOCKER-SECRET-ENV`** | Hardcoded Secret in `ENV` / `ARG` | `HIGH` | `HIGH` | All Instructions | Sensitive credential pattern in `ENV` or `ARG` values (masked in findings). |
| **`DOCKER-SENSITIVE-PORT`** | Sensitive Port Exposed | `MEDIUM` | `MEDIUM` | All Instructions | `EXPOSE` includes sensitive ports (SSH 22, RDP 3389, DB 3306/5432/27017). |
| **`DOCKER-NO-HEALTHCHECK`** | Missing `HEALTHCHECK` Instruction | `LOW` | `HIGH` | Final Runtime Stage | Final stage lacks a `HEALTHCHECK` instruction. |
| **`DOCKER-SUDO-USAGE`** | `sudo` Used in `RUN` Instruction | `MEDIUM` | `HIGH` | All Instructions | `RUN` instruction invokes `sudo` command. |

### 2.3 False Positive Mitigation & Multi-Stage Intelligence
- **Multi-Stage Builder Exclusion**: Intermediate builder stages (`FROM golang:1.21 AS builder`) generate temporary artifacts. Runtime rules (`DOCKER-ROOT-USER` and `DOCKER-NO-HEALTHCHECK`) are evaluated **ONLY on the final runtime stage**.
- **Digest-Pinned Images**: Images pinned by immutable SHA256 digests (`FROM python:3.12-slim@sha256:1234...`) produce **0 base-image pinning findings**.

### 2.4 Security & Privacy Safeguards
- **Zero Command Execution**: Never runs `docker build`, `docker run`, `docker pull`, `docker inspect`, `docker exec`, or shell commands in `RUN`.
- **Zero Socket Access**: Never connects to `/var/run/docker.sock` or remote Docker API endpoints.
- **Zero Secret Exposure**: Secret values in `ENV`/`ARG` are strictly masked before constructing findings.
- **Read-Only**: Target Dockerfile files are never modified.

---

## 📁 3. Files Created & Modified

- `src/sentinelscan/scanners/docker_scanner.py` (New `DockerScanner` module and `DockerfileParser`)
- `src/sentinelscan/scanners/registry.py` (Auto-registered `DockerScanner` by default)
- `src/sentinelscan/scanners/__init__.py` (Exported `DockerScanner`)
- `src/sentinelscan/cli/main.py` (Added `docker` subcommand parser)
- `src/sentinelscan/cli/commands.py` (Added `handle_docker()`)
- `src/sentinelscan/cli/__init__.py` (Exported `handle_docker`)
- `tests/unit/test_docker_scanner.py` (Unit test suite covering Dockerfile parsing, single-stage, multi-stage, digest pinning, secrets masking, and JSON output)
- `tests/unit/test_cli.py` (Added CLI tests for `docker` command)
- `README.md`, `IMPLEMENTATION.md`, `CONTRIBUTING.md`, `docs/ROADMAP.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY_PRINCIPLES.md` (Updated documentation)

---

## 🧪 4. Test & Verification Results

- **`pytest`**: **61 passing tests** (1.14s) covering single-stage, multi-stage, digest pinning, secret masking, and CLI subcommands.
- **`ruff check .`**: 0 errors.
- **`mypy src/sentinelscan`**: 0 issues across 26 source files.
- **Manual Verification**: Executed `sentinelscan --help`, `sentinelscan scan .`, `sentinelscan docker .`, `sentinelscan docker . --json`.

---

## 📌 5. Known Limitations at Milestone 06 Completion

- Static Dockerfile analysis inspects declared build instructions. It does not inspect installed OS package vulnerabilities inside the built container image (handled by SCA).
- Runtime CLI flags passed to `docker run` (e.g. `--privileged`) are outside Dockerfile static scope.
