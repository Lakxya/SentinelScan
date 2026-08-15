# SentinelScan 🛡️

> **SentinelScan** is an open-source, local-first DevSecOps and cloud security assessment CLI.

---

## 🎯 Overview

SentinelScan provides security engineers, developers, and DevOps teams with a single, unified local command-line tool for multi-domain security assessments across 12 security domains:

1. **Secret & Credential Detection** *(Implemented in v0.2.0)*
2. **Static Application Security Testing (SAST)** *(Implemented in v0.3.0)*
3. **Infrastructure-as-Code (IaC) Assessment** *(Implemented in v0.4.0)*
4. **Software Composition Analysis (SCA)** *(Implemented in v0.5.0)*
5. **Docker Security Analysis** *(Implemented in v0.6.0)*
6. Dynamic Application Security Testing (DAST)
7. Kubernetes Security Analysis
8. AWS & Cloud Posture Assessment
9. Network Security Assessment
10. Architecture Analysis
11. Attack-Path & Risk Correlation
12. Posture Scoring & Remediation Guidance

---

## 📌 Current Status & Features

> [!NOTE]
> **Current Version: `v0.6.0` (Milestone 6: Docker Security Scanner Active)**
>
> SentinelScan includes a production-oriented **Secret Scanner**, **Python SAST Scanner**, **IaC Security Scanner**, **SCA Dependency Scanner**, and **Docker Security Scanner** evaluating Dockerfile misconfigurations locally without executing containers or Docker daemons.

### Supported Security Modules
- **Secret Scanner (`sentinelscan secrets`)**: AWS keys, GitHub PATs, JWTs, PEM private keys, DB connection URLs, service API keys, generic high-entropy secrets.
- **Python SAST Scanner (`sentinelscan sast`)**: Python AST analysis for dynamic code execution (`eval`, `exec`), command injection (`subprocess shell=True`, `os.system`), weak cryptography (`MD5`, `SHA-1`), and unsafe deserialization (`pickle`).
- **IaC Security Scanner (`sentinelscan iac`)**: Terraform (`.tf`), CloudFormation (`.yaml`/`.json`), and SAM template analysis using `python-hcl2` and `PyYAML` `SafeLoader`.
- **SCA Scanner (`sentinelscan sca`)**: Dependency vulnerability analysis for Python (`requirements.txt`, `pyproject.toml`, `poetry.lock`) and JavaScript (`package.json`, `package-lock.json`) using OSV intelligence, npm SemVer, and local cache (`--offline`).
- **Docker Scanner (`sentinelscan docker`)**: Static Dockerfile security analysis evaluating root user usage, base image pinning, embedded secrets, dangerous `ADD` instructions, sensitive ports, and health checks.

### 🔒 Security & Privacy Guarantees
- **Zero Raw Secret Exposure**: Secret values are strictly masked before constructing finding objects.
- **Zero Code / Container Execution**: Target code and infrastructure commands are **NEVER** executed. Docker CLI commands (`docker build`, `docker run`) are **NEVER** invoked. Local Docker daemon socket is **NEVER** accessed.
- **Strict Metadata Privacy**: Outbound SCA queries send ONLY package names and version strings (`{"package": {"name": "express", "ecosystem": "npm"}, "version": "4.16.0"}`). Source code, secrets, or file paths are **NEVER** transmitted.
- **Strict `--offline` Mode**: Passing `--offline` strictly guarantees zero network socket calls.





---

## ⚡ Quickstart & Installation

### Prerequisites
- **Python 3.11+**

### Installation

Clone the repository and install SentinelScan in editable mode:

```bash
git clone https://github.com/sentinelscan/sentinelscan.git
cd SentinelScan
pip install -e ".[dev]"
```

---

## 💻 CLI Usage

Check version:
```bash
sentinelscan --version
```

Run full security scan against current directory:
```bash
sentinelscan scan .
```

Run focused Secret & Credential scan:
```bash
sentinelscan secrets .
```

Run focused Python SAST scan:
```bash
sentinelscan sast .
```

Run focused Infrastructure-as-Code (IaC) scan:
```bash
sentinelscan iac .
```

Run focused Software Composition Analysis (SCA) scan:
```bash
sentinelscan sca .
```

Run focused Docker security scan:
```bash
sentinelscan docker .
```

Generate machine-readable JSON output:
```bash
sentinelscan docker . --json
```

---

## 📋 Example Console Output

```text
==================================================
        SentinelScan Security Assessment          
==================================================

TARGET DISCOVERY
  Path              : /path/to/project
  Target Type       : Directory
  Git Repository    : Yes
  Total Files       : 34
  Total Size        : 61400 bytes
  Detected Tech     : python, javascript, container

SCANNER MODULES
  [OK  ] secret-scanner       : SUCCESS (0 findings, 0.002s)
  [OK  ] sast-scanner         : SUCCESS (0 findings, 0.001s)
  [OK  ] iac-scanner          : SUCCESS (0 findings, 0.003s)
  [OK  ] sca-scanner          : SUCCESS (0 findings, 0.012s)
  [OK  ] docker-scanner       : SUCCESS (1 findings, 0.004s)

FINDINGS SUMMARY
  Total Findings    : 1

FINDINGS DETAILS
--------------------------------------------------
  [1] [HIGH] Container Running as Root User
      Rule ID       : DOCKER-ROOT-USER (docker-scanner)
      Category      : container
      Confidence    : HIGH
      Location      : /path/to/project/Dockerfile:L15
      Description   : Dockerfile final stage lacks a USER instruction and runs as default root.
      Impact        : Containers running as root allow privilege escalation and host system compromise.
      Remediation   : Create a dedicated non-root user/group and switch to it using USER <username>.
--------------------------------------------------
EXECUTION COMPLETED in 0.022 seconds.
==================================================
```

---

## 🗺️ Roadmap

- [x] **v0.1.0 - Foundation & Architecture**: Core CLI, target discovery, scanner interface, data models, reporters, test suite, and docs.
- [x] **v0.2.0 - Secret & Credential Detection Scanner (Milestone 1)**: Production secret detectors, entropy analysis, credential masking, dedicated `secrets` CLI command.
- [x] **v0.3.0 - SAST & Static Code Analysis (Milestone 3)**: Python AST static analyzer flagging dynamic execution (`eval`, `exec`), command injection (`shell=True`, `os.system`), weak crypto (`MD5`, `SHA-1`), and unsafe deserialization (`pickle`).
- [x] **v0.4.0 - Infrastructure-as-Code (IaC) Security (Milestone 4)**: Misconfiguration analysis for Terraform (`.tf`), CloudFormation, and SAM templates using `python-hcl2` and `PyYAML` `SafeLoader`.
- [x] **v0.5.0 - Software Composition Analysis (Milestone 5)**: Dependency vulnerability scanner for Python and JavaScript ecosystems using two-stage OSV intelligence, npm SemVer, local disk cache, and `sentinelscan sca` subcommand with `--offline` support.
- [x] **v0.6.0 - Docker Security Analysis (Milestone 6)**: Static Dockerfile security analysis evaluating root user, base image pinning, secrets in `ENV`/`ARG`, dangerous `ADD`, sensitive ports, and health checks.
- [ ] **v0.7.0 - Kubernetes Security Analysis**: K8s manifest security checks (privileged mode, missing limits, RBAC).
- [ ] **v0.8.0 - Cloud Posture Assessment (AWS)**: Read-only AWS security posture assessment module.
- [ ] **v0.9.0 - Risk Correlation & Attack-Path Analysis**: Multi-finding correlation engine, posture scoring, and remediation reports.

---

## 📖 Documentation

Comprehensive engineering documentation is maintained in the [`docs/`](docs/) directory:

- **[DEVELOPMENT_PLAN.md](docs/DEVELOPMENT_PLAN.md)**: Engineering workflow, milestone pipeline, and AI agent instructions.
- **[ARCHITECTURE.md](docs/ARCHITECTURE.md)**: System architecture specification, core engine, models, and flow diagrams.
- **[SECURITY_PRINCIPLES.md](docs/SECURITY_PRINCIPLES.md)**: Security commitments, leak prevention rules, and privacy controls.
- **[TESTING.md](docs/TESTING.md)**: Quality assurance guide, pytest suite structure, and secret leak verification.
- **[SCANNER_DEVELOPMENT.md](docs/SCANNER_DEVELOPMENT.md)**: Definitive 13-step guide for building new scanner modules.
- **[ROADMAP.md](docs/ROADMAP.md)**: Official feature matrix and capability status breakdown.
- **[Milestones](docs/milestones/)**: Historical milestone release records ([`01-foundation.md`](docs/milestones/01-foundation.md), [`02-secret-scanner.md`](docs/milestones/02-secret-scanner.md), [`03-sast.md`](docs/milestones/03-sast.md), [`04-iac.md`](docs/milestones/04-iac.md), [`05-sca.md`](docs/milestones/05-sca.md), [`06-docker.md`](docs/milestones/06-docker.md)).





---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

