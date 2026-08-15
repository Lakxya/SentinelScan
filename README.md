# SentinelScan 🛡️

> **SentinelScan** is an open-source, local-first DevSecOps and cloud security assessment CLI.

---

## 🎯 Overview

SentinelScan provides security engineers, developers, and DevOps teams with a single, unified local command-line tool for multi-domain security assessments across 12 security domains:

1. **Secret & Credential Detection** *(Implemented in v0.2.0)*
2. Static Application Security Testing (SAST)
3. Software Composition Analysis (SCA)
4. Dynamic Application Security Testing (DAST)
5. Docker Security Analysis
6. Kubernetes Security Analysis
7. Infrastructure-as-Code (IaC) Assessment
8. AWS & Cloud Posture Assessment
9. Network Security Assessment
10. Architecture Analysis
11. Attack-Path & Risk Correlation
12. Posture Scoring & Remediation Guidance

---

## 📌 Current Status & Features

> [!NOTE]
> **Current Version: `v0.2.0` (Milestone 1: Secret Scanner Active)**
>
> SentinelScan now includes a production-oriented, local-first **Secret & Credential Detection Scanner** alongside the baseline CLI, discovery engine, finding models, reporters, and unit test suite.

### Supported Secret Detectors
- **AWS Access Key IDs**: `AKIA[0-9A-Z]{16}`, `ASIA[0-9A-Z]{16}` (`SECRET-AWS-ACCESS-KEY`)
- **AWS Secret Access Keys**: Contextual key assignments (`SECRET-AWS-SECRET-KEY`)
- **PEM / Private Keys**: RSA, EC, DSA, OpenSSH private key blocks (`SECRET-PRIVATE-KEY`)
- **GitHub Tokens**: Personal access tokens `ghp_`, `gho_`, `github_pat_` (`SECRET-GITHUB-TOKEN`)
- **JWT Tokens**: Signed JSON Web Tokens (`SECRET-JWT`)
- **Service API Keys**: Slack, Stripe, Google API, SendGrid (`SECRET-API-KEY`)
- **Database Connection Strings**: Credentials in PostgreSQL, MySQL, MongoDB, Redis URLs (`SECRET-DATABASE-CREDENTIAL`)
- **Generic High-Entropy Secrets**: Suspicious variable assignments with Shannon entropy $H \ge 3.6$ (`SECRET-GENERIC`)

### 🔒 Secret Safety Guarantee
Raw credentials and secrets are **NEVER** stored inside `Finding` objects, descriptions, impacts, remediations, metadata, `Location`, logs, exceptions, console reports, or JSON output. Discovered values are strictly masked (e.g. `AKIA************CDEF` or `[PRIVATE KEY REDACTED]`).

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

Generate machine-readable JSON output:
```bash
sentinelscan secrets . --json
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
  Total Files       : 24
  Total Size        : 45120 bytes
  Detected Tech     : python

SCANNER MODULES
  [OK  ] secret-scanner       : SUCCESS (1 findings, 0.002s)

FINDINGS SUMMARY
  Total Findings    : 1

FINDINGS DETAILS
--------------------------------------------------
  [1] [CRITICAL] Exposed AWS Access Key ID
      Rule ID       : SECRET-AWS-ACCESS-KEY (secret-scanner)
      Category      : secret
      Confidence    : HIGH
      Location      : /path/to/project/aws_config.py:L12
      Description   : An AWS Access Key ID pattern was detected.
      Impact        : Allows unauthorized API authentication to AWS cloud infrastructure.
      Remediation   : Immediately revoke the access key in AWS IAM and generate a new key pair.
--------------------------------------------------
EXECUTION COMPLETED in 0.002 seconds.
==================================================
```

---

## 🗺️ Roadmap

- [x] **v0.1.0 - Foundation & Architecture**: Core CLI, target discovery, scanner interface, data models, reporters, test suite, and docs.
- [x] **v0.2.0 - Secret & Credential Detection Scanner (Milestone 1)**: Production secret detectors, entropy analysis, credential masking, dedicated `secrets` CLI command.
- [ ] **v0.3.0 - SAST & Static Code Analysis (Milestone 2)**: Python AST static analyzer flagging insecure functions (`eval()`, `exec()`, `shell=True`).
- [ ] **v0.4.0 - Container & IaC Security**: Dockerfile, Kubernetes manifests, and Terraform misconfiguration scanners.
- [ ] **v0.5.0 - Software Composition Analysis (SCA)**: Dependency vulnerability and license compliance scanning.
- [ ] **v0.6.0 - Cloud Posture Assessment (AWS)**: Read-only AWS security posture assessment module.
- [ ] **v0.7.0 - Risk Correlation & Attack-Path Analysis**: Multi-finding correlation engine, posture scoring, and remediation reports.

---

## 📖 Documentation

Comprehensive engineering documentation is maintained in the [`docs/`](docs/) directory:

- **[DEVELOPMENT_PLAN.md](docs/DEVELOPMENT_PLAN.md)**: Engineering workflow, milestone pipeline, and AI agent instructions.
- **[ARCHITECTURE.md](docs/ARCHITECTURE.md)**: System architecture specification, core engine, models, and flow diagrams.
- **[SECURITY_PRINCIPLES.md](docs/SECURITY_PRINCIPLES.md)**: Security commitments, leak prevention rules, and privacy controls.
- **[TESTING.md](docs/TESTING.md)**: Quality assurance guide, pytest suite structure, and secret leak verification.
- **[SCANNER_DEVELOPMENT.md](docs/SCANNER_DEVELOPMENT.md)**: Definitive 13-step guide for building new scanner modules.
- **[ROADMAP.md](docs/ROADMAP.md)**: Official feature matrix and capability status breakdown.
- **[Milestones](docs/milestones/)**: Historical milestone release records ([`01-foundation.md`](docs/milestones/01-foundation.md), [`02-secret-scanner.md`](docs/milestones/02-secret-scanner.md)).

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

