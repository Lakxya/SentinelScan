# SentinelScan 🛡️

> **SentinelScan** is an open-source, local-first DevSecOps and cloud security assessment CLI.

---

## 🎯 Overview

SentinelScan provides security engineers, developers, and DevOps teams with a single, unified local command-line tool for multi-domain security assessments across 12 security domains:

1. **Secret & Credential Detection** *(Implemented in v0.2.0)*
2. **Static Application Security Testing (SAST)** *(Implemented in v0.3.0)*
3. **Infrastructure-as-Code (IaC) Assessment** *(Implemented in v0.4.0)*
4. Software Composition Analysis (SCA)
5. Dynamic Application Security Testing (DAST)
6. Docker Security Analysis
7. Kubernetes Security Analysis
8. AWS & Cloud Posture Assessment
9. Network Security Assessment
10. Architecture Analysis
11. Attack-Path & Risk Correlation
12. Posture Scoring & Remediation Guidance

---

## 📌 Current Status & Features

> [!NOTE]
> **Current Version: `v0.4.0` (Milestone 4: IaC Security Scanner Active)**
>
> SentinelScan includes a production-oriented **Secret Scanner**, **Python SAST Scanner**, and **IaC Security Scanner** analyzing Terraform HCL, CloudFormation, and SAM templates locally.

### Supported Security Modules
- **Secret Scanner (`sentinelscan secrets`)**: AWS keys, GitHub PATs, JWTs, PEM private keys, DB connection URLs, service API keys, generic high-entropy secrets.
- **Python SAST Scanner (`sentinelscan sast`)**: Python AST analysis for dynamic code execution (`eval`, `exec`), command injection (`subprocess shell=True`, `os.system`), weak cryptography (`MD5`, `SHA-1`), and unsafe deserialization (`pickle`).
- **IaC Security Scanner (`sentinelscan iac`)**: Terraform (`.tf`), CloudFormation (`.yaml`/`.json`), and SAM template analysis using `python-hcl2` and `PyYAML` `SafeLoader`.

### 🔒 Security & Privacy Guarantees
- **Zero Raw Secret Exposure**: Secret values are strictly masked before constructing finding objects.
- **Zero Code Execution**: Python source code is parsed strictly into Abstract Syntax Trees (`ast.parse()`). IaC templates are parsed strictly via `python-hcl2` and `PyYAML` `SafeLoader`. Target code/infrastructure commands are **NEVER** executed or deployed.
- **Zero Network & Zero AWS Credential Calls**: Operates 100% locally; calls no cloud APIs or socket connections.



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

Generate machine-readable JSON output:
```bash
sentinelscan iac . --json
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
  Detected Tech     : python, iac-terraform

SCANNER MODULES
  [OK  ] secret-scanner       : SUCCESS (1 findings, 0.002s)
  [OK  ] sast-scanner         : SUCCESS (0 findings, 0.001s)
  [OK  ] iac-scanner          : SUCCESS (1 findings, 0.003s)

FINDINGS SUMMARY
  Total Findings    : 2

FINDINGS DETAILS
--------------------------------------------------
  [1] [HIGH] Security Group Open Ingress to World
      Rule ID       : IAC-AWS-SG-OPEN-INGRESS (iac-scanner)
      Category      : iac
      Confidence    : HIGH
      Location      : /path/to/project/main.tf:L12
      Description   : Security group 'web_sg' allows unrestricted ingress from 0.0.0.0/0 on sensitive port 22.
      Impact        : Exposes infrastructure ports directly to internet scans and unauthorized remote access.
      Remediation   : Restrict security group ingress cidr_blocks to known internal corporate IP ranges.
--------------------------------------------------
EXECUTION COMPLETED in 0.006 seconds.
==================================================
```

---

## 🗺️ Roadmap

- [x] **v0.1.0 - Foundation & Architecture**: Core CLI, target discovery, scanner interface, data models, reporters, test suite, and docs.
- [x] **v0.2.0 - Secret & Credential Detection Scanner (Milestone 1)**: Production secret detectors, entropy analysis, credential masking, dedicated `secrets` CLI command.
- [x] **v0.3.0 - SAST & Static Code Analysis (Milestone 3)**: Python AST static analyzer flagging dynamic execution (`eval`, `exec`), command injection (`shell=True`, `os.system`), weak crypto (`MD5`, `SHA-1`), and unsafe deserialization (`pickle`).
- [x] **v0.4.0 - Infrastructure-as-Code (IaC) Security (Milestone 4)**: Misconfiguration analysis for Terraform (`.tf`), CloudFormation, and SAM templates using `python-hcl2` and `PyYAML` `SafeLoader`.
- [ ] **v0.5.0 - Docker Security Analysis**: Dockerfile instruction security and unpinned image checks.
- [ ] **v0.6.0 - Kubernetes Security Analysis**: K8s manifest security checks (privileged mode, missing limits, RBAC).
- [ ] **v0.7.0 - Software Composition Analysis (SCA)**: Dependency vulnerability and license compliance scanning.
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
- **[Milestones](docs/milestones/)**: Historical milestone release records ([`01-foundation.md`](docs/milestones/01-foundation.md), [`02-secret-scanner.md`](docs/milestones/02-secret-scanner.md), [`03-sast.md`](docs/milestones/03-sast.md), [`04-iac.md`](docs/milestones/04-iac.md)).



---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

