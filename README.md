# SentinelScan 🛡️

> **SentinelScan** is an open-source, local-first DevSecOps and cloud security assessment CLI.

---

## 🎯 Overview

SentinelScan provides security engineers, developers, and DevOps teams with a single, unified local command-line tool for multi-domain security assessments across 12 security domains:

1. **Secret & Credential Detection** *(Implemented in v0.2.0)*
2. **Static Application Security Testing (SAST)** *(Implemented in v0.3.0)*
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
> **Current Version: `v0.3.0` (Milestone 3: Python SAST Scanner Active)**
>
> SentinelScan includes a production-oriented **Secret & Credential Scanner** and a zero-execution **Python SAST Scanner** operating via AST analysis alongside the baseline CLI, discovery engine, finding models, reporters, and test suite.

### Supported Security Modules
- **Secret Scanner (`sentinelscan secrets`)**: AWS keys, GitHub PATs, JWTs, PEM private keys, DB connection URLs, service API keys, generic high-entropy secrets.
- **Python SAST Scanner (`sentinelscan sast`)**: Python AST analysis for dynamic code execution (`eval`, `exec`), command injection (`subprocess shell=True`, `os.system`), weak cryptography (`MD5`, `SHA-1`), and unsafe deserialization (`pickle.load`, `pickle.loads`).

### 🔒 Security & Privacy Guarantees
- **Zero Raw Secret Exposure**: Secret values are strictly masked before constructing finding objects.
- **Zero Code Execution**: Python source code is parsed strictly into Abstract Syntax Trees using standard library `ast.parse()`. Target code is **NEVER** imported, executed, evaluated, or called.
- **Strict Decoding**: Source files are parsed with strict UTF-8 decoding (`errors="strict"`). If decoding fails, the file is logged and skipped without mangling source bytes.


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

Generate machine-readable JSON output:
```bash
sentinelscan sast . --json
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
  [OK  ] sast-scanner         : SUCCESS (1 findings, 0.001s)

FINDINGS SUMMARY
  Total Findings    : 2

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
  [2] [CRITICAL] Dynamic Code Execution via eval()
      Rule ID       : SAST-PY-EVAL (sast-scanner)
      Category      : sast
      Confidence    : HIGH
      Location      : /path/to/project/app.py:L45
      Description   : An eval() call was detected. Dynamic code evaluation can lead to arbitrary code execution.
      Impact        : Potential Remote Code Execution (RCE) vulnerability.
      Remediation   : Avoid eval(). Parse data using structured formats like json.loads().
--------------------------------------------------
EXECUTION COMPLETED in 0.003 seconds.
==================================================
```

---

## 🗺️ Roadmap

- [x] **v0.1.0 - Foundation & Architecture**: Core CLI, target discovery, scanner interface, data models, reporters, test suite, and docs.
- [x] **v0.2.0 - Secret & Credential Detection Scanner (Milestone 1)**: Production secret detectors, entropy analysis, credential masking, dedicated `secrets` CLI command.
- [x] **v0.3.0 - SAST & Static Code Analysis (Milestone 3)**: Python AST static analyzer flagging dynamic execution (`eval`, `exec`), command injection (`shell=True`, `os.system`), weak crypto (`MD5`, `SHA-1`), and unsafe deserialization (`pickle`).
- [ ] **v0.4.0 - Infrastructure-as-Code (IaC) Security**: Misconfiguration analysis for Terraform (`.tf`), CloudFormation, and SAM templates.
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
- **[Milestones](docs/milestones/)**: Historical milestone release records ([`01-foundation.md`](docs/milestones/01-foundation.md), [`02-secret-scanner.md`](docs/milestones/02-secret-scanner.md), [`03-sast.md`](docs/milestones/03-sast.md)).


---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

