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
6. **Kubernetes Security Analysis** *(Implemented in v0.7.0)*
7. **AWS Cloud Posture Assessment** *(Implemented in v0.8.0)*
8. Dynamic Application Security Testing (DAST)
9. Network Security Assessment
10. Architecture Analysis
11. Attack-Path & Risk Correlation
12. Posture Scoring & Remediation Guidance

---

## 📌 Current Status & Features

> [!NOTE]
> **Current Version: `v0.8.0` (Milestone 8: AWS Security Posture Scanner Active)**
>
> SentinelScan includes a production-oriented **Secret Scanner**, **Python SAST Scanner**, **IaC Security Scanner**, **SCA Dependency Scanner**, **Docker Security Scanner**, **Kubernetes Security Scanner**, and **AWS Security Posture Scanner** evaluating local IAM policies and AWS configurations without cloud network calls or AWS CLI execution.

### Supported Security Modules
- **Secret Scanner (`sentinelscan secrets`)**: AWS keys, GitHub PATs, JWTs, PEM private keys, DB connection URLs, service API keys, generic high-entropy secrets.
- **Python SAST Scanner (`sentinelscan sast`)**: Python AST analysis for dynamic code execution (`eval`, `exec`), command injection (`subprocess shell=True`, `os.system`), weak cryptography (`MD5`, `SHA-1`), and unsafe deserialization (`pickle`).
- **IaC Security Scanner (`sentinelscan iac`)**: Terraform (`.tf`), CloudFormation (`.yaml`/`.json`), and SAM template analysis using `python-hcl2` and `PyYAML` `SafeLoader`.
- **SCA Scanner (`sentinelscan sca`)**: Dependency vulnerability analysis for Python (`requirements.txt`, `pyproject.toml`, `poetry.lock`) and JavaScript (`package.json`, `package-lock.json`) using OSV intelligence, npm SemVer, and local cache (`--offline`).
- **Docker Scanner (`sentinelscan docker`)**: Static Dockerfile security analysis evaluating root user usage, base image pinning, embedded secrets, dangerous `ADD` instructions, sensitive ports, and health checks.
- **Kubernetes Scanner (`sentinelscan k8s`)**: Static manifest analysis evaluating privileged containers, root users, resource limits, host namespaces, privilege escalation, RBAC cluster-admin permissions, and unencrypted secret data.
- **AWS Posture Scanner (`sentinelscan aws`)**: Static IAM policy and configuration analysis evaluating wildcard actions/resources, `iam:PassRole`, S3 public/unencrypted policies, KMS key policies, local credential masking, and MFA profiles.

### 🔒 Security & Privacy Guarantees
- **Zero Raw Secret Exposure**: Secret values are strictly masked before constructing finding objects.
- **Zero Code / Container / Cluster / Cloud Execution**: Target code and infrastructure commands are **NEVER** executed. Docker CLI (`docker`), Kubernetes CLI (`kubectl`/`helm`), and AWS CLI (`aws`) binaries are **NEVER** invoked. Live AWS account APIs and Kubernetes API servers are **NEVER** accessed.
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

Run focused Kubernetes security scan:
```bash
sentinelscan k8s .
```

Run focused AWS security posture scan:
```bash
sentinelscan aws .
```

Generate machine-readable JSON output:
```bash
sentinelscan aws . --json
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
  Total Files       : 42
  Total Size        : 74200 bytes
  Detected Tech     : python, javascript, container, kubernetes, cloud

SCANNER MODULES
  [OK  ] secret-scanner       : SUCCESS (0 findings, 0.002s)
  [OK  ] sast-scanner         : SUCCESS (0 findings, 0.001s)
  [OK  ] iac-scanner          : SUCCESS (0 findings, 0.003s)
  [OK  ] sca-scanner          : SUCCESS (0 findings, 0.012s)
  [OK  ] docker-scanner       : SUCCESS (0 findings, 0.004s)
  [OK  ] k8s-scanner          : SUCCESS (0 findings, 0.005s)
  [OK  ] aws-scanner          : SUCCESS (1 findings, 0.004s)

FINDINGS SUMMARY
  Total Findings    : 1

FINDINGS DETAILS
--------------------------------------------------
  [1] [CRITICAL] IAM Policy Grants Full Wildcard Action in iam-policy.json
      Rule ID       : AWS-IAM-WILDCARD-ACTION (aws-scanner)
      Category      : cloud
      Confidence    : HIGH
      Location      : /path/to/project/iam-policy.json:L1
      Description   : IAM policy statement #1 in 'iam-policy.json' grants Effect: Allow with Action: '*'.
      Impact        : Full wildcard action grants unrestricted administrative access across all AWS service APIs.
      Remediation   : Restrict Action permissions to specific required API calls (e.g. s3:GetObject).
--------------------------------------------------
EXECUTION COMPLETED in 0.031 seconds.
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
- [x] **v0.7.0 - Kubernetes Security Analysis (Milestone 7)**: Static Kubernetes manifest analysis evaluating privileged containers, root users, resource limits, host namespaces, allowPrivilegeEscalation, RBAC cluster-admin permissions, and unencrypted secret data.
- [x] **v0.8.0 - AWS Cloud Posture Assessment (Milestone 8)**: Static AWS IAM policy and configuration analysis evaluating wildcard actions/resources, `iam:PassRole`, S3 public/unencrypted policies, KMS key policies, local credential masking, and MFA profiles.
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
- **[Milestones](docs/milestones/)**: Historical milestone release records ([`01-foundation.md`](docs/milestones/01-foundation.md), [`02-secret-scanner.md`](docs/milestones/02-secret-scanner.md), [`03-sast.md`](docs/milestones/03-sast.md), [`04-iac.md`](docs/milestones/04-iac.md), [`05-sca.md`](docs/milestones/05-sca.md), [`06-docker.md`](docs/milestones/06-docker.md), [`07-k8s.md`](docs/milestones/07-k8s.md), [`08-aws.md`](docs/milestones/08-aws.md)).







---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

