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
8. **Dynamic Testing & Web Security (DAST)** *(Implemented in v0.9.0)*
9. **Architecture Graph Capability** *(Implemented in v1.0.0)*
10. Network Security Assessment
11. Attack-Path & Risk Correlation
12. Posture Scoring & Remediation Guidance

---

## 📌 Current Status & Features

> [!NOTE]
> **Current Version: `v1.0.0` (Milestone 10: Architecture Graph Active)**
>
> SentinelScan includes a production-oriented **Secret Scanner**, **Python SAST Scanner**, **IaC Security Scanner**, **SCA Dependency Scanner**, **Docker Security Scanner**, **Kubernetes Security Scanner**, **AWS Posture Scanner**, **DAST Web Security Scanner**, and **Architecture Graph Capability** mapping relationships between Terraform, Kubernetes, AWS IAM, Docker assets, and security findings.

### Supported Security Modules & Capabilities
- **Secret Scanner (`sentinelscan secrets`)**: AWS keys, GitHub PATs, JWTs, PEM private keys, DB connection URLs, service API keys, generic high-entropy secrets.
- **Python SAST Scanner (`sentinelscan sast`)**: Python AST analysis for dynamic code execution (`eval`, `exec`), command injection (`subprocess shell=True`, `os.system`), weak cryptography (`MD5`, `SHA-1`), and unsafe deserialization (`pickle`).
- **IaC Security Scanner (`sentinelscan iac`)**: Terraform (`.tf`), CloudFormation (`.yaml`/`.json`), and SAM template analysis using `python-hcl2` and `PyYAML` `SafeLoader`.
- **SCA Scanner (`sentinelscan sca`)**: Dependency vulnerability analysis for Python (`requirements.txt`, `pyproject.toml`, `poetry.lock`) and JavaScript (`package.json`, `package-lock.json`) using OSV intelligence, npm SemVer, and local cache (`--offline`).
- **Docker Scanner (`sentinelscan docker`)**: Static Dockerfile security analysis evaluating root user usage, base image pinning, embedded secrets, dangerous `ADD` instructions, sensitive ports, and health checks.
- **Kubernetes Scanner (`sentinelscan k8s`)**: Static manifest analysis evaluating privileged containers, root users, resource limits, host namespaces, privilege escalation, RBAC cluster-admin permissions, and unencrypted secret data.
- **AWS Posture Scanner (`sentinelscan aws`)**: Static IAM policy and configuration analysis evaluating wildcard actions/resources, `iam:PassRole`, S3 public/unencrypted policies, KMS key policies, local credential masking, and MFA profiles.
- **DAST Web Scanner (`sentinelscan dast`)**: Web application security analysis evaluating OpenAPI specifications, unauthenticated sensitive endpoints, HTTP security headers (HSTS, CSP, XFO, XCTO), CORS policies, server banner disclosures, and explicit `--target-url` read-only header inspection.
- **Architecture Graph (`sentinelscan graph`)**: Local read-only resource discovery and relationship graph mapping Terraform dependencies, Kubernetes workloads to Secrets/ConfigMaps/ServiceAccounts, AWS IAM policies to S3 buckets, Docker base images, and scanner security findings.

### 🔒 Security & Privacy Guarantees
- **Terminal CLI Exclusivity**: SentinelScan is strictly a terminal CLI tool. Zero web interfaces, dashboards, or web servers.
- **Zero Raw Secret Exposure**: Secret values are strictly masked using `mask_token()` before constructing finding objects or graph metadata.
- **100% Offline Default Scans**: Running `sentinelscan scan .` or `sentinelscan graph .` performs 100% offline static analysis. Target code, containers, or cloud CLI commands are **NEVER** executed.
- **Strict Read-Only Active Header Inspection**: Active HTTP checks run **ONLY** when explicitly requested via `sentinelscan dast --target-url`. Performs single read-only `HEAD`/`GET` requests with cross-host redirect safeguards. **NEVER** sends mutating requests (`POST`/`PUT`/`DELETE`), attack payloads, fuzzing, or port scans.
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

Run focused DAST web application scan (static local mode):
```bash
sentinelscan dast .
```

Run focused DAST web application scan against an explicit local HTTP target URL:
```bash
sentinelscan dast --target-url http://localhost:8080
```

Build and render local architecture resource and relationship graph (terminal ASCII tree):
```bash
sentinelscan graph .
```

Generate machine-readable architecture graph JSON output:
```bash
sentinelscan graph . --json
```

---

## 📋 Example Console Output

```text
==================================================
        SentinelScan Architecture Graph           
==================================================

TARGET DISCOVERY
  Path              : /path/to/project
  Total Nodes       : 6
  Total Edges       : 5

ARCHITECTURE GRAPH TREES
--------------------------------------------------
[k8s:Deployment:default/web-deploy] (Deployment/web-deploy)
  ├── [USES_SECRET] ---> [k8s:Secret:default/db-secret]
  │     └── [HAS_FINDING] ---> [Finding: K8S-PLAIN-TEXT-SECRET-DATA] (MEDIUM)
  └── [USES_SERVICE_ACCOUNT] ---> [k8s:ServiceAccount:default/web-sa]

[tf:aws_iam_role.app_role] (aws_iam_role/app_role)
  └── [ATTACHED_TO] ---> [tf:aws_iam_policy.app_policy]
        └── [HAS_FINDING] ---> [Finding: AWS-IAM-WILDCARD-ACTION] (CRITICAL)
--------------------------------------------------
EXECUTION COMPLETED in 0.015 seconds.
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
- [x] **v0.9.0 - Dynamic Testing & Web Security (Milestone 9)**: Web application security analysis evaluating OpenAPI specifications, unauthenticated sensitive endpoints, HTTP security headers (HSTS, CSP, XFO, XCTO), CORS policies, server banner disclosures, and explicit `--target-url` read-only header inspection.
- [x] **v1.0.0 - Architecture Graph Capability (Milestone 10)**: Local read-only architecture graph discovery mapping Terraform, Kubernetes, AWS IAM, Docker relationships, scanner finding association, terminal ASCII tree, and JSON serialization.
- [ ] **v1.1.0 - Network Security Assessment**: Authorized local port and service banner assessment module.

---

## 📖 Documentation

Comprehensive engineering documentation is maintained in the [`docs/`](docs/) directory:

- **[DEVELOPMENT_PLAN.md](docs/DEVELOPMENT_PLAN.md)**: Engineering workflow, milestone pipeline, and AI agent instructions.
- **[ARCHITECTURE.md](docs/ARCHITECTURE.md)**: System architecture specification, core engine, models, and flow diagrams.
- **[SECURITY_PRINCIPLES.md](docs/SECURITY_PRINCIPLES.md)**: Security commitments, leak prevention rules, and privacy controls.
- **[TESTING.md](docs/TESTING.md)**: Quality assurance guide, pytest suite structure, and secret leak verification.
- **[SCANNER_DEVELOPMENT.md](docs/SCANNER_DEVELOPMENT.md)**: Definitive 13-step guide for building new scanner modules.
- **[ROADMAP.md](docs/ROADMAP.md)**: Official feature matrix and capability status breakdown.
- **[Milestones](docs/milestones/)**: Historical milestone release records ([`01-foundation.md`](docs/milestones/01-foundation.md), [`02-secret-scanner.md`](docs/milestones/02-secret-scanner.md), [`03-sast.md`](docs/milestones/03-sast.md), [`04-iac.md`](docs/milestones/04-iac.md), [`05-sca.md`](docs/milestones/05-sca.md), [`06-docker.md`](docs/milestones/06-docker.md), [`07-k8s.md`](docs/milestones/07-k8s.md), [`08-aws.md`](docs/milestones/08-aws.md), [`09-dast.md`](docs/milestones/09-dast.md), [`10-architecture-graph.md`](docs/milestones/10-architecture-graph.md)).









---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

