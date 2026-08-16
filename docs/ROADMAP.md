# SentinelScan - Feature & Milestone Roadmap

This document outlines the official development roadmap for SentinelScan. Each capability is explicitly status-tagged as `IMPLEMENTED`, `IN PROGRESS`, or `PLANNED`.

---

## 🗺️ Master Feature Matrix

| Feature / Domain | Status | Milestone | Description |
| :--- | :--- | :--- | :--- |
| **CLI & Core Architecture** | `IMPLEMENTED` | v0.1.0 | Project structure, Target model, Finding model, ScanResult, ScannerRegistry, ConsoleReporter, JsonReporter, CLI handlers. |
| **Secret & Credential Scanner** | `IMPLEMENTED` | v0.2.0 | High-confidence detectors (AWS keys, GitHub PATs, JWTs, PEM private keys, DB URLs, API keys) + entropy analysis + secret value masking. |
| **Static Code Analysis (SAST)** | `IMPLEMENTED` | v0.3.0 | Python AST analyzer for dangerous dynamic code execution (`eval`, `exec`), command injection (`shell=True`, `os.system`), weak crypto (`md5`, `sha1`), and unsafe deserialization (`pickle`). |
| **Infrastructure-as-Code (IaC)** | `IMPLEMENTED` | v0.4.0 | Misconfiguration analysis for Terraform (`.tf`), CloudFormation, and SAM templates using `python-hcl2` and `PyYAML` `SafeLoader`. |
| **Software Composition Analysis (SCA)** | `IMPLEMENTED` | v0.5.0 | Vulnerability scanner for Python (`requirements.txt`, `pyproject.toml`, `poetry.lock`) and JavaScript (`package.json`, `package-lock.json`) using OSV two-stage API, npm SemVer, and local cache. |
| **Docker Security Analysis** | `IMPLEMENTED` | v0.6.0 | Static Dockerfile misconfiguration analysis (root user, base image pinning, embedded secrets, dangerous ADD, sensitive ports, missing HEALTHCHECK). |
| **Kubernetes Security Analysis** | `IMPLEMENTED` | v0.7.0 | Static Kubernetes manifest analysis (privileged containers, root users, resource limits, host namespaces, allowPrivilegeEscalation, RBAC cluster-admin, plain text secret data). |
| **AWS Cloud Posture Assessment** | `IMPLEMENTED` | v0.8.0 | Static AWS policy and posture scanner (wildcard IAM actions/resources, iam:PassRole, S3 public/unencrypted policies, KMS key policies, local credentials masking, MFA profiles). |
| **Dynamic Testing (DAST)** | `IMPLEMENTED` | v0.9.0 | Web application & DAST scanner (OpenAPI spec validation, unauthenticated endpoints, HTTP security headers, CORS policies, server banner disclosure, explicit --target-url read-only header inspection). |
| **Architecture Graph Capability** | `IMPLEMENTED` | v1.0.0 | Local read-only architecture graph discovery (Terraform, K8s, AWS IAM, Docker relationships, finding association, terminal ASCII trees, JSON serialization). |
| **Network Security Assessment** | `IMPLEMENTED` | v1.1.0 | Authorized read-only TCP connect scanning, passive banner reading, stdlib TLS handshake version inspection, and single IP target resolution (`sentinelscan network <target>`). |
| **Attack-Path & Risk Correlation** | `IMPLEMENTED` | v1.2.0 | Analytical attack path correlation engine discovering potential multi-step risk chains with max depth 5 bounds, confidence ratings, and `sentinelscan paths <path>` command. |
| **Posture Scoring & Remediation Guidance** | `IMPLEMENTED` | v1.3.0 | DevSecOps posture scoring engine (0-100 scale, A+ to F grades), domain breakdowns, deduction traceability, and prioritized fix advice (`sentinelscan posture <path>`). |











| **Kubernetes Security Analysis** | `PLANNED` | v0.6.0 | Kubernetes manifest security checks (privileged containers, missing resource limits, RBAC permissions). |
| **Software Composition Analysis (SCA)** | `PLANNED` | v0.7.0 | Dependency vulnerability scanner for `requirements.txt`, `pyproject.toml`, and `package.json`. |
| **AWS / Cloud Posture (CSPM)** | `PLANNED` | v0.8.0 | Read-only AWS posture evaluation (S3 encryption/public access, IAM policies, Security Groups). |
| **Dynamic Testing (DAST)** | `PLANNED` | v0.9.0 | Local HTTP endpoint security analysis (security headers, CORS, TLS configuration). |
| **Network Security Assessment** | `PLANNED` | v1.0.0 | Authorized local port and service banner assessment module. |
| **Architecture Analysis** | `PLANNED` | v1.1.0 | High-level system architecture and component dependency security analysis. |
| **Finding & Risk Correlation** | `PLANNED` | v1.2.0 | Multi-finding correlation engine linking secrets, code vulnerabilities, and cloud posture into unified risk models. |
| **Attack Path Analysis** | `PLANNED` | v1.3.0 | Graph-based attack path modeling tracing exploit paths from public assets to high-value secrets. |
| **Security Posture Scoring** | `PLANNED` | v1.4.0 | Algorithmic security posture score (0-100) based on severity, exposure, and asset criticality. |
| **Advanced Reporting (SARIF / HTML)** | `PLANNED` | v1.5.0 | Output generators for SARIF (GitHub Security tab) and self-contained interactive HTML dashboards. |
| **CI/CD Pipeline Integration** | `PLANNED` | v1.6.0 | GitHub Actions, GitLab CI, and pre-commit hooks integration with exit code policy controls. |

---

## 📌 Release Schedule History

- **v0.1.0 (Milestone 01 - Foundation)**: Built baseline architecture, target discoverer, engine fault isolation, models, CLI, and test suite.
- **v0.2.0 (Milestone 02 - Secret Scanner)**: Built production secret detection module, 8 detector rules, Shannon entropy analysis, length-aware secret value masking, and `sentinelscan secrets` subcommand.
- **v0.3.0 (Milestone 03 - SAST Scanner)**: Built Python SAST AST scanner module, 8 deterministic security rules, strict UTF-8 decoding, zero-execution guarantees, and `sentinelscan sast` subcommand.
- **v0.4.0 (Milestone 04 - IaC Scanner)**: Built IaC security scanner module, 8 deterministic rules, `python-hcl2` parsing, `PyYAML` CloudFormation `SafeLoader` tag handling, and `sentinelscan iac` subcommand.
- **v0.5.0 (Milestone 05 - SCA Scanner)**: Built SCA security scanner module, Python & JS dependency parsers, two-stage OSV vulnerability intelligence, npm SemVer matching, local disk cache, and `sentinelscan sca` subcommand with `--offline` support.
- **v0.6.0 (Milestone 06 - Docker Scanner)**: Built static Docker security scanner module, deterministic Dockerfile parser, multi-stage build intelligence, 8 security rules, zero CLI/daemon execution guarantees, and `sentinelscan docker` subcommand.
- **v0.7.0 (Milestone 07 - Kubernetes Scanner)**: Built static Kubernetes security scanner module, multi-document YAML parser (`PyYAML` `SafeLoader`), workload controller navigation, RBAC policy rules, secret masking, zero `kubectl` execution guarantees, and `sentinelscan k8s` subcommand.
- **v0.8.0 (Milestone 08 - AWS Scanner)**: Built static AWS policy & posture scanner module, IAM document validator (Statement object & list support), 8 security rules, credential masking via `mask_token()`, zero AWS CLI/network calls, and `sentinelscan aws` subcommand.
- **v0.9.0 (Milestone 09 - DAST Scanner)**: Built Web Application & DAST scanner module, OpenAPI v3/v2 validator, web server config parser, 8 security rules, 100% offline static default scan, explicit `--target-url` active read-only header inspector with cross-host redirect safeguards, and `sentinelscan dast` subcommand.
- **v1.0.0 (Milestone 10 - Architecture Graph)**: Built local read-only architecture graph discovery module, Node/Edge data models, relationship extraction engine (Terraform, Kubernetes, AWS IAM, Docker), finding association, terminal ASCII tree and JSON reporters, and `sentinelscan graph` subcommand.
- **v1.1.0 (Milestone 11 - Network Security Assessment)**: Built authorized read-only TCP connect scanner module (`NetworkScanner`), `NetworkTargetValidator` single IP resolution, `TcpConnectScanner` stdlib TLS handshake version inspector, 8 refined security rules, 100% offline default scan guarantee, zero subprocess execution, and `sentinelscan network` subcommand.
- **v1.2.0 (Milestone 12 - Attack-Path & Risk Correlation)**: Built analytical attack path engine (`AttackPathEngine`), `AttackStep` and `AttackPath` data models, confidence ratings (`LOW`/`MEDIUM`/`HIGH`), depth-bounded BFS traversal (max 5 hops), path hash deduplication (`AP-<hash>`), `TerminalPathReporter`, `JsonPathReporter`, and `sentinelscan paths` subcommand.
- **v1.3.0 (Milestone 13 - Posture Scoring & Remediation Guidance)**: Built explainable posture scoring engine (`PostureEngine`) and `RemediationEngine`, domain score breakdowns, grade scale (`A+` to `F`), fingerprint deduplication, anti-double-counting caps, `TerminalPostureReporter`, `JsonPostureReporter`, and `sentinelscan posture` subcommand.











