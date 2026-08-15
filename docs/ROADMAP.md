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
| **Docker Security Analysis** | `PLANNED` | v0.6.0 | Dockerfile security analysis (root user, unpinned base image, hardcoded secrets, unsafe instructions). |



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



