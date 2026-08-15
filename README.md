# SentinelScan 🛡️

> **SentinelScan** is an open-source, local-first DevSecOps and cloud security assessment CLI.

---

## 🎯 Overview

SentinelScan is designed to provide security engineers, developers, and DevOps teams with a single, unified local command-line tool for multi-domain security assessments.

The long-term goal of SentinelScan is to seamlessly combine 12 security domains into a single auditable workflow:

1. **Static Application Security Testing (SAST)**
2. **Software Composition Analysis (SCA)**
3. **Dynamic Application Security Testing (DAST)**
4. **Secret & Credential Detection**
5. **Docker Security Analysis**
6. **Kubernetes Security Analysis**
7. **Infrastructure-as-Code (IaC) Assessment**
8. **AWS & Cloud Posture Assessment**
9. **Network Security Assessment**
10. **Architecture Analysis**
11. **Attack-Path & Risk Correlation**
12. **Posture Scoring & Remediation Guidance**

---

## 📌 Current Milestone & Status

> [!NOTE]
> **Current Version: `v0.1.0` (Production Baseline Foundation)**
>
> SentinelScan is currently in its initial architecture milestone. The core CLI, target discovery engine, unified finding model, scanner interface, scanner registry, report formatters, and test suite are fully operational.
> 
> *Domain scanner detection modules (SAST, SCA, DAST, Secrets, Cloud, Containers) are being prepared for subsequent releases.*

---

## ⚡ Quickstart & Installation

### Prerequisites
- **Python 3.11+**

### Installation

Clone the repository and install SentinelScan in editable mode:

```bash
git clone https://github.com/sentinelscan/sentinelscan.git
cd SentinelScan
pip install -e .
```

To install development dependencies (testing and linting tools):

```bash
pip install -e ".[dev]"
```

---

## 💻 CLI Usage

Check version:
```bash
sentinelscan --version
```

View command help:
```bash
sentinelscan --help
```

Run security assessment against current directory:
```bash
sentinelscan scan .
```

Generate machine-readable JSON output:
```bash
sentinelscan scan . --json
```

Enable verbose debug logging:
```bash
sentinelscan scan . --verbose
```

---

## 🏗️ Core Architecture & Security Design

SentinelScan is built around key security principles:
- **Local-First Execution**: All assessments run locally without sending source code or project artifacts to third-party endpoints.
- **Data Protection & Least Privilege**: Raw credentials, private keys, or raw source snippets are never logged or stored in finding models.
- **Scanner Failure Isolation**: An unhandled exception in one scanner module is safely trapped and reported separately; it will never crash or abort the rest of the scan.
- **Correlation Ready**: Findings contain deterministic fingerprints (`FS-<hash>`), tags, and resource identifiers to prepare for future attack-path correlation.
- **Auditable & Deterministic**: Uniform data schemas allow reproducible security scans across local and CI/CD pipelines.

---

## 🗺️ Roadmap

- [x] **v0.1.0 - Foundation & Architecture**: Core CLI, target discovery, scanner interface, data models, reporters, test suite, and docs.
- [ ] **v0.2.0 - Secret Detection & SAST Baseline**: Static code analyzer and high-entropy secret scanner.
- [ ] **v0.3.0 - Container & IaC Security**: Dockerfile, Kubernetes manifests, and Terraform misconfiguration scanners.
- [ ] **v0.4.0 - Software Composition Analysis (SCA)**: Dependency vulnerability and license compliance scanning.
- [ ] **v0.5.0 - Cloud Posture (AWS)**: Read-only AWS security posture assessment module.
- [ ] **v0.6.0 - Risk Correlation & Attack-Path Analysis**: Multi-finding correlation engine, posture scoring, and remediation reports.

---

## 📖 Documentation

- **[IMPLEMENTATION.md](IMPLEMENTATION.md)**: Deep dive into project design decisions, scanner abstraction, models, and architecture.
- **[CONTRIBUTING.md](CONTRIBUTING.md)**: Developer guide for setup, running tests, linting, and adding custom scanner modules.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
