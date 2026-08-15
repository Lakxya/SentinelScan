# Milestone 04 - Infrastructure-as-Code (IaC) Security Scanner

- **Status**: `COMPLETED`
- **Release Version**: `v0.4.0`
- **Focus**: Building a local-first IaC security scanner (`IacScanner`) analyzing Terraform HCL, CloudFormation, and SAM templates locally using `python-hcl2` and `PyYAML` `SafeLoader`, 8 deterministic security rules, and `sentinelscan iac` CLI command.

---

## 🎯 1. Goals

Implement a static IaC configuration scanner (`IacScanner`) integrating into SentinelScan's `BaseScanner` interface, inspecting Terraform (`.tf`), CloudFormation (`.yaml`/`.yml`/`.json`), and SAM templates without deploying infrastructure, executing external CLI binaries, validating credentials against AWS APIs, or making network calls.

---

## 🛠️ 2. Actual Capabilities Implemented

### 2.1 Implemented Rules & Rule IDs
1. **Security Group Open Ingress to World** (`IAC-AWS-SG-OPEN-INGRESS`): Detects ingress rules permitting `0.0.0.0/0` or `::/0` on sensitive ports (SSH 22, RDP 3389, DB ports 3306/5432/1433/27017/6379) or all ports (`-1`) in Terraform `aws_security_group` and CloudFormation `AWS::EC2::SecurityGroup` (`HIGH`, `HIGH`/`MEDIUM`).
2. **Public S3 Bucket ACL** (`IAC-AWS-S3-PUBLIC-ACL`): Detects bucket `acl` configured as `public-read` or `public-read-write` (`AccessControl: PublicRead`/`PublicReadWrite`) (`HIGH`, `HIGH`).
3. **S3 Public Access Block Disabled** (`IAC-AWS-S3-PUBLIC-BLOCK-DISABLED`): Detects public access block flags explicitly set to `false` (`HIGH`, `HIGH`).
4. **Unencrypted S3 Bucket** (`IAC-AWS-S3-UNENCRYPTED`): Detects missing server-side encryption configurations on S3 buckets (`MEDIUM`, `HIGH`).
5. **IAM Policy Wildcard Action** (`IAC-AWS-IAM-WILDCARD-ACTION`): Detects IAM policy statements allowing `"Action": "*"` or `"s3:*"` with `"Effect": "Allow"` (`HIGH`, `HIGH`).
6. **IAM Policy Wildcard Resource** (`IAC-AWS-IAM-WILDCARD-RESOURCE`): Detects IAM policy statements allowing `"Resource": "*"` with wildcard actions (`MEDIUM`, `MEDIUM`).
7. **Publicly Accessible Database Instance** (`IAC-AWS-RDS-PUBLIC`): Detects RDS instances with `publicly_accessible = true` (`PubliclyAccessible: true`) (`HIGH`, `HIGH`).
8. **Unencrypted RDS Storage** (`IAC-AWS-RDS-UNENCRYPTED`): Detects RDS instances with `storage_encrypted = false` (`StorageEncrypted: false`) (`MEDIUM`, `HIGH`).

### 2.2 Parser Strategy & Safety Principles
- **Terraform HCL Parsing**: Uses `python-hcl2` (grammar-based LALR(1) parser built on Lark) to parse `.tf` syntax into Python structures without regex fragility or HCL code execution.
- **CloudFormation Safe YAML Parsing**: Uses `PyYAML>=6.0` with a custom `CloudFormationSafeLoader` subclassing `yaml.SafeLoader`. Intrinsic function tags (`!Ref`, `!Sub`, `!GetAtt`, `!FindInMap`, `!Join`, `!Select`, `!ImportValue`, `!Condition`, etc.) are transformed into safe dictionary mappings (`{"Ref": "..."}`) without executing code.
- **Line Number Tracking**: YAML loader attaches `__line__` metadata to parsed dictionary nodes (`node.start_mark.line + 1`). Terraform loader attaches resource line index locations.
- **Read-Only & Zero Network**: Zero socket calls, zero AWS STS credential checks, and zero external CLI command executions (`terraform`, `aws`, `kubectl`, `sam`).

### 2.3 CLI Integration
- `IacScanner` auto-registered in `ScannerRegistry` by default (`sentinelscan scan .` automatically runs IaC analysis when IaC files are present).
- Dedicated CLI command added: `sentinelscan iac <path>` with `--json` and `--verbose` options.

---

## 📁 3. Files Created & Modified

- `src/sentinelscan/scanners/iac_scanner.py` (New IacScanner module & CloudFormationSafeLoader)
- `src/sentinelscan/scanners/registry.py` (Auto-registered IacScanner by default)
- `src/sentinelscan/scanners/__init__.py` (Exported IacScanner)
- `src/sentinelscan/cli/main.py` (Added `iac` subcommand parser)
- `src/sentinelscan/cli/commands.py` (Added `handle_iac()`)
- `pyproject.toml` (Added `PyYAML>=6.0` and `python-hcl2>=4.3.0` dependencies)
- `tests/unit/test_iac_scanner.py` (Comprehensive unit test suite for IaC rules, HCL2 parsing, CloudFormation safe loading, malformed files, and CLI commands)
- `tests/unit/test_cli.py` (Added CLI tests for `iac` command)
- `README.md`, `IMPLEMENTATION.md`, `CONTRIBUTING.md`, `docs/ROADMAP.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY_PRINCIPLES.md` (Updated documentation)

---

## 🧪 4. Test & Verification Results

- **`pytest`**: **45 passing tests** (0.72s) covering Terraform HCL, CloudFormation YAML/JSON, SAM templates, intrinsic tag security, line numbers, non-CloudFormation YAML exclusions, malformed syntax handling, and CLI commands.
- **`ruff check .`**: 0 errors.
- **`mypy src/sentinelscan`**: 0 issues across 24 source files.
- **Manual Verification**: Executed `sentinelscan --help`, `sentinelscan scan .`, `sentinelscan iac .`, `sentinelscan iac . --json`.

---

## 📌 5. Known Limitations at Milestone 04 Completion

- Static configuration analysis inspects declared template values. Dynamic Terraform expressions (e.g. `var.custom_cidr`) or dynamic CloudFormation parameters (`!Ref ParamCidr`) where values are passed at deployment time cannot be evaluated without runtime variable context and are reported with `Confidence.MEDIUM`.
- Does not connect to live AWS environments to verify if resources are currently deployed or active.
