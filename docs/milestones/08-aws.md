# Milestone 08 - AWS Security Posture Analysis Scanner

- **Status**: `COMPLETED`
- **Release Version**: `v0.8.0`
- **Focus**: Building a static AWS security posture scanner (`AwsScanner`) inspecting local IAM policies, S3/KMS resource policies, Trust policies, and local `.aws/config` files for security misconfigurations, wildcard permissions, unencrypted transport, and plaintext access keys without executing AWS CLI commands, live API calls, or remote socket connections.

---

## 🎯 1. Goals

Implement a static AWS policy and posture scanner (`AwsScanner`) integrating into SentinelScan's `BaseScanner` interface under `Category.CLOUD`, discovering IAM policy documents (`*.json`, `*.yaml`, `*.yml`) and local configuration files (`.aws/credentials`, `.aws/config`), validating policy document schemas, evaluating 8 deterministic rules, and providing CLI support via `sentinelscan aws <path>`.

---

## 🛠️ 2. Actual Capabilities Implemented

### 2.1 Safe IAM Policy & Config Parser
- **JSON & PyYAML SafeLoader (`json.loads`, `yaml.safe_load()`)**: Safely parses policy documents into dictionary AST objects without dynamic execution.
- **IAM Policy Document Structural Validation**: Inspects `Version` (`2012-10-17` or `2008-10-17`) and `Statement` nodes before analyzing files, ignoring non-AWS JSON/YAML files (`package.json`, `tsconfig.json`, Docker Compose, Kubernetes manifests).
- **Statement Normalization**: Supports `Statement` declared as a dictionary object (`"Statement": {...}`) or list of dictionaries (`"Statement": [...]`).
- **Local AWS INI Config Parser**: Reads `.aws/credentials` and `.aws/config` files using `configparser`.

### 2.2 Security Rules Implemented

| Rule ID | Title | Severity | Confidence | Target Scope | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`AWS-IAM-WILDCARD-ACTION`** | IAM Policy Grants Full Wildcard Action | `CRITICAL` | `HIGH` | IAM Statement | `Effect: Allow` with `Action: "*"` or `Action: ["*"]`. (Does not flag `Effect: Deny`). |
| **`AWS-IAM-WILDCARD-RESOURCE`** | Sensitive Action Granted on Wildcard Resource | `HIGH` | `HIGH` | IAM Statement | `Effect: Allow` with sensitive actions (`s3:GetObject`, `kms:Decrypt`, `secretsmanager:GetSecretValue`) on `Resource: "*"`. |
| **`AWS-IAM-PASSROLE-WILDCARD`** | `iam:PassRole` Granted on Wildcard Resource | `HIGH` | `HIGH` | IAM Statement | `Effect: Allow` with `Action: "iam:PassRole"` on `Resource: "*"`. |
| **`AWS-S3-PUBLIC-POLICY`** | S3 Bucket Policy Allows Anonymous Access | `CRITICAL` / `MEDIUM` | `HIGH` / `MEDIUM` | S3 Policy | `Principal: "*"` without restrictive conditions (`Severity.CRITICAL`); or with restrictive Condition (`Severity.MEDIUM`). |
| **`AWS-S3-UNENCRYPTED-POLICY`** | S3 Bucket Policy Lacks SSL Transport Enforcement | `MEDIUM` | `HIGH` | S3 Policy | Statement allows `aws:SecureTransport: false` or lacks `aws:SecureTransport` SSL condition. |
| **`AWS-KMS-WILDCARD-PRINCIPAL`** | KMS Key Policy Allows Anonymous Principal | `HIGH` | `HIGH` | KMS Policy | `Effect: Allow` with `Principal: "*"` for KMS cryptographic actions (`kms:Decrypt`, `kms:GenerateDataKey`). |
| **`AWS-LOCAL-PLAINTEXT-CREDENTIALS`** | Long-Term AWS Credentials in Local File | `MEDIUM` | `HIGH` | `.aws/credentials` | Static access key ID and secret access key stored in local file. Keys are strictly masked in findings via `mask_token()`. |
| **`AWS-LOCAL-CONFIG-NO-MFA`** | Elevated Profile Lacks MFA Requirement | `LOW` | `HIGH` | `.aws/config` | Elevated role-assumption profile (`role_arn` / `source_profile`) lacking `mfa_serial`. |

### 2.3 False Positive Mitigation & Intelligence
- **Explicit `Effect: Deny` Exclusions**: Deny statements are explicit security enforcement boundaries and never generate allow-based wildcard findings.
- **Restrictive Condition Intelligence**: Restrictive `Condition` blocks (e.g. `aws:PrincipalOrgID`) on wildcard principals reduce finding severity to `Severity.MEDIUM` and `Confidence.MEDIUM`.
- **Conservative Elevated Profile Evaluation**: Missing `mfa_serial` is evaluated ONLY for elevated role profiles containing `role_arn` or `source_profile`.
- **Secret Value Masking**: Access key IDs and secret access keys are masked via `mask_token()` before constructing finding objects.

### 2.4 Security & Privacy Safeguards
- **Zero Command Execution**: Never runs `aws` CLI, `cdk`, `sam`, or shell commands.
- **Zero Network Socket Calls**: 100% offline static policy analysis. Zero cloud socket calls.
- **Zero Secret Leakage**: Access keys are masked in findings, logs, reports, and test output.
- **Read-Only**: Target files are never modified.

---

## 📁 3. Files Created & Modified

- `src/sentinelscan/scanners/aws_scanner.py` (New `AwsScanner` module and `AwsPolicyParser`)
- `src/sentinelscan/scanners/registry.py` (Auto-registered `AwsScanner` by default)
- `src/sentinelscan/scanners/__init__.py` (Exported `AwsScanner`)
- `src/sentinelscan/cli/main.py` (Added `aws` subcommand parser)
- `src/sentinelscan/cli/commands.py` (Added `handle_aws()`)
- `src/sentinelscan/cli/__init__.py` (Exported `handle_aws`)
- `tests/unit/test_aws_scanner.py` (Unit test suite covering Statement object/list, IAM rules, S3 public policy, KMS policies, credential masking, non-AWS file exclusions, and JSON output)
- `tests/unit/test_cli.py` (Added CLI tests for `aws` command)
- `README.md`, `IMPLEMENTATION.md`, `CONTRIBUTING.md`, `docs/ROADMAP.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY_PRINCIPLES.md` (Updated documentation)

---

## 4. Test & Verification Results

- **`pytest`**: **80 passing tests** (1.42s).
- **`ruff check .`**: 0 errors.
- **`mypy src/sentinelscan`**: 0 issues across 28 source files.
- **Manual Verification**: Executed `sentinelscan --help`, `sentinelscan scan .`, `sentinelscan aws .`, `sentinelscan aws . --json`.

---

## 5. Known Limitations at Milestone 08 Completion

- Static IAM policy analysis inspects declared policy JSON/YAML text. It does not evaluate live AWS account runtime state or service control policies (SCPs) unless static policy manifests are present.
