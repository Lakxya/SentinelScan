# Milestone 09 - Dynamic & Web Security Analysis Scanner (DAST)

- **Status**: `COMPLETED`
- **Release Version**: `v0.9.0`
- **Focus**: Building a Web Application and DAST scanner (`DastScanner`) inspecting static OpenAPI/Swagger API specifications, web server configuration files (Nginx, Apache, Caddy), and explicit local target HTTP response headers (`--target-url`) for security header misconfigurations, missing CORS controls, unauthenticated sensitive endpoints, and server version disclosures.

---

## 🎯 1. Goals

Implement a Web Application & DAST security scanner (`DastScanner`) integrating into SentinelScan's `BaseScanner` interface under `Category.DAST`, discovering OpenAPI specifications (`openapi.yaml`, `swagger.json`) and web server configs (`nginx.conf`, `caddyfile`), parsing API security schemes, evaluating 8 security rules, supporting explicit read-only active URL header inspection (`--target-url`), and providing CLI support via `sentinelscan dast <path>`.

---

## 🛠️ 2. Actual Capabilities Implemented

### 2.1 Static OpenAPI & Web Config Parsers
- **JSON & PyYAML SafeLoader (`json.loads`, `yaml.safe_load()`)**: Parses OpenAPI v3.x and Swagger v2.x specifications into dictionary AST objects.
- **OpenAPI Schema Validation**: Inspects `openapi:` or `swagger:` and `paths:` nodes before analyzing files, ignoring non-OpenAPI JSON/YAML files (`package.json`, `tsconfig.json`, Kubernetes manifests).
- **Web Server Config Directive Parser**: Regex-based matcher parsing security headers (`add_header`, `Header set`, `header`) in Nginx, Apache, and Caddy configuration files.

### 2.2 Active Read-Only HTTP Header Inspector (Explicit `--target-url` Mode Only)
- **Zero Network Calls in Default Scan**: Running `sentinelscan scan .` or `sentinelscan dast .` performs 100% offline static analysis.
- **Explicit Target URL Only**: Active HTTP inspection is triggered **ONLY** when the user explicitly specifies `--target-url <url>`.
- **Bounded Read-Only Inspection**: Issues a single `HEAD` or `GET` request using stdlib `urllib.request` with a short timeout (3.0s) to read HTTP response headers (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Access-Control-Allow-Origin`, `Server`).
- **Cross-Host Redirect Safeguard**: Implements `NoCrossHostRedirectHandler` preventing automatic redirection if the target host changes.

### 2.3 Security Rules Implemented

| Rule ID | Title | Severity | Confidence | Target Scope | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`DAST-MISSING-HSTS`** | Missing HTTP Strict Transport Security (HSTS) | `HIGH` | `HIGH` | Config / Headers | Lacks valid `Strict-Transport-Security` header or sets `max-age < 31536000`. |
| **`DAST-MISSING-CSP`** | Missing or Weak Content Security Policy (CSP) | `HIGH` | `HIGH` | Config / Headers | Lacks strong `Content-Security-Policy` header or includes `unsafe-inline` / `unsafe-eval`. |
| **`DAST-MISSING-X-FRAME-OPTIONS`** | Missing X-Frame-Options Clickjacking Control | `MEDIUM` | `HIGH` | Config / Headers | Lacks `X-Frame-Options` header set to `DENY` or `SAMEORIGIN`. |
| **`DAST-MISSING-X-CONTENT-TYPE-OPTIONS`** | Missing X-Content-Type-Options Protection | `LOW` | `HIGH` | Config / Headers | Lacks `X-Content-Type-Options: nosniff` header. |
| **`DAST-WILDCARD-CORS`** | Overly Permissive CORS Origin Configuration | `HIGH` | `HIGH` | Config / Headers | `Access-Control-Allow-Origin: *` or wildcard origin with credentials allowed. |
| **`DAST-SERVER-BANNER-DISCLOSURE`** | Web Server Software Version Banner Disclosed | `LOW` | `HIGH` | Config / Headers | Detailed server version disclosed in `Server` or `X-Powered-By` headers. |
| **`DAST-OPENAPI-NO-AUTH`** | Sensitive OpenAPI Endpoint Lacks Authentication | `HIGH` | `HIGH` | OpenAPI Spec | Sensitive API endpoint (`/admin`, `/user/delete`, `/api/v1/keys`) lacks security requirements. Public `/health` endpoints are excluded. |
| **`DAST-OPENAPI-HTTP-BASIC-AUTH`** | OpenAPI Specifies Unencrypted HTTP Basic Auth | `MEDIUM` | `HIGH` | OpenAPI Spec | `securitySchemes` defines HTTP Basic authentication (`scheme: basic`). |

### 2.4 Security & Privacy Safeguards
- **Zero Network Socket Calls in Default Scan**: 100% offline static analysis during `sentinelscan scan .`.
- **Zero Mutating Requests**: Never sends `POST`, `PUT`, `DELETE`, `PATCH`, `OPTIONS`, or `TRACE` HTTP requests.
- **Zero Fuzzing or Exploitation**: Never sends attack payloads, SQL injection vectors, or directory traversal tests.
- **Zero Command Execution**: Never runs external network scanning tools (`nmap`, `zap`, `nikto`).
- **Read-Only**: Target files and active endpoints are never modified.

---

## 📁 3. Files Created & Modified

- `src/sentinelscan/scanners/dast_scanner.py` (New `DastScanner` module, `OpenApiParser`, `WebConfigParser`, `HttpHeaderInspector`, `NoCrossHostRedirectHandler`)
- `src/sentinelscan/scanners/registry.py` (Auto-registered `DastScanner` by default)
- `src/sentinelscan/scanners/__init__.py` (Exported `DastScanner`)
- `src/sentinelscan/cli/main.py` (Added `dast` subcommand parser with `--target-url`)
- `src/sentinelscan/cli/commands.py` (Added `handle_dast()`)
- `src/sentinelscan/cli/__init__.py` (Exported `handle_dast`)
- `tests/unit/test_dast_scanner.py` (Unit test suite covering OpenAPI spec parsing, web server header analysis, CORS checks, unauthenticated API detection, static mode zero-network assertions, cross-host redirect prevention, and JSON output)
- `tests/unit/test_cli.py` (Added CLI tests for `dast` command)
- `README.md`, `IMPLEMENTATION.md`, `CONTRIBUTING.md`, `docs/ROADMAP.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY_PRINCIPLES.md` (Updated documentation)

---

## 4. Test & Verification Results

- **`pytest`**: **89 passing tests** (1.58s).
- **`ruff check .`**: 0 errors.
- **`mypy src/sentinelscan`**: 0 issues across 29 source files.
- **Manual Verification**: Executed `sentinelscan --help`, `sentinelscan scan .`, `sentinelscan dast .`, `sentinelscan dast . --json`.

---

## 5. Known Limitations at Milestone 09 Completion

- Static OpenAPI analysis inspects declared API schema specifications. Active HTTP response header checking evaluates web server headers on user-supplied target URLs but does not perform intrusive vulnerability exploitation.
