# Milestone 11 - Network Security Assessment

- **Status**: `COMPLETED`
- **Release Version**: `v1.1.0`
- **Focus**: Authorized Network Security Assessment scanner (`NetworkScanner`) performing read-only TCP connect scanning, passive banner reading, and stdlib TLS handshake protocol version inspection against explicit user-specified target hosts (`sentinelscan network <target>`).

---

## 🎯 1. Goals

Implement a production-oriented Network Security Assessment scanner (`NetworkScanner`) under `Category.NETWORK` that inspects open TCP ports, protocol banners, and TLS handshake versions on user-requested target hosts, while guaranteeing that default scans (`sentinelscan scan .`) remain 100% network-free and executing zero external scanner subprocesses.

---

## 🛠️ 2. Actual Capabilities Implemented

### 2.1 Target Validation & Single-Address Resolution (`NetworkTargetValidator`)
- **Single IP Resolution**: Resolves user-provided hostnames to a single primary IP address via `socket.gethostbyname()`.
- **Subnet Sweep Rejection**: Rejects CIDR notation (`/0`, `/16`, `/24`) to prevent unauthorized scanning.

### 2.2 Read-Only TCP Connect & TLS Inspector (`TcpConnectScanner`)
- **Stdlib Socket Connection**: Uses `socket.create_connection((ip, port), timeout=0.5)`.
- **Passive Banner Reading**: Reads up to 256 bytes passively for protocol banners (`SSH-2.0`, `HTTP/1.1`, `220 FTP`).
- **Stdlib TLS Version Inspection**: Performs TLS handshake using `ssl.create_default_context().wrap_socket()` to read `ssl_object.version()`.

### 2.3 Refined Security Rules Inventory
- **`NET-EXPOSED-DOCKER-API`**: Exposed Docker Daemon API Port 2375 open and reachable (`Severity.HIGH`, `Confidence.HIGH`).
- **`NET-EXPOSED-K8S-API`**: Exposed Kubernetes API Server Port 6443 open and reachable (`Severity.HIGH`, `Confidence.HIGH`).
- **`NET-EXPOSED-DATABASE`**: Exposed Database Service Port open (3306 MySQL, 5432 PostgreSQL, 6379 Redis, 27017 MongoDB) (`Severity.HIGH`, `Confidence.HIGH`).
- **`NET-UNENCRYPTED-TELNET`**: Unencrypted Telnet Service Port 23 open (`Severity.HIGH`, `Confidence.HIGH`).
- **`NET-UNENCRYPTED-FTP`**: Unencrypted FTP Service Port 21 open (`Severity.HIGH`, `Confidence.HIGH`).
- **`NET-UNENCRYPTED-HTTP-SERVICE`**: Unencrypted HTTP Web Service Port 80/8080 open without TLS (`Severity.MEDIUM`, `Confidence.HIGH`).
- **`NET-EXPOSED-REMOTE-DESKTOP`**: Exposed Remote Desktop Interface Port (3389 RDP, 5900 VNC) open (`Severity.HIGH`, `Confidence.HIGH`).
- **`NET-WEAK-TLS-PROTOCOL`**: Legacy SSL/TLS Protocol Version (`SSLv3`, `TLSv1`, `TLSv1.1`) detected during TLS handshake inspection (`Severity.MEDIUM`, `Confidence.HIGH`).
- **`NET-VERBOSE-SERVICE-BANNER`**: Detailed software version disclosed in protocol banner (`Severity.LOW`, `Confidence.HIGH`).

### 2.4 Security & Privacy Safeguards
- **100% Offline Default Scan Guarantee**: Standard local scans (`sentinelscan scan .`) execute **zero network socket calls**.
- **Zero Subprocess Execution**: Uses standard library `socket` and `ssl`. Never runs `nmap`, `masscan`, `nc`, or `netcat`.
- **Zero Exploitation**: Read-only connect checks. Never sends attack payloads, SQL injection vectors, or brute-force passwords.
- **Secret Value Masking**: Sanitizes banner response data using `mask_token()`.

---

## 📁 3. Files Created & Modified

- `src/sentinelscan/scanners/network_scanner.py` (New `NetworkScanner`, `NetworkTargetValidator`, `TcpConnectScanner`)
- `tests/unit/test_network_scanner.py` (New test suite covering single IP validation, TCP connect scanning, stdlib TLS version inspection, rules, zero network in static scan, zero subprocess assertions, and JSON serialization)
- `docs/milestones/11-network-security.md` (New release document)
- `src/sentinelscan/models/finding.py` (Added `Category.NETWORK`)
- `src/sentinelscan/models/graph.py` (Added `NodeType.NETWORK_SERVICE` and `EdgeType.EXPOSES_SERVICE`)
- `src/sentinelscan/scanners/registry.py` (Auto-registered `NetworkScanner`)
- `src/sentinelscan/scanners/__init__.py` (Exported `NetworkScanner`)
- `src/sentinelscan/cli/commands.py` (Added `handle_network()`)
- `src/sentinelscan/cli/main.py` (Added `network` subcommand parser)
- `src/sentinelscan/cli/__init__.py` (Exported `handle_network`)
- `tests/unit/test_cli.py` (Added `test_cli_network_command`)
- `README.md`, `IMPLEMENTATION.md`, `CONTRIBUTING.md`, `docs/ROADMAP.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY_PRINCIPLES.md` (Updated documentation)

---

## 4. Test & Verification Results

- **`pytest`**: **105 passing tests** (4.61s).
- **`ruff check .`**: All checks passed cleanly (**0 errors**).
- **`mypy src/sentinelscan`**: Success with **0 type issues** across 33 source files.
- **Manual Verification**: Executed `sentinelscan network 127.0.0.1`, `sentinelscan network 127.0.0.1 --json`, `sentinelscan scan .`.

---

## 5. Known Limitations at Milestone 11 Completion

- `NetworkScanner` performs non-intrusive TCP connect checks, passive banner reading, and stdlib TLS handshake version inspection. It does not claim authentication status, perform raw packet injection (SYN stealth scans requiring root privileges), exploit execution, or credential brute forcing.
