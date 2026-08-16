"""Network Security Assessment Scanner evaluating open TCP service ports, protocol banners, and TLS versions."""

import logging
import socket
import ssl
from dataclasses import dataclass
from pathlib import Path

from sentinelscan.models.finding import Category, Confidence, Finding, Location, Severity
from sentinelscan.models.target import Target
from sentinelscan.scanners.base import BaseScanner
from sentinelscan.scanners.secret_scanner import mask_token

logger = logging.getLogger("sentinelscan.scanners.network_scanner")

# Default top security-critical ports
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
    1433, 1521, 2375, 3306, 3389, 5432, 5900, 6379, 6443, 8080, 8443, 27017,
]

DATABASE_PORTS = {
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    1433: "MSSQL",
    1521: "Oracle DB",
}


@dataclass
class NetworkService:
    """Dataclass representing an identified open network service."""

    host: str
    ip: str
    port: int
    is_open: bool
    banner: str
    has_tls: bool
    tls_version: str | None


class NetworkTargetValidator:
    """Validator for explicit network target hosts enforcing single IP resolution and CIDR rejection."""

    @staticmethod
    def validate_and_resolve(target_host: str) -> str | None:
        """Validate target host string and resolve to single IP address.

        Args:
            target_host: Target host string (e.g. "127.0.0.1", "localhost", "api.local").

        Returns:
            Resolved single IP address string or None if target is invalid/CIDR.
        """
        host_str = target_host.strip().lower()
        if not host_str:
            return None

        # Rejects subnet CIDR notation (/0, /16, /24) to prevent sweep abuse
        if "/" in host_str:
            logger.warning("Subnet CIDR scanning is prohibited: %s", target_host)
            return None

        try:
            # Resolve host string to single primary IP address
            ip = socket.gethostbyname(host_str)
            return ip
        except Exception as e:  # noqa: BLE001
            logger.debug("Failed to resolve target host %s: %s", target_host, e)
            return None


class TcpConnectScanner:
    """Inspector for read-only TCP stream connect scanning, banner reading, and TLS version verification."""

    @staticmethod
    def inspect_port(target_host: str, target_ip: str, port: int, timeout: float = 0.5) -> NetworkService | None:
        sock = None
        try:
            sock = socket.create_connection((target_ip, port), timeout=timeout)
        except (TimeoutError, OSError):
            return None

        banner = ""
        try:
            sock.settimeout(0.3)
            raw = sock.recv(256)
            if raw:
                banner = raw.decode("utf-8", errors="replace").strip()
        except Exception:  # noqa: BLE001
            banner = ""

        # Perform stdlib TLS handshake version inspection on TLS ports (443, 8443, etc.)
        has_tls = False
        tls_version = None

        if port in (443, 8443) or "ssl" in banner.lower() or "tls" in banner.lower():
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(sock, server_hostname=target_host) as ssl_sock:
                    has_tls = True
                    tls_version = ssl_sock.version()
            except Exception as e:  # noqa: BLE001
                logger.debug("TLS handshake failed for %s:%d: %s", target_host, port, e)
        else:
            try:
                sock.close()
            except Exception as e:  # noqa: BLE001
                logger.debug("Socket close error for %s:%d: %s", target_host, port, e)


        return NetworkService(
            host=target_host,
            ip=target_ip,
            port=port,
            is_open=True,
            banner=banner,
            has_tls=has_tls,
            tls_version=tls_version,
        )


class NetworkScanner(BaseScanner):
    """Network security assessment scanner evaluating open TCP service ports, protocol banners, and TLS versions."""

    def __init__(self, target_host: str | None = None, ports: list[int] | None = None) -> None:
        self.target_host = target_host
        self.ports = ports if ports else DEFAULT_PORTS

    @property
    def name(self) -> str:
        return "network-scanner"

    @property
    def category(self) -> Category:
        return Category.NETWORK

    @property
    def description(self) -> str:
        return "Network security assessment scanner evaluating open TCP service ports, protocol banners, and TLS versions."

    def is_available(self, target: Target) -> bool:
        return True

    def scan(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        # CRITICAL SAFETY GUARANTEE: In standard local directory scans (sentinelscan scan .),
        # self.target_host is None and NetworkScanner executes ZERO network calls.
        if not self.target_host:
            return findings

        resolved_ip = NetworkTargetValidator.validate_and_resolve(self.target_host)
        if not resolved_ip:
            logger.warning("Invalid or unresolvable network target: %s", self.target_host)
            return findings

        for port in self.ports:
            svc = TcpConnectScanner.inspect_port(self.target_host, resolved_ip, port)
            if svc:
                self._evaluate_rules(svc, findings)

        return findings

    def _evaluate_rules(self, svc: NetworkService, findings: list[Finding]) -> None:
        resource_id = f"{svc.host}:{svc.port}"
        loc = Location(file_path=Path(resource_id), start_line=1)
        masked_banner = mask_token(svc.banner) if svc.banner else ""

        # 1. NET-EXPOSED-DOCKER-API
        if svc.port == 2375:
            findings.append(
                Finding(
                    scanner="network-scanner",
                    category=Category.NETWORK,
                    rule_id="NET-EXPOSED-DOCKER-API",
                    title=f"Exposed Docker Daemon API Port in {resource_id}",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description=f"Docker Daemon API port 2375 is open and network accessible on '{resource_id}'.",
                    impact="Exposes Docker management port to remote network access.",
                    remediation="Restrict network access via firewalls and enforce TLS mutual authentication.",
                    location=loc,
                    resource_id=resource_id,
                )
            )

        # 2. NET-EXPOSED-K8S-API
        if svc.port == 6443:
            findings.append(
                Finding(
                    scanner="network-scanner",
                    category=Category.NETWORK,
                    rule_id="NET-EXPOSED-K8S-API",
                    title=f"Exposed Kubernetes API Server Port in {resource_id}",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description=f"Kubernetes API server port 6443 is open and network accessible on '{resource_id}'.",
                    impact="Exposes Kubernetes cluster API server port to remote network access.",
                    remediation="Restrict API server exposure via Security Groups and RBAC/VPN.",
                    location=loc,
                    resource_id=resource_id,
                )
            )

        # 3. NET-EXPOSED-DATABASE
        if svc.port in DATABASE_PORTS:
            db_name = DATABASE_PORTS[svc.port]
            findings.append(
                Finding(
                    scanner="network-scanner",
                    category=Category.NETWORK,
                    rule_id="NET-EXPOSED-DATABASE",
                    title=f"Exposed Database Service Port ({db_name}) in {resource_id}",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description=f"Exposed {db_name} database port {svc.port} open on '{resource_id}'.",
                    impact="Exposes database management ports to remote network reconnaissance.",
                    remediation="Bind database listener to 127.0.0.1 or enforce firewall rules.",
                    location=loc,
                    resource_id=resource_id,
                )
            )

        # 4. NET-UNENCRYPTED-TELNET
        if svc.port == 23:
            findings.append(
                Finding(
                    scanner="network-scanner",
                    category=Category.NETWORK,
                    rule_id="NET-UNENCRYPTED-TELNET",
                    title=f"Unencrypted Telnet Service Exposed in {resource_id}",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description=f"Unencrypted Telnet management service port 23 open on '{resource_id}'.",
                    impact="Transmits management credentials in plain text across the network.",
                    remediation="Disable Telnet service and migrate to SSH (TCP 22) for remote management.",
                    location=loc,
                    resource_id=resource_id,
                )
            )

        # 5. NET-UNENCRYPTED-FTP
        if svc.port == 21:
            findings.append(
                Finding(
                    scanner="network-scanner",
                    category=Category.NETWORK,
                    rule_id="NET-UNENCRYPTED-FTP",
                    title=f"Unencrypted FTP Service Exposed in {resource_id}",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description=f"Unencrypted FTP file transfer service port 21 open on '{resource_id}'.",
                    impact="Transmits file transfer data and user credentials in unencrypted plain text.",
                    remediation="Upgrade file transfer services to SFTP or FTPS (TLS).",
                    location=loc,
                    resource_id=resource_id,
                )
            )

        # 6. NET-UNENCRYPTED-HTTP-SERVICE
        if svc.port in (80, 8080) and not svc.has_tls:
            findings.append(
                Finding(
                    scanner="network-scanner",
                    category=Category.NETWORK,
                    rule_id="NET-UNENCRYPTED-HTTP-SERVICE",
                    title=f"Unencrypted HTTP Web Service in {resource_id}",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    description=f"HTTP web service open on port {svc.port} without SSL/TLS encryption.",
                    impact="Transmits web traffic in cleartext, vulnerable to credential sniffing and session hijacking.",
                    remediation="Enforce HTTPS encryption with valid TLS certificates for all web services.",
                    location=loc,
                    resource_id=resource_id,
                )
            )

        # 7. NET-EXPOSED-REMOTE-DESKTOP
        if svc.port in (3389, 5900):
            rd_name = "RDP" if svc.port == 3389 else "VNC"
            findings.append(
                Finding(
                    scanner="network-scanner",
                    category=Category.NETWORK,
                    rule_id="NET-EXPOSED-REMOTE-DESKTOP",
                    title=f"Exposed Remote Desktop Interface ({rd_name}) in {resource_id}",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description=f"Exposed {rd_name} graphical administration port {svc.port} open on '{resource_id}'.",
                    impact="Exposes graphical administration interfaces to remote network access.",
                    remediation="Restrict RDP/VNC access behind a secure VPN gateway or SSH tunnel.",
                    location=loc,
                    resource_id=resource_id,
                )
            )

        # 8. NET-WEAK-TLS-PROTOCOL
        if svc.has_tls and svc.tls_version in ("SSLv3", "TLSv1", "TLSv1.1"):
            findings.append(
                Finding(
                    scanner="network-scanner",
                    category=Category.NETWORK,
                    rule_id="NET-WEAK-TLS-PROTOCOL",
                    title=f"Legacy SSL/TLS Protocol Version ({svc.tls_version}) in {resource_id}",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    description=f"TLS handshake metadata inspection detected legacy protocol '{svc.tls_version}' on '{resource_id}'.",
                    impact="Exposes network traffic to protocol downgrade attacks (e.g. POODLE, BEAST).",
                    remediation="Upgrade TLS daemon configuration to support TLS 1.2 and TLS 1.3 only.",
                    location=loc,
                    resource_id=resource_id,
                )
            )

        # Verbose service banner disclosure check
        if masked_banner and any(c.isdigit() for c in masked_banner):
            findings.append(
                Finding(
                    scanner="network-scanner",
                    category=Category.NETWORK,
                    rule_id="NET-VERBOSE-SERVICE-BANNER",
                    title=f"Detailed Software Version Banner Disclosed in {resource_id}",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    description=f"Service on '{resource_id}' disclosed detailed software version banner: '{masked_banner}'.",
                    impact="Discloses exact software version details, simplifying CVE lookup and targeted attacks.",
                    remediation="Reconfigure service daemon to suppress version information in banners.",
                    location=loc,
                    resource_id=resource_id,
                )
            )
