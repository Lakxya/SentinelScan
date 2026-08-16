"""Web Application and DAST Security Scanner evaluating OpenAPI specs, web server security headers, and CORS policies."""

import json
import logging
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from sentinelscan.models.finding import Category, Confidence, Finding, Location, Severity
from sentinelscan.models.target import Target
from sentinelscan.scanners.base import BaseScanner

logger = logging.getLogger("sentinelscan.scanners.dast_scanner")

# Maximum file size to scan (5 MB)
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024

# Directories ignored during recursive filesystem traversal
EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "build",
    "dist",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".sentinelscan",
}

# Sensitive API endpoint path keywords
SENSITIVE_PATH_KEYWORDS = re.compile(
    r"(?i)(/admin|/user|/delete|/key|/token|/account|/internal|/auth|/credential|/config|/management)"
)

# Harmless public utility endpoints to exclude from no-auth findings
PUBLIC_PATH_KEYWORDS = re.compile(r"(?i)(/health|/metrics|/ping|/docs|/swagger|/favicon|/status|/version)")


@dataclass
class DastResource:
    """Dataclass representing a parsed OpenAPI spec, web server config, or HTTP response headers."""

    resource_type: str  # "OPENAPI_SPEC", "WEB_CONFIG", "HTTP_RESPONSE"
    name: str
    headers: dict[str, str]
    raw_data: dict[str, Any] | str
    fpath: Path | None
    start_line: int


class NoCrossHostRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Custom HTTP redirect handler that halts redirection if target host differs from initial request host."""

    def redirect_request(self, req: urllib.request.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> urllib.request.Request | None:
        orig_host = urllib.parse.urlparse(req.full_url).netloc.lower()
        new_host = urllib.parse.urlparse(newurl).netloc.lower()

        # If redirect leads to a different host, stop redirect and return None
        if orig_host != new_host:
            logger.debug("Prevented cross-host redirect from %s to %s", orig_host, new_host)
            return None

        return super().redirect_request(req, fp, code, msg, headers, newurl)


class HttpHeaderInspector:
    """Inspector for active read-only HTTP response headers with strict cross-host redirect safeguards."""

    @staticmethod
    def inspect_url(target_url: str) -> DastResource | None:
        parsed = urllib.parse.urlparse(target_url)
        if parsed.scheme.lower() not in ("http", "https"):
            logger.warning("Target URL scheme must be http or https: %s", target_url)
            return None

        opener = urllib.request.build_opener(NoCrossHostRedirectHandler())

        headers: dict[str, str] = {}
        try:
            # Issue a single HEAD request with short timeout
            req = urllib.request.Request(
                target_url,
                method="HEAD",
                headers={"User-Agent": "SentinelScan/0.9.0 Security Assessment Scanner"},
            )
            with opener.open(req, timeout=3.0) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
        except Exception as e:  # noqa: BLE001
            # Fall back to a single GET if HEAD fails or returns HTTP error
            try:
                err_headers = getattr(e, "headers", None)
                if hasattr(e, "headers") and err_headers:
                    headers = {k.lower(): v for k, v in err_headers.items()}
                else:
                    req_get = urllib.request.Request(
                        target_url,
                        method="GET",
                        headers={"User-Agent": "SentinelScan/0.9.0 Security Assessment Scanner"},
                    )
                    with opener.open(req_get, timeout=3.0) as resp_get:
                        headers = {k.lower(): v for k, v in resp_get.headers.items()}
            except Exception as e_get:  # noqa: BLE001
                logger.debug("Failed active HTTP inspection for %s: %s", target_url, e_get)
                return None

        if not headers:
            return None

        return DastResource(
            resource_type="HTTP_RESPONSE",
            name=target_url,
            headers=headers,
            raw_data="",
            fpath=None,
            start_line=1,
        )


class OpenApiParser:
    """Parser for OpenAPI v3.x and Swagger v2.x API specifications."""

    @staticmethod
    def parse_file(fpath: Path) -> DastResource | None:
        try:
            with open(fpath, "r", encoding="utf-8", errors="strict") as f:
                content = f.read()
        except Exception as e:  # noqa: BLE001
            logger.debug("Failed to read file %s: %s", fpath, e)
            return None

        if not content.strip():
            return None

        doc = None
        try:
            doc = json.loads(content)
        except Exception:  # noqa: BLE001
            try:
                doc = yaml.safe_load(content)
            except Exception:  # noqa: BLE001
                doc = None

        if not isinstance(doc, dict):
            return None

        # Validate OpenAPI / Swagger structure
        has_openapi = "openapi" in doc or "swagger" in doc
        paths = doc.get("paths")
        if not has_openapi or not isinstance(paths, dict):
            return None

        return DastResource(
            resource_type="OPENAPI_SPEC",
            name=fpath.name,
            headers={},
            raw_data=doc,
            fpath=fpath,
            start_line=1,
        )


class WebConfigParser:
    """Parser for Nginx, Apache, and Caddy web server configuration files."""

    @staticmethod
    def parse_file(fpath: Path) -> DastResource | None:
        fname = fpath.name.lower()
        if not (fname.endswith(".conf") or fname in ("nginx.conf", "httpd.conf", ".htaccess", "caddyfile")):
            return None

        try:
            with open(fpath, "r", encoding="utf-8", errors="strict") as f:
                content = f.read()
        except Exception as e:  # noqa: BLE001
            logger.debug("Failed to read web config %s: %s", fpath, e)
            return None

        if not content.strip():
            return None

        headers: dict[str, str] = {}
        # Parse add_header (Nginx), Header set (Apache), header (Caddy)
        for line in content.splitlines():
            line_str = line.strip()
            if line_str.startswith(("#", "//")):
                continue

            # Nginx: add_header Strict-Transport-Security "max-age=31536000";
            # Apache: Header set Strict-Transport-Security "max-age=31536000"
            # Caddy: header Strict-Transport-Security max-age=31536000
            match = re.search(
                r"(?:add_header|Header\s+(?:set|always\s+set)|header)\s+([A-Za-z0-9\-]+)\s+[\"']?([^\"';]+)[\"']?",
                line_str,
                re.IGNORECASE,
            )
            if match:
                h_name = match.group(1).lower()
                h_val = match.group(2).strip()
                headers[h_name] = h_val

        if not headers and not any(kw in content.lower() for kw in ("server", "location", "virtualhost", "listen")):
            return None

        return DastResource(
            resource_type="WEB_CONFIG",
            name=fpath.name,
            headers=headers,
            raw_data=content,
            fpath=fpath,
            start_line=1,
        )


class DastScanner(BaseScanner):
    """Web Application and DAST security scanner evaluating OpenAPI specs, web server security headers, and CORS policies."""

    def __init__(self, target_url: str | None = None) -> None:
        self.target_url = target_url

    @property
    def name(self) -> str:
        return "dast-scanner"

    @property
    def category(self) -> Category:
        return Category.DAST

    @property
    def description(self) -> str:
        return "Web application and DAST scanner evaluating OpenAPI specifications, web server security headers, and CORS policies."

    def is_available(self, target: Target) -> bool:
        return True

    def scan(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        # 1. Explicit --target-url active header inspection mode
        if self.target_url:
            active_res = HttpHeaderInspector.inspect_url(self.target_url)
            if active_res:
                self._evaluate_header_rules(active_res, findings)
            return findings

        # 2. 100% Offline static file analysis mode
        if target.is_file:
            self._scan_static_file(target.path, findings)
            return findings

        for root, dirs, files in os.walk(target.path, topdown=True, followlinks=False):
            dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
            root_path = Path(root)

            for fname in files:
                fpath = root_path / fname

                if fpath.is_symlink():
                    try:
                        resolved = fpath.resolve()
                        if not resolved.exists() or not str(resolved).startswith(str(target.path)):
                            continue
                    except OSError:
                        continue

                ext = fpath.suffix.lower()
                fname_lower = fname.lower()
                if ext in (".json", ".yaml", ".yml", ".conf") or fname_lower in ("caddyfile", ".htaccess", "httpd.conf", "nginx.conf"):
                    self._scan_static_file(fpath, findings)

        return findings

    def _scan_static_file(self, fpath: Path, findings: list[Finding]) -> None:
        try:
            stat = fpath.stat()
            if stat.st_size > MAX_FILE_SIZE_BYTES:
                return

            with open(fpath, "rb") as f:
                header = f.read(1024)
                if b"\x00" in header:
                    return
        except (OSError, PermissionError):
            return

        openapi_res = OpenApiParser.parse_file(fpath)
        if openapi_res:
            self._evaluate_openapi_rules(openapi_res, findings)
            return

        web_config_res = WebConfigParser.parse_file(fpath)
        if web_config_res:
            self._evaluate_header_rules(web_config_res, findings)

    def _evaluate_header_rules(self, res: DastResource, findings: list[Finding]) -> None:
        headers = res.headers
        loc_path = res.fpath if res.fpath else Path(res.name)

        # 1. DAST-MISSING-HSTS
        hsts = headers.get("strict-transport-security")
        if not hsts or "max-age" not in hsts.lower():
            findings.append(
                Finding(
                    scanner="dast-scanner",
                    category=Category.DAST,
                    rule_id="DAST-MISSING-HSTS",
                    title=f"Missing HTTP Strict Transport Security (HSTS) in {res.name}",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description=f"Resource '{res.name}' lacks a valid Strict-Transport-Security header.",
                    impact="Allows Man-in-the-Middle (MitM) attackers to downgrade HTTPS connections to unencrypted HTTP.",
                    remediation="Add Strict-Transport-Security: max-age=31536000; includeSubDomains header to web responses.",
                    location=Location(file_path=loc_path, start_line=res.start_line),
                    resource_id=f"{res.name}:HSTS",
                )
            )

        # 2. DAST-MISSING-CSP
        csp = headers.get("content-security-policy")
        if not csp or "unsafe-inline" in csp.lower() or "unsafe-eval" in csp.lower():
            findings.append(
                Finding(
                    scanner="dast-scanner",
                    category=Category.DAST,
                    rule_id="DAST-MISSING-CSP",
                    title=f"Missing or Weak Content Security Policy (CSP) in {res.name}",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description=f"Resource '{res.name}' lacks a strong Content-Security-Policy header.",
                    impact="Exposes web application users to Cross-Site Scripting (XSS) and data injection attacks.",
                    remediation="Define a strict Content Security Policy restricting script, style, and object execution sources.",
                    location=Location(file_path=loc_path, start_line=res.start_line),
                    resource_id=f"{res.name}:CSP",
                )
            )

        # 3. DAST-MISSING-X-FRAME-OPTIONS
        xfo = headers.get("x-frame-options")
        if not xfo or xfo.upper() not in ("DENY", "SAMEORIGIN"):
            findings.append(
                Finding(
                    scanner="dast-scanner",
                    category=Category.DAST,
                    rule_id="DAST-MISSING-X-FRAME-OPTIONS",
                    title=f"Missing X-Frame-Options Clickjacking Control in {res.name}",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    description=f"Resource '{res.name}' lacks X-Frame-Options header (set to DENY or SAMEORIGIN).",
                    impact="Enables Clickjacking attacks, allowing unauthorized framing of sensitive application pages.",
                    remediation="Configure X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN on web responses.",
                    location=Location(file_path=loc_path, start_line=res.start_line),
                    resource_id=f"{res.name}:X-Frame-Options",
                )
            )

        # 4. DAST-MISSING-X-CONTENT-TYPE-OPTIONS
        xcto = headers.get("x-content-type-options")
        if not xcto or xcto.lower() != "nosniff":
            findings.append(
                Finding(
                    scanner="dast-scanner",
                    category=Category.DAST,
                    rule_id="DAST-MISSING-X-CONTENT-TYPE-OPTIONS",
                    title=f"Missing X-Content-Type-Options MIME Sniffing Protection in {res.name}",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    description=f"Resource '{res.name}' lacks X-Content-Type-Options: nosniff header.",
                    impact="Browsers may execute non-executable files by sniffing response MIME types.",
                    remediation="Set X-Content-Type-Options: nosniff header on all HTTP responses.",
                    location=Location(file_path=loc_path, start_line=res.start_line),
                    resource_id=f"{res.name}:X-Content-Type-Options",
                )
            )

        # 5. DAST-WILDCARD-CORS
        cors_origin = headers.get("access-control-allow-origin")
        cors_creds = headers.get("access-control-allow-credentials")
        if cors_origin == "*" or (cors_origin and str(cors_creds).lower() == "true"):
            findings.append(
                Finding(
                    scanner="dast-scanner",
                    category=Category.DAST,
                    rule_id="DAST-WILDCARD-CORS",
                    title=f"Overly Permissive CORS Origin Configuration in {res.name}",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description=f"Resource '{res.name}' configures Access-Control-Allow-Origin: '*'.",
                    impact="Allows arbitrary third-party websites to read authenticated API response data.",
                    remediation="Restrict Access-Control-Allow-Origin to specific trusted domain origins.",
                    location=Location(file_path=loc_path, start_line=res.start_line),
                    resource_id=f"{res.name}:CORS",
                )
            )

        # 6. DAST-SERVER-BANNER-DISCLOSURE
        server_banner = headers.get("server") or headers.get("x-powered-by")
        if server_banner and any(c.isdigit() for c in server_banner):
            findings.append(
                Finding(
                    scanner="dast-scanner",
                    category=Category.DAST,
                    rule_id="DAST-SERVER-BANNER-DISCLOSURE",
                    title=f"Web Server Software Version Banner Disclosed in {res.name}",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    description=f"Resource '{res.name}' discloses detailed software version banner: '{server_banner}'.",
                    impact="Discloses software version details to attackers, simplifying target reconnaissance and CVE lookup.",
                    remediation="Suppress detailed server banners (e.g. ServerTokens ProductOnly or server_tokens off).",
                    location=Location(file_path=loc_path, start_line=res.start_line),
                    resource_id=f"{res.name}:ServerBanner",
                )
            )

    def _evaluate_openapi_rules(self, res: DastResource, findings: list[Finding]) -> None:
        if not isinstance(res.raw_data, dict):
            return

        doc = res.raw_data
        global_security = doc.get("security")
        has_global_sec = isinstance(global_security, list) and len(global_security) > 0

        # Check securitySchemes for Basic auth
        sec_components = doc.get("components", {}).get("securitySchemes", {}) if "components" in doc else doc.get("securityDefinitions", {})
        if isinstance(sec_components, dict):
            for sec_name, sec_def in sec_components.items():
                if isinstance(sec_def, dict):
                    sec_type = str(sec_def.get("type", "")).lower()
                    sec_scheme = str(sec_def.get("scheme", "")).lower()
                    if sec_type == "basic" or (sec_type == "http" and sec_scheme == "basic"):
                        findings.append(
                            Finding(
                                scanner="dast-scanner",
                                category=Category.DAST,
                                rule_id="DAST-OPENAPI-HTTP-BASIC-AUTH",
                                title=f"OpenAPI Specifies Unencrypted HTTP Basic Auth in {res.name}",
                                severity=Severity.MEDIUM,
                                confidence=Confidence.HIGH,
                                description=f"OpenAPI spec '{res.name}' defines security scheme '{sec_name}' using HTTP Basic authentication.",
                                impact="Basic authentication transmits credentials in unencrypted Base64, vulnerable to credential sniffing.",
                                remediation="Upgrade API authentication to OAuth2, OIDC, or Bearer JWT tokens.",
                                location=Location(file_path=res.fpath if res.fpath else Path(res.name), start_line=res.start_line),
                                resource_id=f"{res.name}:SecurityScheme:{sec_name}",
                            )
                        )

        # Check sensitive paths for missing authentication
        paths = doc.get("paths", {})
        if isinstance(paths, dict):
            for path_str, path_item in paths.items():
                if not isinstance(path_item, dict):
                    continue

                is_sensitive = SENSITIVE_PATH_KEYWORDS.search(path_str) is not None
                is_public = PUBLIC_PATH_KEYWORDS.search(path_str) is not None

                if is_sensitive and not is_public:
                    for method in ("get", "post", "put", "delete", "patch"):
                        op = path_item.get(method)
                        if isinstance(op, dict):
                            op_sec = op.get("security")
                            if op_sec == [] or (op_sec is None and not has_global_sec):
                                findings.append(
                                    Finding(
                                        scanner="dast-scanner",
                                        category=Category.DAST,
                                        rule_id="DAST-OPENAPI-NO-AUTH",
                                        title=f"Sensitive OpenAPI Endpoint Lacks Authentication in {res.name}",
                                        severity=Severity.HIGH,
                                        confidence=Confidence.HIGH,
                                        description=f"OpenAPI endpoint '{method.upper()} {path_str}' in '{res.name}' lacks security requirements.",
                                        impact="Exposes administrative or sensitive business logic APIs to unauthenticated remote access.",
                                        remediation="Enforce global or endpoint-level security requirements in OpenAPI specification.",
                                        location=Location(file_path=res.fpath if res.fpath else Path(res.name), start_line=res.start_line),
                                        resource_id=f"{res.name}:{method.upper()}:{path_str}",
                                    )
                                )
