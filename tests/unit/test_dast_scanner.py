"""Unit tests for DastScanner, OpenApiParser, WebConfigParser, HttpHeaderInspector, security rules, and CLI integration."""

import socket
import urllib.request

from sentinelscan.models.finding import Category, Confidence, Severity
from sentinelscan.models.result import ScannerExecutionResult, ScannerExecutionStatus, ScanResult
from sentinelscan.models.target import Target
from sentinelscan.reporting.json import JsonReporter
from sentinelscan.scanners.dast_scanner import (
    DastScanner,
    NoCrossHostRedirectHandler,
    OpenApiParser,
)


def test_dast_openapi_parser_valid_v3_and_v2(tmp_path):
    """Verify OpenApiParser parses OpenAPI v3 and Swagger v2 specifications."""
    openapi_v3 = tmp_path / "openapi3.json"
    openapi_v3.write_text(
        '{\n'
        '  "openapi": "3.0.0",\n'
        '  "info": { "title": "Test API", "version": "1.0" },\n'
        '  "paths": {\n'
        '    "/users": { "get": { "responses": { "200": { "description": "ok" } } } }\n'
        '  }\n'
        '}\n'
    )

    res3 = OpenApiParser.parse_file(openapi_v3)
    assert res3 is not None
    assert res3.resource_type == "OPENAPI_SPEC"

    swagger_v2 = tmp_path / "swagger2.yaml"
    swagger_v2.write_text(
        "swagger: '2.0'\n"
        "info:\n"
        "  title: Legacy API\n"
        "  version: '2.0'\n"
        "paths:\n"
        "  /pets:\n"
        "    get:\n"
        "      responses:\n"
        "        '200':\n"
        "          description: OK\n"
    )

    res2 = OpenApiParser.parse_file(swagger_v2)
    assert res2 is not None
    assert res2.resource_type == "OPENAPI_SPEC"


def test_dast_positive_security_detections(tmp_path):
    """Verify DastScanner positive detections for OpenAPI unauthenticated endpoints and basic auth."""
    spec = tmp_path / "openapi-insecure.json"
    spec.write_text(
        '{\n'
        '  "openapi": "3.0.0",\n'
        '  "info": { "title": "Insecure API", "version": "1.0" },\n'
        '  "components": {\n'
        '    "securitySchemes": {\n'
        '      "basicAuth": { "type": "http", "scheme": "basic" }\n'
        '    }\n'
        '  },\n'
        '  "paths": {\n'
        '    "/admin/deleteUser": {\n'
        '      "post": { "security": [], "responses": { "200": { "description": "ok" } } }\n'
        '    }\n'
        '  }\n'
        '}\n'
    )

    scanner = DastScanner()
    target = Target(
        path=spec,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(spec.read_bytes()),
    )

    findings = scanner.scan(target)
    rule_ids = [f.rule_id for f in findings]

    assert "DAST-OPENAPI-NO-AUTH" in rule_ids
    assert "DAST-OPENAPI-HTTP-BASIC-AUTH" in rule_ids

    no_auth = next(f for f in findings if f.rule_id == "DAST-OPENAPI-NO-AUTH")
    assert no_auth.severity == Severity.HIGH
    assert no_auth.confidence == Confidence.HIGH
    assert no_auth.category == Category.DAST


def test_dast_web_config_header_detections(tmp_path):
    """Verify DastScanner parses web server config security headers."""
    nginx_conf = tmp_path / "nginx.conf"
    nginx_conf.write_text(
        "server {\n"
        "    listen 80;\n"
        "    server_name example.com;\n"
        '    add_header Access-Control-Allow-Origin "*";\n'
        '    add_header Server "Apache/2.4.41 (Ubuntu)";\n'
        "}\n"
    )

    scanner = DastScanner()
    target = Target(
        path=nginx_conf,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(nginx_conf.read_bytes()),
    )

    findings = scanner.scan(target)
    rule_ids = [f.rule_id for f in findings]

    assert "DAST-MISSING-HSTS" in rule_ids
    assert "DAST-MISSING-CSP" in rule_ids
    assert "DAST-MISSING-X-FRAME-OPTIONS" in rule_ids
    assert "DAST-MISSING-X-CONTENT-TYPE-OPTIONS" in rule_ids
    assert "DAST-WILDCARD-CORS" in rule_ids
    assert "DAST-SERVER-BANNER-DISCLOSURE" in rule_ids


def test_dast_openapi_no_auth_excludes_health_checks(tmp_path):
    """Verify public health check endpoints (/health) are excluded from no-auth findings."""
    spec = tmp_path / "openapi-health.json"
    spec.write_text(
        '{\n'
        '  "openapi": "3.0.0",\n'
        '  "info": { "title": "API", "version": "1.0" },\n'
        '  "paths": {\n'
        '    "/health": {\n'
        '      "get": { "security": [], "responses": { "200": { "description": "ok" } } }\n'
        '    }\n'
        '  }\n'
        '}\n'
    )

    scanner = DastScanner()
    target = Target(
        path=spec,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(spec.read_bytes()),
    )

    findings = scanner.scan(target)
    no_auth_findings = [f for f in findings if f.rule_id == "DAST-OPENAPI-NO-AUTH"]
    assert len(no_auth_findings) == 0


def test_dast_static_mode_zero_network(tmp_path, monkeypatch):
    """Verify static scanning performs zero socket calls or network requests."""
    def _forbidden_connect(*args, **kwargs):
        raise RuntimeError("Network socket call attempted during static scan!")

    monkeypatch.setattr(socket, "socket", _forbidden_connect)

    spec = tmp_path / "openapi.json"
    spec.write_text(
        '{\n'
        '  "openapi": "3.0.0",\n'
        '  "info": { "title": "Offline Test", "version": "1.0" },\n'
        '  "paths": {}\n'
        '}\n'
    )

    scanner = DastScanner()
    target = Target(
        path=spec,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(spec.read_bytes()),
    )

    # Static scan must complete without triggering network socket error
    findings = scanner.scan(target)
    assert len(findings) == 0


def test_dast_active_mode_no_cross_host_redirects():
    """Verify NoCrossHostRedirectHandler prevents following redirects to external hosts."""
    handler = NoCrossHostRedirectHandler()
    req = urllib.request.Request("http://localhost:8080/api")

    # Same host redirect -> allowed
    same_host_req = handler.redirect_request(req, None, 302, "Found", {}, "http://localhost:8080/new-api")
    assert same_host_req is not None

    # Cross host redirect -> blocked (returns None)
    cross_host_req = handler.redirect_request(req, None, 302, "Found", {}, "http://malicious-external.com/steal")
    assert cross_host_req is None


def test_dast_non_openapi_json_ignored(tmp_path):
    """Verify non-OpenAPI JSON files (package.json, tsconfig.json) are ignored safely."""
    pkg = tmp_path / "package.json"
    pkg.write_text('{\n  "name": "my-app",\n  "version": "1.0.0"\n}\n')

    scanner = DastScanner()
    target = Target(
        path=pkg,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(pkg.read_bytes()),
    )

    findings = scanner.scan(target)
    assert len(findings) == 0


def test_dast_json_serialization(tmp_path):
    """Verify DAST findings serialize cleanly to structured JSON format."""
    spec = tmp_path / "openapi.json"
    spec.write_text(
        '{\n'
        '  "openapi": "3.0.0",\n'
        '  "info": { "title": "API", "version": "1.0" },\n'
        '  "components": {\n'
        '    "securitySchemes": { "basicAuth": { "type": "basic" } }\n'
        '  },\n'
        '  "paths": {}\n'
        '}\n'
    )

    scanner = DastScanner()
    target = Target(
        path=spec,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(spec.read_bytes()),
    )

    findings = scanner.scan(target)
    assert len(findings) >= 1

    res = ScanResult(
        target=target,
        findings=findings,
        scanner_results=[
            ScannerExecutionResult(scanner_name="dast-scanner", status=ScannerExecutionStatus.SUCCESS)
        ],
    )
    json_out = JsonReporter().render(res)
    assert '"category": "dast"' in json_out
    assert '"rule_id": "DAST-OPENAPI-HTTP-BASIC-AUTH"' in json_out
