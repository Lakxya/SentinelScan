"""Unit tests for ScaScanner, Python/JS dependency parsers, SemVer matching, OSV API client, and CLI commands."""

import json
from unittest.mock import MagicMock, patch

from sentinelscan.models.finding import Category, Confidence
from sentinelscan.models.target import Target
from sentinelscan.scanners.sca_scanner import (
    JsDependencyParser,
    OsvCacheManager,
    OsvClient,
    PythonDependencyParser,
    ScaScanner,
    matches_npm_semver,
    matches_pep440,
)


def test_npm_semver_range_matching():
    """Verify npm SemVer matching for caret, tilde, equality, and invalid versions."""
    assert matches_npm_semver("1.2.5", "^1.2.3") is True
    assert matches_npm_semver("2.0.0", "^1.2.3") is False
    assert matches_npm_semver("1.2.9", "~1.2.3") is True
    assert matches_npm_semver("1.3.0", "~1.2.3") is False
    assert matches_npm_semver("1.0.0", "1.0.0") is True
    assert matches_npm_semver("invalid", "^1.0.0") is False


def test_pep440_version_matching():
    """Verify Python PEP 440 version specifier matching."""
    assert matches_pep440("2.25.0", ">=2.20.0, <3.0.0") is True
    assert matches_pep440("3.1.0", ">=2.20.0, <3.0.0") is False
    assert matches_pep440("invalid", ">=1.0.0") is False


def test_python_requirements_txt_parser(tmp_path):
    """Verify requirements.txt parser extracts exact versions and constraints."""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text(
        "# Comment line\n"
        "requests==2.25.0\n"
        "urllib3>=1.26.0\n"
        "-r base.txt\n"
    )

    pkgs = PythonDependencyParser.parse_requirements_txt(req_file)
    assert len(pkgs) == 2

    r_pkg = next(p for p in pkgs if p.name == "requests")
    assert r_pkg.installed_version == "2.25.0"
    assert r_pkg.declared_constraint is None

    u_pkg = next(p for p in pkgs if p.name == "urllib3")
    assert u_pkg.installed_version is None
    assert u_pkg.declared_constraint == ">=1.26.0"


def test_js_package_json_parser(tmp_path):
    """Verify package.json parser handles scoped packages and constraints."""
    pkg_file = tmp_path / "package.json"
    pkg_file.write_text(
        json.dumps(
            {
                "name": "my-app",
                "dependencies": {
                    "express": "^4.17.1",
                    "@types/node": "~14.14.0",
                },
                "devDependencies": {
                    "jest": "^27.0.0",
                },
            }
        )
    )

    pkgs = JsDependencyParser.parse_package_json(pkg_file)
    assert len(pkgs) == 3

    names = [p.name for p in pkgs]
    assert "express" in names
    assert "@types/node" in names
    assert "jest" in names

    expr = next(p for p in pkgs if p.name == "express")
    assert expr.declared_constraint == "^4.17.1"
    assert expr.is_direct is True


def test_js_package_lock_parser_v3(tmp_path):
    """Verify package-lock.json v3 parser extracts exact resolved versions."""
    lock_file = tmp_path / "package-lock.json"
    lock_file.write_text(
        json.dumps(
            {
                "name": "my-app",
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "my-app", "version": "1.0.0"},
                    "node_modules/express": {"version": "4.17.3", "dev": False},
                    "node_modules/@types/node": {"version": "14.14.37", "dev": True},
                },
            }
        )
    )

    pkgs = JsDependencyParser.parse_package_lock(lock_file)
    assert len(pkgs) == 2

    expr = next(p for p in pkgs if p.name == "express")
    assert expr.installed_version == "4.17.3"
    assert expr.is_direct is True


def test_osv_two_stage_api_lookup_and_cache(tmp_path):
    """Verify OSV two-stage lookup (querybatch index + vuln details) and local cache interaction."""
    cache_mgr = OsvCacheManager(cache_dir=tmp_path / "cache")
    client = OsvClient(cache_manager=cache_mgr)

    mock_batch_resp = {
        "results": [
            {
                "vulns": [
                    {"id": "GHSA-1234"},
                ]
            }
        ]
    }

    mock_detail_resp = {
        "id": "GHSA-1234",
        "summary": "Mock vulnerability in requests",
        "details": "RCE flaw in requests library.",
        "database_specific": {"severity": "HIGH"},
        "affected": [
            {
                "package": {"name": "requests", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.26.0"}]}],
            }
        ],
    }

    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.25.0\n")
    pkg = PythonDependencyParser.parse_requirements_txt(req_file)[0]

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_resp_stage1 = MagicMock()
        mock_resp_stage1.read.return_value = json.dumps(mock_batch_resp).encode("utf-8")
        mock_resp_stage1.__enter__.return_value = mock_resp_stage1

        mock_resp_stage2 = MagicMock()
        mock_resp_stage2.read.return_value = json.dumps(mock_detail_resp).encode("utf-8")
        mock_resp_stage2.__enter__.return_value = mock_resp_stage2

        mock_urlopen.side_effect = [mock_resp_stage1, mock_resp_stage2]

        vuln_map, is_net_err = client.fetch_vulnerabilities([pkg], offline=False)

        assert is_net_err is False
        ckey = "PyPI:requests:2.25.0"
        assert ckey in vuln_map
        assert len(vuln_map[ckey]) == 1
        assert vuln_map[ckey][0]["id"] == "GHSA-1234"

    # Second call should use cache with ZERO urllib calls
    with patch("urllib.request.urlopen") as mock_urlopen2:
        vuln_map_cached, is_net_err2 = client.fetch_vulnerabilities([pkg], offline=False)
        assert is_net_err2 is False
        assert ckey in vuln_map_cached
        mock_urlopen2.assert_not_called()


def test_strict_offline_mode_zero_network(tmp_path):
    """Verify --offline flag strictly guarantees zero network requests."""
    cache_mgr = OsvCacheManager(cache_dir=tmp_path / "cache")
    client = OsvClient(cache_manager=cache_mgr)

    req_file = tmp_path / "requirements.txt"
    req_file.write_text("flask==1.1.0\n")
    pkg = PythonDependencyParser.parse_requirements_txt(req_file)[0]

    with patch("urllib.request.urlopen") as mock_urlopen:
        _vuln_map, is_net_err = client.fetch_vulnerabilities([pkg], offline=True)
        assert is_net_err is False
        mock_urlopen.assert_not_called()


def test_network_unavailability_handling(tmp_path):
    """Verify network error with empty cache sets is_network_error = True."""
    cache_mgr = OsvCacheManager(cache_dir=tmp_path / "cache")
    client = OsvClient(cache_manager=cache_mgr)

    req_file = tmp_path / "requirements.txt"
    req_file.write_text("django==2.2.0\n")
    pkg = PythonDependencyParser.parse_requirements_txt(req_file)[0]

    with patch("urllib.request.urlopen", side_effect=OSError("Network unreachable")):
        vuln_map, is_net_err = client.fetch_vulnerabilities([pkg], offline=False)
        assert is_net_err is True
        assert len(vuln_map) == 0


def test_sca_scanner_lockfile_vs_manifest_confidence(tmp_path):
    """Verify lockfiles use Confidence.HIGH while manifests use Confidence.MEDIUM."""
    lock_file = tmp_path / "package-lock.json"
    lock_file.write_text(
        json.dumps(
            {
                "name": "app",
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/express": {"version": "4.16.0"},
                },
            }
        )
    )

    manifest_file = tmp_path / "package.json"
    manifest_file.write_text(json.dumps({"dependencies": {"express": "^4.16.0"}}))

    mock_detail = {
        "id": "GHSA-test",
        "summary": "Vulnerability in express",
        "database_specific": {"severity": "HIGH"},
    }

    scanner = ScaScanner(offline=True)

    with patch.object(OsvClient, "fetch_vulnerabilities") as mock_fetch:
        mock_fetch.return_value = ({"npm:express:4.16.0": [mock_detail], "npm:express:^4.16.0": [mock_detail]}, False)

        target_lock = Target(path=lock_file, is_directory=False, is_file=True, is_git_repo=False, file_count=1, total_size_bytes=100)
        lock_findings = scanner.scan(target_lock)

        target_manifest = Target(path=manifest_file, is_directory=False, is_file=True, is_git_repo=False, file_count=1, total_size_bytes=100)
        manifest_findings = scanner.scan(target_manifest)

        assert len(lock_findings) == 1
        assert lock_findings[0].confidence == Confidence.HIGH
        assert lock_findings[0].category == Category.SCA

        assert len(manifest_findings) == 1
        assert manifest_findings[0].confidence == Confidence.MEDIUM
