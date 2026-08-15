"""Software Composition Analysis (SCA) Scanner analyzing Python and JavaScript dependencies via OSV vulnerability intelligence."""

import json
import logging
import os
import re
import time
import tomllib
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import semver
from packaging.specifiers import SpecifierSet
from packaging.version import Version

from sentinelscan.models.finding import Category, Confidence, Finding, Location, Severity
from sentinelscan.models.target import Target
from sentinelscan.scanners.base import BaseScanner

logger = logging.getLogger("sentinelscan.scanners.sca_scanner")

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

# Cache directory path
CACHE_DIR = Path.home() / ".sentinelscan" / "cache" / "osv"
CACHE_TTL_SECONDS = 86400  # 24 hours


@dataclass
class DependencyPackage:
    """Dataclass representing a discovered project dependency."""

    name: str
    ecosystem: str  # "PyPI" or "npm"
    manifest_path: Path
    line_number: int
    installed_version: str | None = None
    declared_constraint: str | None = None
    is_direct: bool = True


class OsvCacheManager:
    """Local cache manager for OSV vulnerability index and advisory details."""

    def __init__(self, cache_dir: Path = CACHE_DIR) -> None:
        self.cache_dir = cache_dir
        self.query_cache_file = cache_dir / "query_index_cache.json"
        self.vuln_cache_file = cache_dir / "vuln_details_cache.json"
        self._ensure_cache_dir()

    def _ensure_cache_dir(self) -> None:
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass

    def _load_json(self, fpath: Path) -> dict[str, Any]:
        if fpath.exists():
            try:
                with open(fpath, "r", encoding="utf-8", errors="strict") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        return data
            except Exception as e:  # noqa: BLE001
                logger.debug("Failed to read cache file %s: %s", fpath, e)
        return {}

    def _save_json(self, fpath: Path, data: dict[str, Any]) -> None:
        try:
            with open(fpath, "w", encoding="utf-8", errors="strict") as f:
                json.dump(data, f, indent=2)
        except Exception as e:  # noqa: BLE001
            logger.debug("Failed to write cache file %s: %s", fpath, e)

    def get_cached_query(self, key: str) -> list[str] | None:
        cache = self._load_json(self.query_cache_file)
        entry = cache.get(key)
        if isinstance(entry, dict):
            timestamp = entry.get("timestamp", 0)
            if time.time() - timestamp < CACHE_TTL_SECONDS:
                vulns = entry.get("vuln_ids")
                if isinstance(vulns, list):
                    return [str(v) for v in vulns]
        return None

    def save_cached_query(self, key: str, vuln_ids: list[str]) -> None:
        cache = self._load_json(self.query_cache_file)
        cache[key] = {"timestamp": time.time(), "vuln_ids": vuln_ids}
        self._save_json(self.query_cache_file, cache)

    def get_cached_vuln(self, vuln_id: str) -> dict[str, Any] | None:
        cache = self._load_json(self.vuln_cache_file)
        entry = cache.get(vuln_id)
        if isinstance(entry, dict):
            timestamp = entry.get("timestamp", 0)
            if time.time() - timestamp < CACHE_TTL_SECONDS:
                details = entry.get("details")
                if isinstance(details, dict):
                    return details
        return None

    def save_cached_vuln(self, vuln_id: str, details: dict[str, Any]) -> None:
        cache = self._load_json(self.vuln_cache_file)
        cache[vuln_id] = {"timestamp": time.time(), "details": details}
        self._save_json(self.vuln_cache_file, cache)


class OsvClient:
    """Client for OSV vulnerability API with two-stage lookup and local caching."""

    def __init__(self, cache_manager: OsvCacheManager | None = None) -> None:
        self.cache = cache_manager or OsvCacheManager()

    def fetch_vulnerabilities(
        self,
        packages: list[DependencyPackage],
        offline: bool = False,
    ) -> tuple[dict[str, list[dict[str, Any]]], bool]:
        """Fetch OSV vulnerability details for packages using two-stage lookup.

        Returns:
            tuple[dict[package_key, list[vuln_details]], is_network_error]
        """
        results: dict[str, list[dict[str, Any]]] = {}
        is_network_error = False

        if not packages:
            return results, False

        uncached_queries: list[dict[str, Any]] = []
        package_keys: list[str] = []

        for pkg in packages:
            ver = pkg.installed_version or pkg.declared_constraint or ""
            cache_key = f"{pkg.ecosystem}:{pkg.name}:{ver}"
            package_keys.append(cache_key)

            cached_vuln_ids = self.cache.get_cached_query(cache_key)
            if cached_vuln_ids is not None:
                vulns = self._resolve_vuln_ids(cached_vuln_ids, offline)
                results[cache_key] = vulns
            else:
                if ver:
                    uncached_queries.append(
                        {"package": {"name": pkg.name, "ecosystem": pkg.ecosystem}, "version": ver}
                    )
                else:
                    uncached_queries.append({"package": {"name": pkg.name, "ecosystem": pkg.ecosystem}})

        if uncached_queries:
            if offline:
                logger.debug("Offline mode active: skipping network lookup for %d uncached packages", len(uncached_queries))
            else:
                batch_results, net_err = self._query_batch_api(uncached_queries)
                if net_err:
                    is_network_error = True
                else:
                    for idx, res in enumerate(batch_results):
                        if idx < len(package_keys):
                            ckey = package_keys[idx]
                            vuln_items = res.get("vulns", [])
                            vuln_ids = [str(v["id"]) for v in vuln_items if isinstance(v, dict) and "id" in v]
                            self.cache.save_cached_query(ckey, vuln_ids)

                            vulns = self._resolve_vuln_ids(vuln_ids, offline=False)
                            results[ckey] = vulns

        return results, is_network_error

    def _query_batch_api(self, queries: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], bool]:
        """Perform Stage 1 batch POST request to OSV API."""
        url = "https://api.osv.dev/v1/querybatch"
        payload = json.dumps({"queries": queries}).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "SentinelScan/0.5.0"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                results = data.get("results", [])
                if isinstance(results, list):
                    return results, False
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            logger.warning("OSV querybatch API request failed: %s", e)
            return [], True
        except Exception as e:  # noqa: BLE001
            logger.warning("Failed to parse OSV querybatch response: %s", e)
            return [], True

        return [], False

    def _resolve_vuln_ids(self, vuln_ids: list[str], offline: bool) -> list[dict[str, Any]]:
        """Perform Stage 2 advisory record retrieval for vulnerability IDs."""
        details_list: list[dict[str, Any]] = []

        for vid in vuln_ids:
            cached_detail = self.cache.get_cached_vuln(vid)
            if cached_detail is not None:
                details_list.append(cached_detail)
            elif not offline:
                detail = self._fetch_vuln_detail(vid)
                if detail:
                    self.cache.save_cached_vuln(vid, detail)
                    details_list.append(detail)

        return details_list

    def _fetch_vuln_detail(self, vuln_id: str) -> dict[str, Any] | None:
        """Fetch single vulnerability advisory detail from OSV GET endpoint."""
        url = f"https://api.osv.dev/v1/vulns/{vuln_id}"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "SentinelScan/0.5.0"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if isinstance(data, dict):
                    return data
        except Exception as e:  # noqa: BLE001
            logger.debug("Failed to fetch detail for vuln_id %s: %s", vuln_id, e)
        return None


# Helper functions for npm SemVer matching
def matches_npm_semver(version_str: str, constraint_str: str) -> bool:
    """Evaluate whether a SemVer string satisfies an npm constraint range."""
    clean_ver = version_str.strip().lstrip("v")
    clean_range = constraint_str.strip()

    try:
        ver = semver.Version.parse(clean_ver)
    except Exception:  # noqa: BLE001
        return False

    # Handle caret (^1.2.3)
    if clean_range.startswith("^"):
        target_str = clean_range[1:].lstrip("v")
        try:
            target = semver.Version.parse(target_str)
            if ver < target:
                return False
            if target.major > 0:
                return bool(ver.major == target.major)
            elif target.minor > 0:
                return bool(ver.major == 0 and ver.minor == target.minor)
            else:
                return bool(ver == target)
        except Exception:  # noqa: BLE001
            return False

    # Handle tilde (~1.2.3)
    if clean_range.startswith("~"):
        target_str = clean_range[1:].lstrip("v")
        try:
            target = semver.Version.parse(target_str)
            return bool(ver.major == target.major and ver.minor == target.minor and ver >= target)
        except Exception:  # noqa: BLE001
            return False

    # Fallback to general comparison operators or simple equality
    try:
        return bool(ver == semver.Version.parse(clean_range.lstrip("v=")))
    except Exception:  # noqa: BLE001
        return False


def matches_pep440(version_str: str, specifier_str: str) -> bool:
    """Evaluate whether a Python version string matches a PEP 440 specifier range."""
    try:
        v = Version(version_str)
        spec = SpecifierSet(specifier_str)
        return v in spec
    except Exception:  # noqa: BLE001
        return False


class PythonDependencyParser:
    """Parser for Python requirements.txt, pyproject.toml, and poetry.lock dependency files."""

    @staticmethod
    def parse_requirements_txt(fpath: Path) -> list[DependencyPackage]:
        packages: list[DependencyPackage] = []
        try:
            with open(fpath, "r", encoding="utf-8", errors="strict") as f:
                for line_num, line in enumerate(f, start=1):
                    clean = line.strip()
                    if not clean or clean.startswith(("#", "-")):
                        continue

                    # Extract package name and version / constraint
                    match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*([==|>=|<=|!=|~=|>|<].*)?$", clean)
                    if match:
                        name = match.group(1).lower()
                        spec = match.group(2)
                        installed_ver = None
                        constraint = None

                        if spec:
                            spec_clean = spec.strip()
                            if spec_clean.startswith("=="):
                                installed_ver = spec_clean[2:].strip()
                            else:
                                constraint = spec_clean

                        packages.append(
                            DependencyPackage(
                                name=name,
                                ecosystem="PyPI",
                                manifest_path=fpath,
                                line_number=line_num,
                                installed_version=installed_ver,
                                declared_constraint=constraint,
                                is_direct=True,
                            )
                        )
        except Exception as e:  # noqa: BLE001
            logger.debug("Failed to parse requirements.txt %s: %s", fpath, e)
        return packages

    @staticmethod
    def parse_pyproject_toml(fpath: Path) -> list[DependencyPackage]:
        packages: list[DependencyPackage] = []
        try:
            with open(fpath, "rb") as f:
                data = tomllib.load(f)

            deps: list[str] = []

            # PEP 621 dependencies
            project = data.get("project", {})
            if isinstance(project, dict):
                p_deps = project.get("dependencies", [])
                if isinstance(p_deps, list):
                    deps.extend([str(d) for d in p_deps])

            # Poetry dependencies
            tool = data.get("tool", {})
            if isinstance(tool, dict):
                poetry = tool.get("poetry", {})
                if isinstance(poetry, dict):
                    poetry_deps = poetry.get("dependencies", {})
                    if isinstance(poetry_deps, dict):
                        for name, val in poetry_deps.items():
                            if name.lower() != "python":
                                deps.append(f"{name}{val if isinstance(val, str) else ''}")

            for idx, dep_str in enumerate(deps, start=1):
                clean = dep_str.strip()
                match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*([==|>=|<=|!=|~=|>|<|^|~].*)?$", clean)
                if match:
                    name = match.group(1).lower()
                    spec = match.group(2)
                    installed_ver = None
                    constraint = None
                    if spec:
                        spec_clean = spec.strip()
                        if spec_clean.startswith("=="):
                            installed_ver = spec_clean[2:].strip()
                        else:
                            constraint = spec_clean

                    packages.append(
                        DependencyPackage(
                            name=name,
                            ecosystem="PyPI",
                            manifest_path=fpath,
                            line_number=idx,
                            installed_version=installed_ver,
                            declared_constraint=constraint,
                            is_direct=True,
                        )
                    )
        except Exception as e:  # noqa: BLE001
            logger.debug("Failed to parse pyproject.toml %s: %s", fpath, e)
        return packages

    @staticmethod
    def parse_poetry_lock(fpath: Path) -> list[DependencyPackage]:
        packages: list[DependencyPackage] = []
        try:
            with open(fpath, "rb") as f:
                data = tomllib.load(f)

            pkgs_list = data.get("package", [])
            if isinstance(pkgs_list, list):
                for idx, pkg in enumerate(pkgs_list, start=1):
                    if isinstance(pkg, dict):
                        name = str(pkg.get("name", "")).lower()
                        version = str(pkg.get("version", ""))
                        if name and version:
                            packages.append(
                                DependencyPackage(
                                    name=name,
                                    ecosystem="PyPI",
                                    manifest_path=fpath,
                                    line_number=idx,
                                    installed_version=version,
                                    is_direct=pkg.get("category", "") == "main",
                                )
                            )
        except Exception as e:  # noqa: BLE001
            logger.debug("Failed to parse poetry.lock %s: %s", fpath, e)
        return packages


class JsDependencyParser:
    """Parser for JavaScript package.json and package-lock.json dependency files."""

    @staticmethod
    def parse_package_json(fpath: Path) -> list[DependencyPackage]:
        packages: list[DependencyPackage] = []
        try:
            with open(fpath, "r", encoding="utf-8", errors="strict") as f:
                data = json.load(f)

            if not isinstance(data, dict):
                return packages

            sections = [("dependencies", True), ("devDependencies", False), ("peerDependencies", False)]
            line_idx = 1
            for section_name, is_direct in sections:
                deps = data.get(section_name, {})
                if isinstance(deps, dict):
                    for name, constraint in deps.items():
                        line_idx += 1
                        packages.append(
                            DependencyPackage(
                                name=name,
                                ecosystem="npm",
                                manifest_path=fpath,
                                line_number=line_idx,
                                declared_constraint=str(constraint),
                                is_direct=is_direct,
                            )
                        )
        except Exception as e:  # noqa: BLE001
            logger.debug("Failed to parse package.json %s: %s", fpath, e)
        return packages

    @staticmethod
    def parse_package_lock(fpath: Path) -> list[DependencyPackage]:
        packages: list[DependencyPackage] = []
        try:
            with open(fpath, "r", encoding="utf-8", errors="strict") as f:
                data = json.load(f)

            if not isinstance(data, dict):
                return packages

            # Handle v2 / v3 lockfiles (`packages` key)
            pkgs = data.get("packages", {})
            if isinstance(pkgs, dict) and len(pkgs) > 0:
                line_idx = 1
                for path_key, pkg_info in pkgs.items():
                    line_idx += 1
                    if not path_key or not isinstance(pkg_info, dict):
                        continue
                    name = pkg_info.get("name") or path_key.replace("node_modules/", "").split("node_modules/")[-1]
                    version = pkg_info.get("version")
                    if name and version:
                        packages.append(
                            DependencyPackage(
                                name=name,
                                ecosystem="npm",
                                manifest_path=fpath,
                                line_number=line_idx,
                                installed_version=str(version),
                                is_direct=not pkg_info.get("dev", False),
                            )
                        )
                return packages

            # Handle v1 lockfiles (`dependencies` key fallback)
            deps = data.get("dependencies", {})
            if isinstance(deps, dict):
                line_idx = 1
                for name, info in deps.items():
                    line_idx += 1
                    if isinstance(info, dict) and "version" in info:
                        packages.append(
                            DependencyPackage(
                                name=name,
                                ecosystem="npm",
                                manifest_path=fpath,
                                line_number=line_idx,
                                installed_version=str(info["version"]),
                                is_direct=not info.get("dev", False),
                            )
                        )
        except Exception as e:  # noqa: BLE001
            logger.debug("Failed to parse package-lock.json %s: %s", fpath, e)
        return packages


class ScaScanner(BaseScanner):
    """Software Composition Analysis (SCA) scanner discovering vulnerable Python and JavaScript dependencies."""

    def __init__(self, offline: bool = False) -> None:
        self.offline = offline
        self.osv_client = OsvClient()

    @property
    def name(self) -> str:
        return "sca-scanner"

    @property
    def category(self) -> Category:
        return Category.SCA

    @property
    def description(self) -> str:
        return "Software Composition Analysis scanner discovering vulnerable Python and JavaScript dependencies via OSV intelligence and local cache."

    def is_available(self, target: Target) -> bool:
        return True

    def scan(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        packages: list[DependencyPackage] = []

        if target.is_file:
            self._parse_manifest_file(target.path, packages)
        else:
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

                    self._parse_manifest_file(fpath, packages)

        if not packages:
            return findings

        # Query vulnerability intelligence via two-stage OSV lookup
        vuln_map, is_network_error = self.osv_client.fetch_vulnerabilities(packages, offline=self.offline)

        # Handle network failure with empty cache gracefully
        if is_network_error and not vuln_map:
            logger.warning("OSV vulnerability intelligence unavailable due to network failure.")

        # Convert OSV advisories to normalized findings
        for pkg in packages:
            ver = pkg.installed_version or pkg.declared_constraint or ""
            cache_key = f"{pkg.ecosystem}:{pkg.name}:{ver}"
            advisories = vuln_map.get(cache_key, [])

            for adv in advisories:
                finding = self._create_vuln_finding(pkg, adv)
                if finding:
                    findings.append(finding)

        return findings

    def _parse_manifest_file(self, fpath: Path, packages: list[DependencyPackage]) -> None:
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

        fname = fpath.name.lower()
        if fname == "requirements.txt":
            packages.extend(PythonDependencyParser.parse_requirements_txt(fpath))
        elif fname == "pyproject.toml":
            packages.extend(PythonDependencyParser.parse_pyproject_toml(fpath))
        elif fname == "poetry.lock":
            packages.extend(PythonDependencyParser.parse_poetry_lock(fpath))
        elif fname == "package.json":
            packages.extend(JsDependencyParser.parse_package_json(fpath))
        elif fname == "package-lock.json":
            packages.extend(JsDependencyParser.parse_package_lock(fpath))

    def _create_vuln_finding(self, pkg: DependencyPackage, adv: dict[str, Any]) -> Finding | None:
        vuln_id = str(adv.get("id", "UNKNOWN"))
        summary = str(adv.get("summary", adv.get("details", f"Vulnerability {vuln_id} detected in {pkg.name}")))
        details = str(adv.get("details", ""))

        # Map CVSS / OSV database severity
        severity = Severity.LOW
        database_specific = adv.get("database_specific", {})
        db_sev = ""
        if isinstance(database_specific, dict):
            db_sev = str(database_specific.get("severity", "")).upper()

        if db_sev == "CRITICAL":
            severity = Severity.CRITICAL
        elif db_sev == "HIGH":
            severity = Severity.HIGH
        elif db_sev in ("MODERATE", "MEDIUM"):
            severity = Severity.MEDIUM
        elif db_sev == "LOW":
            severity = Severity.LOW

        # Confidence: lockfiles with exact installed_version -> HIGH, manifests -> MEDIUM
        confidence = Confidence.HIGH if pkg.installed_version else Confidence.MEDIUM

        version_display = f"v{pkg.installed_version}" if pkg.installed_version else f"constraint '{pkg.declared_constraint}'"
        rule_id = f"SCA-{pkg.ecosystem.upper()}-{pkg.name.upper()}-{vuln_id}".replace("@", "").replace("/", "-")

        # Extract fixed version if available
        fixed_version = "Unknown"
        affected_list = adv.get("affected", [])
        if isinstance(affected_list, list):
            for aff in affected_list:
                if isinstance(aff, dict):
                    ranges = aff.get("ranges", [])
                    if isinstance(ranges, list):
                        for r in ranges:
                            if isinstance(r, dict):
                                events = r.get("events", [])
                                if isinstance(events, list):
                                    for ev in events:
                                        if isinstance(ev, dict) and "fixed" in ev:
                                            fixed_version = str(ev["fixed"])
                                            break

        return Finding(
            scanner="sca-scanner",
            category=Category.SCA,
            rule_id=rule_id,
            title=f"Vulnerable Dependency: {pkg.name} ({version_display})",
            severity=severity,
            confidence=confidence,
            description=f"Vulnerability {vuln_id} affects {pkg.name} ({version_display}). {summary}",
            impact=f"Security flaw in {pkg.name} dependency could lead to unexpected behavior or remote exploitation: {details[:200]}",
            remediation=f"Upgrade {pkg.name} to version {fixed_version} or newer.",
            location=Location(file_path=pkg.manifest_path, start_line=pkg.line_number, end_line=pkg.line_number),
            resource_id=f"{pkg.ecosystem}:{pkg.name}",
            metadata={
                "package_name": pkg.name,
                "ecosystem": pkg.ecosystem,
                "installed_version": pkg.installed_version,
                "declared_constraint": pkg.declared_constraint,
                "vuln_id": vuln_id,
                "fixed_version": fixed_version,
                "is_direct": pkg.is_direct,
            },
        )
