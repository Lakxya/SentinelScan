"""Docker Security Scanner analyzing Dockerfiles for misconfigurations and security best practices."""

import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path

from sentinelscan.models.finding import Category, Confidence, Finding, Location, Severity
from sentinelscan.models.target import Target
from sentinelscan.scanners.base import BaseScanner
from sentinelscan.scanners.secret_scanner import mask_token

logger = logging.getLogger("sentinelscan.scanners.docker_scanner")

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

# Sensitive network ports
SENSITIVE_PORTS = {22, 3389, 3306, 5432, 1433, 27017, 6379}

# Secret variable name patterns in ENV or ARG
SECRET_VAR_PATTERN = re.compile(
    r"(?i)(api[_\-]?key|secret|password|passwd|private[_\-]?key|auth[_\-]?token|access[_\-]?token|credentials)"
)

# Placeholders to ignore in secret detection
PLACEHOLDER_PATTERN = re.compile(
    r"(?i)^(your[_\-]|\$\{|\$|change_me|example|dummy|placeholder|xxx|todofixme|foo|bar)"
)


@dataclass
class DockerfileInstruction:
    """Dataclass representing a parsed instruction inside a Dockerfile."""

    name: str
    args: str
    raw: str
    start_line: int
    end_line: int
    stage_index: int
    stage_alias: str | None = None


class DockerfileParser:
    """Deterministic parser for Dockerfile instructions, line continuations, comments, and multi-stage builds."""

    @staticmethod
    def parse_file(fpath: Path) -> list[DockerfileInstruction]:
        instructions: list[DockerfileInstruction] = []
        try:
            with open(fpath, "r", encoding="utf-8", errors="strict") as f:
                lines = f.readlines()
        except Exception as e:  # noqa: BLE001
            logger.debug("Failed to read Dockerfile %s: %s", fpath, e)
            return instructions

        idx = 0
        total_lines = len(lines)
        current_stage_index = 0
        current_stage_alias: str | None = None

        while idx < total_lines:
            line_num = idx + 1
            raw_line = lines[idx].strip()

            # Skip comments and empty lines
            if not raw_line or raw_line.startswith("#"):
                idx += 1
                continue

            # Collect line continuations ending with backslash '\'
            combined_parts = [raw_line]
            start_line = line_num
            end_line = line_num

            while combined_parts[-1].endswith("\\") and (idx + 1) < total_lines:
                combined_parts[-1] = combined_parts[-1][:-1].rstrip()
                idx += 1
                end_line = idx + 1
                next_line = lines[idx].strip()
                if next_line and not next_line.startswith("#"):
                    combined_parts.append(next_line)

            combined_str = " ".join(combined_parts)

            # Split instruction name and argument text
            parts = combined_str.split(maxsplit=1)
            if not parts:
                idx += 1
                continue

            inst_name = parts[0].upper()
            inst_args = parts[1].strip() if len(parts) > 1 else ""

            # Check for FROM instruction to track multi-stage builds
            if inst_name == "FROM":
                if len(instructions) > 0:
                    current_stage_index += 1
                current_stage_alias = None

                # Extract stage alias if declared as 'FROM image AS alias'
                from_match = re.search(r"(?i)\s+AS\s+([a-zA-Z0-9_\-\.]+)", inst_args)
                if from_match:
                    current_stage_alias = from_match.group(1)

            instructions.append(
                DockerfileInstruction(
                    name=inst_name,
                    args=inst_args,
                    raw=combined_str,
                    start_line=start_line,
                    end_line=end_line,
                    stage_index=current_stage_index,
                    stage_alias=current_stage_alias,
                )
            )

            idx += 1

        return instructions


class DockerScanner(BaseScanner):
    """Docker security scanner analyzing Dockerfiles for static security misconfigurations."""

    @property
    def name(self) -> str:
        return "docker-scanner"

    @property
    def category(self) -> Category:
        return Category.CONTAINER

    @property
    def description(self) -> str:
        return "Docker security scanner analyzing Dockerfiles for misconfigurations and security best practices."

    def is_available(self, target: Target) -> bool:
        return True

    def scan(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        if target.is_file:
            self._scan_dockerfile(target.path, findings)
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

                if self._is_dockerfile(fname):
                    self._scan_dockerfile(fpath, findings)

        return findings

    def _is_dockerfile(self, fname: str) -> bool:
        lower = fname.lower()
        return lower == "dockerfile" or lower.startswith("dockerfile.") or lower.endswith(".dockerfile")

    def _scan_dockerfile(self, fpath: Path, findings: list[Finding]) -> None:
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

        instructions = DockerfileParser.parse_file(fpath)
        if not instructions:
            return

        # Determine total number of stages
        from_instructions = [i for i in instructions if i.name == "FROM"]
        max_stage_index = max((i.stage_index for i in instructions), default=0)

        # 1. Base Image Pinning (DOCKER-LATEST-TAG, DOCKER-UNPINNED-BASE)
        for from_inst in from_instructions:
            image_spec = from_inst.args.split()[0] if from_inst.args else ""
            # Strip 'AS alias' if present
            image_spec = re.sub(r"(?i)\s+AS\s+.*$", "", image_spec).strip()

            if not image_spec or image_spec.startswith("scratch"):
                continue

            # Check for digest pinning
            has_digest = "@sha256:" in image_spec or "@sha512:" in image_spec
            if not has_digest:
                if ":" not in image_spec or image_spec.endswith(":latest"):
                    findings.append(
                        Finding(
                            scanner="docker-scanner",
                            category=Category.CONTAINER,
                            rule_id="DOCKER-LATEST-TAG",
                            title="Base Image Uses Latest or Untagged Version",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            description=f"Base image '{image_spec}' uses ':latest' tag or omits an explicit version tag.",
                            impact="Untagged images lead to non-reproducible builds and unexpected breaking upstream updates.",
                            remediation="Pin base image to a specific version tag or immutable digest (e.g. python:3.12-slim).",
                            location=Location(file_path=fpath, start_line=from_inst.start_line, end_line=from_inst.end_line),
                            resource_id=f"Dockerfile:{from_inst.start_line}",
                            metadata={"image": image_spec},
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            scanner="docker-scanner",
                            category=Category.CONTAINER,
                            rule_id="DOCKER-UNPINNED-BASE",
                            title="Base Image Unpinned by Digest",
                            severity=Severity.LOW,
                            confidence=Confidence.HIGH,
                            description=f"Base image '{image_spec}' uses a version tag without an immutable SHA256 digest.",
                            impact="Version tags can be overwritten upstream; digest pinning guarantees supply chain integrity.",
                            remediation="Pin base image digest using image:tag@sha256:<hash>.",
                            location=Location(file_path=fpath, start_line=from_inst.start_line, end_line=from_inst.end_line),
                            resource_id=f"Dockerfile:{from_inst.start_line}",
                            metadata={"image": image_spec},
                        )
                    )

        # 2. Final Stage Non-Root User (DOCKER-ROOT-USER)
        final_stage_instructions = [i for i in instructions if i.stage_index == max_stage_index]
        user_instructions = [i for i in final_stage_instructions if i.name == "USER"]

        if not user_instructions:
            last_inst = final_stage_instructions[-1]
            findings.append(
                Finding(
                    scanner="docker-scanner",
                    category=Category.CONTAINER,
                    rule_id="DOCKER-ROOT-USER",
                    title="Container Running as Root User",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description="Dockerfile final stage lacks a USER instruction and runs as default root.",
                    impact="Containers running as root allow privilege escalation and host system compromise if exploited.",
                    remediation="Create a dedicated non-root user/group and switch to it using USER <username>.",
                    location=Location(file_path=fpath, start_line=last_inst.start_line, end_line=last_inst.end_line),
                    resource_id="Dockerfile:USER",
                )
            )
        else:
            last_user = user_instructions[-1]
            user_val = last_user.args.strip().lower()
            if user_val in ("root", "0", "0:0"):
                findings.append(
                    Finding(
                        scanner="docker-scanner",
                        category=Category.CONTAINER,
                        rule_id="DOCKER-ROOT-USER",
                        title="Container Explicitly Configured to Run as Root",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description=f"Dockerfile explicitly sets 'USER {user_val}' in the final stage.",
                        impact="Running as root grants unnecessary privileges inside the container environment.",
                        remediation="Switch to an unprivileged non-root user account.",
                        location=Location(file_path=fpath, start_line=last_user.start_line, end_line=last_user.end_line),
                        resource_id="Dockerfile:USER",
                    )
                )

        # 3. Final Stage Healthcheck (DOCKER-NO-HEALTHCHECK)
        healthcheck_instructions = [i for i in final_stage_instructions if i.name == "HEALTHCHECK"]
        if not healthcheck_instructions:
            last_inst = final_stage_instructions[-1]
            findings.append(
                Finding(
                    scanner="docker-scanner",
                    category=Category.CONTAINER,
                    rule_id="DOCKER-NO-HEALTHCHECK",
                    title="Missing HEALTHCHECK Instruction",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    description="Dockerfile final stage lacks a HEALTHCHECK instruction.",
                    impact="Without a health check, container orchestrators cannot automatically detect or restart unresponsive containers.",
                    remediation="Add HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost/ || exit 1.",
                    location=Location(file_path=fpath, start_line=last_inst.start_line, end_line=last_inst.end_line),
                    resource_id="Dockerfile:HEALTHCHECK",
                )
            )

        # 4. Instruction Checks across all lines (ADD, ENV/ARG Secrets, EXPOSE, SUDO)
        for inst in instructions:
            # ADD instead of COPY
            if inst.name == "ADD":
                # Exclude URL downloads if explicitly intended
                if not inst.args.startswith("http://") and not inst.args.startswith("https://"):
                    findings.append(
                        Finding(
                            scanner="docker-scanner",
                            category=Category.CONTAINER,
                            rule_id="DOCKER-ADD-INSTEAD-OF-COPY",
                            title="Dangerous ADD Instruction Used Instead of COPY",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            description=f"Instruction 'ADD {inst.args}' used for local file copying.",
                            impact="ADD automatically extracts tar archives and handles URLs unexpectedly, expanding attack surface.",
                            remediation="Use COPY instead of ADD for copying local files into image.",
                            location=Location(file_path=fpath, start_line=inst.start_line, end_line=inst.end_line),
                            resource_id=f"Dockerfile:{inst.start_line}",
                        )
                    )

            # ENV / ARG Secrets
            elif inst.name in ("ENV", "ARG"):
                eq_idx = inst.args.find("=")
                if eq_idx != -1:
                    var_name = inst.args[:eq_idx].strip()
                    var_val = inst.args[eq_idx + 1 :].strip().strip('"\'')

                    if SECRET_VAR_PATTERN.search(var_name) and var_val and not PLACEHOLDER_PATTERN.search(var_val):
                        masked_val = mask_token(var_val)
                        findings.append(
                            Finding(
                                scanner="docker-scanner",
                                category=Category.CONTAINER,
                                rule_id="DOCKER-SECRET-ENV",
                                title=f"Hardcoded Secret in {inst.name} Instruction",
                                severity=Severity.HIGH,
                                confidence=Confidence.HIGH,
                                description=f"Instruction '{inst.name} {var_name}={masked_val}' embeds sensitive credentials.",
                                impact="Credentials in ENV/ARG instructions are baked into container image layers and visible via docker inspect.",
                                remediation="Use build secrets (RUN --mount=type=secret) or pass credentials at runtime.",
                                location=Location(file_path=fpath, start_line=inst.start_line, end_line=inst.end_line),
                                resource_id=f"Dockerfile:{inst.start_line}",
                                metadata={"var_name": var_name, "masked_val": masked_val},
                            )
                        )

            # EXPOSE Sensitive Ports
            elif inst.name == "EXPOSE":
                ports = inst.args.split()
                for p in ports:
                    p_clean = p.split("/")[0]
                    try:
                        port_num = int(p_clean)
                        if port_num in SENSITIVE_PORTS:
                            findings.append(
                                Finding(
                                    scanner="docker-scanner",
                                    category=Category.CONTAINER,
                                    rule_id="DOCKER-SENSITIVE-PORT",
                                    title=f"Sensitive Port Exposed: {port_num}",
                                    severity=Severity.MEDIUM,
                                    confidence=Confidence.MEDIUM,
                                    description=f"Instruction 'EXPOSE {inst.args}' exposes sensitive administrative or database port {port_num}.",
                                    impact="Exposing database or SSH ports directly in container images increases risk of external scanning and exploitation.",
                                    remediation="Remove sensitive port EXPOSE statements unless strictly necessary for internal container networking.",
                                    location=Location(file_path=fpath, start_line=inst.start_line, end_line=inst.end_line),
                                    resource_id=f"Dockerfile:{inst.start_line}",
                                    metadata={"port": port_num},
                                )
                            )
                    except ValueError:
                        pass

            # sudo in RUN
            elif inst.name == "RUN" and re.search(r"\bsudo\b", inst.args):
                findings.append(
                    Finding(
                        scanner="docker-scanner",
                        category=Category.CONTAINER,
                        rule_id="DOCKER-SUDO-USAGE",
                        title="sudo Command Used in RUN Instruction",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        description="Instruction 'RUN' contains 'sudo' command invocation.",
                        impact="Installing or using sudo inside container images introduces unnecessary root escalation utilities.",
                        remediation="Execute build setup as default root user before adding unprivileged USER instruction.",
                        location=Location(file_path=fpath, start_line=inst.start_line, end_line=inst.end_line),
                        resource_id=f"Dockerfile:{inst.start_line}",
                    )
                )
