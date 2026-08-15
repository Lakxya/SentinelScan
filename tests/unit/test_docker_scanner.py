"""Unit tests for DockerScanner, DockerfileParser, security rules, and CLI commands."""

from sentinelscan.models.finding import Category, Confidence, Severity
from sentinelscan.models.result import ScannerExecutionResult, ScannerExecutionStatus, ScanResult
from sentinelscan.models.target import Target
from sentinelscan.reporting.json import JsonReporter
from sentinelscan.scanners.docker_scanner import DockerfileParser, DockerScanner


def test_dockerfile_parser_line_continuations_and_comments(tmp_path):
    r"""Verify DockerfileParser handles line continuations (\), comments (#), and instruction casing."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "# Global comment\n"
        "FROM python:3.12-slim\n"
        "\n"
        "# Install dependencies\n"
        "run apt-get update \\\n"
        " && apt-get install -y curl \\\n"
        " && rm -rf /var/lib/apt/lists/*\n"
        "\n"
        "user appuser\n"
    )

    instructions = DockerfileParser.parse_file(dockerfile)
    assert len(instructions) == 3

    assert instructions[0].name == "FROM"
    assert instructions[0].args == "python:3.12-slim"
    assert instructions[0].start_line == 2

    assert instructions[1].name == "RUN"
    assert instructions[1].start_line == 5
    assert instructions[1].end_line == 7
    assert "curl" in instructions[1].args

    assert instructions[2].name == "USER"
    assert instructions[2].args == "appuser"


def test_docker_single_stage_positive_detections(tmp_path):
    """Verify single-stage Dockerfile detections for latest tag, missing user, secret env, and sensitive port."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM ubuntu:latest\n"
        "ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "ADD app.tar.gz /app\n"
        "EXPOSE 22\n"
        "RUN sudo apt-get update\n"
    )

    scanner = DockerScanner()
    target = Target(
        path=dockerfile,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(dockerfile.read_bytes()),
    )

    findings = scanner.scan(target)
    rule_ids = [f.rule_id for f in findings]

    assert "DOCKER-LATEST-TAG" in rule_ids
    assert "DOCKER-ROOT-USER" in rule_ids
    assert "DOCKER-SECRET-ENV" in rule_ids
    assert "DOCKER-ADD-INSTEAD-OF-COPY" in rule_ids
    assert "DOCKER-SENSITIVE-PORT" in rule_ids
    assert "DOCKER-SUDO-USAGE" in rule_ids
    assert "DOCKER-NO-HEALTHCHECK" in rule_ids

    secret_finding = next(f for f in findings if f.rule_id == "DOCKER-SECRET-ENV")
    assert secret_finding.severity == Severity.HIGH
    assert secret_finding.confidence == Confidence.HIGH
    assert secret_finding.category == Category.CONTAINER
    # Ensure raw secret is masked
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in secret_finding.description
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in str(secret_finding.metadata)


def test_docker_multi_stage_build_intelligence(tmp_path):
    """Verify multi-stage builds evaluate USER and HEALTHCHECK rules only on the final runtime stage."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "# Stage 1: Builder (runs as root)\n"
        "FROM golang:1.21 AS builder\n"
        "WORKDIR /build\n"
        "COPY . .\n"
        "RUN go build -o app .\n"
        "\n"
        "# Stage 2: Final runtime stage\n"
        "FROM alpine:3.19\n"
        "RUN addgroup -S appgroup && adduser -S appuser -G appgroup\n"
        "COPY --from=builder /build/app /app/app\n"
        "HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://localhost/ || exit 1\n"
        "USER appuser\n"
        "ENTRYPOINT [\"/app/app\"]\n"
    )

    scanner = DockerScanner()
    target = Target(
        path=dockerfile,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(dockerfile.read_bytes()),
    )

    findings = scanner.scan(target)
    rule_ids = [f.rule_id for f in findings]

    # Stage 2 has USER appuser and HEALTHCHECK, so DOCKER-ROOT-USER and DOCKER-NO-HEALTHCHECK must NOT trigger!
    assert "DOCKER-ROOT-USER" not in rule_ids
    assert "DOCKER-NO-HEALTHCHECK" not in rule_ids


def test_docker_digest_pinned_base_image(tmp_path):
    """Verify base images pinned with immutable SHA256 digests produce 0 pinning findings."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.12-slim@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef\n"
        "HEALTHCHECK --interval=30s CMD curl -f http://localhost/ || exit 1\n"
        "USER 10001\n"
    )

    scanner = DockerScanner()
    target = Target(
        path=dockerfile,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(dockerfile.read_bytes()),
    )

    findings = scanner.scan(target)
    rule_ids = [f.rule_id for f in findings]

    assert "DOCKER-LATEST-TAG" not in rule_ids
    assert "DOCKER-UNPINNED-BASE" not in rule_ids
    assert len(findings) == 0


def test_docker_json_serialization(tmp_path):
    """Verify Docker findings can be serialized to machine-readable JSON."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:latest\n"
    )

    scanner = DockerScanner()
    target = Target(
        path=dockerfile,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(dockerfile.read_bytes()),
    )

    findings = scanner.scan(target)
    assert len(findings) >= 1

    res = ScanResult(
        target=target,
        findings=findings,
        scanner_results=[
            ScannerExecutionResult(scanner_name="docker-scanner", status=ScannerExecutionStatus.SUCCESS)
        ],
    )
    json_out = JsonReporter().render(res)
    assert '"rule_id": "DOCKER-LATEST-TAG"' in json_out
    assert '"category": "container"' in json_out
