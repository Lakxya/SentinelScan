"""Finding model representing normalized security scan discoveries."""

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Category(str, Enum):
    """Security assessment domain category."""

    SAST = "sast"
    SCA = "sca"
    DAST = "dast"
    SECRET = "secret"
    CONTAINER = "container"
    KUBERNETES = "kubernetes"
    IAC = "iac"
    CLOUD = "cloud"
    NETWORK = "network"
    ARCHITECTURE = "architecture"


class Severity(str, Enum):
    """Standardized finding severity ratings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    """Finding confidence levels."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True)
class Location:
    """Location of a finding within a file or artifact.

    Intentionally omits raw source snippets to prevent accidental leakage
    of sensitive source code or embedded secrets in findings.
    """

    file_path: Path
    start_line: int | None = None
    end_line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert location to a JSON-serializable dictionary."""
        return {
            "file_path": str(self.file_path),
            "start_line": self.start_line,
            "end_line": self.end_line,
        }


@dataclass
class Finding:
    """Normalized security finding produced by a scanner module.

    Designed for future attack-path correlation, deduplication, and risk scoring.
    """

    scanner: str
    category: Category
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    description: str
    impact: str
    remediation: str
    location: Location | None = None
    resource_id: str | None = None
    tags: list[str] = field(default_factory=list)
    related_finding_ids: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    finding_id: str = field(init=False)
    fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        """Compute deterministic fingerprint and finding_id."""
        loc_str = (
            f"{self.location.file_path}:{self.location.start_line or ''}"
            if self.location
            else ""
        )
        res_str = self.resource_id or ""
        identity_seed = f"{self.scanner}:{self.rule_id}:{loc_str}:{res_str}:{self.title}"
        self.fingerprint = hashlib.sha256(identity_seed.encode("utf-8")).hexdigest()[:16]
        self.finding_id = f"FS-{self.fingerprint}"

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to a JSON-serializable dictionary."""
        return {
            "finding_id": self.finding_id,
            "fingerprint": self.fingerprint,
            "scanner": self.scanner,
            "category": self.category.value if isinstance(self.category, Enum) else self.category,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value if isinstance(self.severity, Enum) else self.severity,
            "confidence": (
                self.confidence.value
                if isinstance(self.confidence, Enum)
                else self.confidence
            ),
            "description": self.description,
            "impact": self.impact,
            "remediation": self.remediation,
            "location": self.location.to_dict() if self.location else None,
            "resource_id": self.resource_id,
            "tags": self.tags,
            "related_finding_ids": self.related_finding_ids,
            "metadata": self.metadata,
        }
