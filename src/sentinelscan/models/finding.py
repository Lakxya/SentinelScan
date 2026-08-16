"""Finding models for SentinelScan security findings."""

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Category(str, Enum):
    """Enumeration of supported scanner security categories."""

    SECRET = "secret"
    SAST = "sast"
    IAC = "iac"
    SCA = "sca"
    CONTAINER = "container"
    KUBERNETES = "kubernetes"
    CLOUD = "cloud"
    DAST = "dast"
    NETWORK = "network"


class Severity(str, Enum):
    """Enumeration of finding severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    """Enumeration of finding confidence levels."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Location:
    """Dataclass representing the file or asset location of a security finding."""

    file_path: Path | None = None
    start_line: int = 1
    end_line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert Location instance to dictionary (omitting raw code snippets)."""
        return {
            "file_path": str(self.file_path) if self.file_path else None,
            "start_line": self.start_line,
            "end_line": self.end_line if self.end_line is not None else self.start_line,
        }


@dataclass
class Finding:
    """Dataclass representing a normalized SentinelScan security finding."""

    scanner: str
    category: Category
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    description: str
    impact: str
    remediation: str
    location: Location
    resource_id: str = ""
    tags: list[str] = field(default_factory=list)
    related_finding_ids: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        """Compute a deterministic 16-character SHA-256 fingerprint for finding deduplication."""
        loc_str = f"{self.location.file_path}:{self.location.start_line}"
        raw = f"{self.scanner}:{self.rule_id}:{loc_str}:{self.resource_id}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    @property
    def finding_id(self) -> str:
        """Return formatted finding ID string."""
        return f"FS-{self.fingerprint}"

    def to_dict(self) -> dict[str, Any]:
        """Convert Finding instance to serializable dictionary."""
        return {
            "finding_id": self.finding_id,
            "fingerprint": self.fingerprint,
            "scanner": self.scanner,
            "category": self.category.value if hasattr(self.category, "value") else str(self.category),
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value if hasattr(self.severity, "value") else str(self.severity),
            "confidence": self.confidence.value if hasattr(self.confidence, "value") else str(self.confidence),
            "description": self.description,
            "impact": self.impact,
            "remediation": self.remediation,
            "location": self.location.to_dict(),
            "resource_id": self.resource_id,
            "tags": self.tags,
            "related_finding_ids": self.related_finding_ids,
            "metadata": self.metadata,
        }
