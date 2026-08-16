"""Data models for SentinelScan Attack-Path & Risk Correlation."""

import hashlib
from dataclasses import dataclass, field
from typing import Any

from sentinelscan.models.finding import Confidence, Severity


@dataclass
class AttackStep:
    """Dataclass representing an individual step in a potential attack path or correlated risk path."""

    step_number: int
    node_id: str
    node_name: str
    node_type: str
    description: str
    finding_fingerprint: str | None = None
    rule_id: str | None = None
    severity: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert AttackStep instance to serializable dictionary."""
        return {
            "step_number": self.step_number,
            "node_id": self.node_id,
            "node_name": self.node_name,
            "node_type": self.node_type,
            "description": self.description,
            "finding_fingerprint": self.finding_fingerprint,
            "rule_id": self.rule_id,
            "severity": self.severity,
        }


@dataclass
class AttackPath:
    """Dataclass representing a potential attack path or correlated risk path linking asset nodes and findings."""

    path_id: str
    title: str
    entry_node_id: str
    target_node_id: str
    steps: list[AttackStep] = field(default_factory=list)
    composite_severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.MEDIUM
    composite_risk_score: float = 5.0
    remediation_summary: str = ""

    @property
    def fingerprint(self) -> str:
        """Compute a deterministic 16-character SHA-256 fingerprint for path deduplication."""
        raw = f"{self.entry_node_id}:{self.target_node_id}:" + ":".join(s.node_id for s in self.steps)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        """Convert AttackPath instance to serializable dictionary."""
        return {
            "path_id": self.path_id,
            "fingerprint": self.fingerprint,
            "title": self.title,
            "entry_node_id": self.entry_node_id,
            "target_node_id": self.target_node_id,
            "steps": [step.to_dict() for step in self.steps],
            "composite_severity": self.composite_severity.value if hasattr(self.composite_severity, "value") else str(self.composite_severity),
            "confidence": self.confidence.value if hasattr(self.confidence, "value") else str(self.confidence),
            "composite_risk_score": round(self.composite_risk_score, 1),
            "remediation_summary": self.remediation_summary,
        }
