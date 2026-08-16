"""Data models for SentinelScan Posture Scoring & Remediation Guidance."""

from dataclasses import dataclass, field
from typing import Any

from sentinelscan.models.finding import Category


@dataclass
class DeductionTrace:
    """Dataclass representing an explainable point deduction entry in posture scoring."""

    source_type: str  # "finding" or "attack_path"
    rule_id: str
    resource_id: str
    domain: str
    severity: str
    confidence: str
    points_deducted: float
    reason: str

    def to_dict(self) -> dict[str, Any]:
        """Convert DeductionTrace instance to serializable dictionary."""
        return {
            "source_type": self.source_type,
            "rule_id": self.rule_id,
            "resource_id": self.resource_id,
            "domain": self.domain,
            "severity": self.severity,
            "confidence": self.confidence,
            "points_deducted": round(self.points_deducted, 1),
            "reason": self.reason,
        }


@dataclass
class DomainScore:
    """Dataclass representing a domain-level security posture score."""

    domain: Category
    score: float  # 0.0 to 100.0
    grade: str
    finding_count: int
    critical_count: int
    high_count: int
    deductions: list[DeductionTrace] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert DomainScore instance to serializable dictionary."""
        return {
            "domain": self.domain.value if hasattr(self.domain, "value") else str(self.domain),
            "score": round(self.score, 1),
            "grade": self.grade,
            "finding_count": self.finding_count,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "deductions": [d.to_dict() for d in self.deductions],
        }


@dataclass
class RemediationAdvice:
    """Dataclass representing actionable, prioritized remediation guidance."""

    priority: int  # 1 (Highest) to N
    priority_score: float
    rule_id: str
    category: Category
    title: str
    action_item: str
    impact_reduction: str
    affected_locations: list[str]
    in_attack_path: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert RemediationAdvice instance to serializable dictionary."""
        return {
            "priority": self.priority,
            "priority_score": round(self.priority_score, 1),
            "rule_id": self.rule_id,
            "category": self.category.value if hasattr(self.category, "value") else str(self.category),
            "title": self.title,
            "action_item": self.action_item,
            "impact_reduction": self.impact_reduction,
            "affected_locations": self.affected_locations,
            "in_attack_path": self.in_attack_path,
        }


@dataclass
class PostureScore:
    """Dataclass representing the overall DevSecOps security posture score and remediation report."""

    overall_score: float
    grade: str
    domain_scores: dict[str, DomainScore] = field(default_factory=dict)
    deductions_explainability: list[DeductionTrace] = field(default_factory=list)
    remediations: list[RemediationAdvice] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert PostureScore instance to serializable dictionary."""
        return {
            "overall_score": round(self.overall_score, 1),
            "grade": self.grade,
            "domain_scores": {k: v.to_dict() for k, v in self.domain_scores.items()},
            "deductions_explainability": [d.to_dict() for d in self.deductions_explainability],
            "remediations": [r.to_dict() for r in self.remediations],
        }
