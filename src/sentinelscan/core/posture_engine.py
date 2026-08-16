"""DevSecOps Posture Scoring & Remediation Guidance Engine."""

import logging

from sentinelscan.models.attack_path import AttackPath
from sentinelscan.models.finding import Category, Confidence, Finding, Severity
from sentinelscan.models.posture import DeductionTrace, DomainScore, PostureScore, RemediationAdvice
from sentinelscan.models.result import ScanResult
from sentinelscan.scanners.secret_scanner import mask_token

logger = logging.getLogger("sentinelscan.core.posture_engine")

SEVERITY_BASE_WEIGHTS = {
    Severity.CRITICAL: 15.0,
    Severity.HIGH: 8.0,
    Severity.MEDIUM: 3.0,
    Severity.LOW: 1.0,
    Severity.INFO: 0.0,
}

CONFIDENCE_MULTIPLIERS = {
    Confidence.HIGH: 1.0,
    Confidence.MEDIUM: 0.8,
    Confidence.LOW: 0.5,
}

ALL_DOMAINS = [
    Category.SECRET,
    Category.SAST,
    Category.IAC,
    Category.SCA,
    Category.CONTAINER,
    Category.KUBERNETES,
    Category.CLOUD,
    Category.DAST,
    Category.NETWORK,
]


def calculate_grade(score: float) -> str:
    """Calculate letter grade from numeric score (0.0 to 100.0)."""
    if score >= 95.0:
        return "A+"
    if score >= 90.0:
        return "A"
    if score >= 80.0:
        return "B"
    if score >= 70.0:
        return "C"
    if score >= 60.0:
        return "D"
    return "F"


class RemediationEngine:
    """Prioritizes and deduplicates remediation guidance across findings and potential attack paths."""

    @staticmethod
    def generate_remediations(
        findings: list[Finding],
        attack_paths: list[AttackPath] | None = None,
    ) -> list[RemediationAdvice]:
        if not findings:
            return []

        # Map attack path rules for bonus ranking
        path_rule_ids: set[str] = set()
        if attack_paths:
            for path in attack_paths:
                for step in path.steps:
                    if step.rule_id:
                        path_rule_ids.add(step.rule_id)

        # Group findings by rule_id
        grouped: dict[str, list[Finding]] = {}
        for f in findings:
            grouped.setdefault(f.rule_id, []).append(f)

        advice_list: list[tuple[float, RemediationAdvice]] = []

        for rule_id, f_list in grouped.items():
            rep_finding = f_list[0]
            locations = list({f"{f.location.file_path}:{f.location.start_line}" for f in f_list if f.location.file_path})
            affected_count = len(locations)

            sev_wt = SEVERITY_BASE_WEIGHTS.get(rep_finding.severity, 3.0)
            conf_mult = CONFIDENCE_MULTIPLIERS.get(rep_finding.confidence, 0.8)
            in_path = rule_id in path_rule_ids
            in_path_bonus = 5.0 if in_path else 0.0

            priority_score = (sev_wt * conf_mult) + (affected_count * 0.5) + in_path_bonus

            action = rep_finding.remediation or f"Remediate {rule_id} finding."
            title = rep_finding.title or f"Fix {rule_id}"
            impact_red = f"Reduces score penalty by {sev_wt:.1f} pts."
            if in_path:
                impact_red += " Resolves correlated potential attack path."

            advice = RemediationAdvice(
                priority=1,  # Temporary, updated after sorting
                priority_score=priority_score,
                rule_id=rule_id,
                category=rep_finding.category,
                title=mask_token(title),
                action_item=mask_token(action),
                impact_reduction=impact_red,
                affected_locations=locations[:5],  # Top 5 locations
                in_attack_path=in_path,
            )
            advice_list.append((priority_score, advice))

        # Sort descending by priority score
        advice_list.sort(key=lambda x: x[0], reverse=True)

        final_remediations: list[RemediationAdvice] = []
        for idx, (_, advice) in enumerate(advice_list, start=1):
            advice.priority = idx
            final_remediations.append(advice)

        return final_remediations


class PostureEngine:
    """Explainable security posture scoring engine executing domain breakdowns and score clamping."""

    def evaluate_posture(
        self,
        scan_result: ScanResult,
        attack_paths: list[AttackPath] | None = None,
    ) -> PostureScore:
        # Deduplicate findings by fingerprint before scoring
        dedup_findings: dict[str, Finding] = {}
        for f in scan_result.findings:
            if f.fingerprint not in dedup_findings:
                dedup_findings[f.fingerprint] = f

        findings_list = list(dedup_findings.values())

        # Group findings by domain category
        domain_findings: dict[Category, list[Finding]] = {d: [] for d in ALL_DOMAINS}
        for f in findings_list:
            if f.category in domain_findings:
                domain_findings[f.category].append(f)

        domain_scores: dict[str, DomainScore] = {}
        all_deductions: list[DeductionTrace] = []

        # 1. Compute Domain-Level Scores
        for domain in ALL_DOMAINS:
            f_sub = domain_findings[domain]
            domain_deductions: list[DeductionTrace] = []
            total_domain_deduction = 0.0

            crit_count = sum(1 for f in f_sub if f.severity == Severity.CRITICAL)
            high_count = sum(1 for f in f_sub if f.severity == Severity.HIGH)

            for f in f_sub:
                base_wt = SEVERITY_BASE_WEIGHTS.get(f.severity, 0.0)
                conf_mult = CONFIDENCE_MULTIPLIERS.get(f.confidence, 1.0)
                pts = base_wt * conf_mult
                total_domain_deduction += pts

                trace = DeductionTrace(
                    source_type="finding",
                    rule_id=f.rule_id,
                    resource_id=f.resource_id or str(f.location.file_path or "asset"),
                    domain=domain.value if hasattr(domain, "value") else str(domain),
                    severity=f.severity.value,
                    confidence=f.confidence.value,
                    points_deducted=pts,
                    reason=f"Finding {f.rule_id} ({f.severity.value}/{f.confidence.value})",
                )
                domain_deductions.append(trace)
                all_deductions.append(trace)

            raw_d_score = 100.0 - total_domain_deduction
            clamped_d_score = max(0.0, min(100.0, raw_d_score))
            d_grade = calculate_grade(clamped_d_score)

            d_key = domain.value if hasattr(domain, "value") else str(domain)
            domain_scores[d_key] = DomainScore(
                domain=domain,
                score=clamped_d_score,
                grade=d_grade,
                finding_count=len(f_sub),
                critical_count=crit_count,
                high_count=high_count,
                deductions=domain_deductions,
            )

        # 2. Compute Overall Base Score (Average of all domain scores)
        overall_base = sum(ds.score for ds in domain_scores.values()) / len(domain_scores)

        # 3. Compute Anti-Double-Counting Attack Path Penalty (Applied to overall score only, capped at 15.0 max)
        path_penalty = 0.0
        if attack_paths:
            for path in attack_paths:
                if path.composite_severity == Severity.CRITICAL:
                    path_penalty += 3.0
                elif path.composite_severity == Severity.HIGH:
                    path_penalty += 1.5
                elif path.composite_severity == Severity.MEDIUM:
                    path_penalty += 0.5

            path_penalty = min(15.0, path_penalty)

            if path_penalty > 0:
                all_deductions.append(
                    DeductionTrace(
                        source_type="attack_path",
                        rule_id="ATTACK-PATH-RISK",
                        resource_id=f"{len(attack_paths)} paths",
                        domain="overall",
                        severity="HIGH",
                        confidence="HIGH",
                        points_deducted=path_penalty,
                        reason=f"Correlated potential attack path risk penalty ({path_penalty:.1f} pts capped)",
                    )
                )

        # 4. Compute Final Overall Score (Clamped 0.0 to 100.0)
        final_overall_score = max(0.0, min(100.0, overall_base - path_penalty))
        overall_grade = calculate_grade(final_overall_score)

        # 5. Generate Prioritized Remediations
        remediations = RemediationEngine.generate_remediations(findings_list, attack_paths)

        return PostureScore(
            overall_score=final_overall_score,
            grade=overall_grade,
            domain_scores=domain_scores,
            deductions_explainability=all_deductions,
            remediations=remediations,
        )
