"""Reporters for rendering DevSecOps security posture scores and remediation guidance."""

import json
from typing import Any

from sentinelscan.models.posture import PostureScore


class TerminalPostureReporter:
    """Reporter rendering security posture scores and remediation guidance into clean terminal text."""

    def render(self, posture: PostureScore, target_path_str: str = ".") -> str:
        """Render posture score and remediation advice into formatted terminal text output.

        Args:
            posture: PostureScore instance.
            target_path_str: Target path string.

        Returns:
            str: Formatted terminal text output.
        """
        lines: list[str] = []
        lines.append("=" * 50)
        lines.append("     SentinelScan Posture & Remediation Report    ")
        lines.append("=" * 50)
        lines.append("")
        lines.append("SECURITY POSTURE SUMMARY")
        lines.append(f"  Target Path       : {target_path_str}")
        lines.append(f"  Overall Score     : {posture.overall_score:.1f} / 100.0")
        lines.append(f"  Security Grade    : {posture.grade}")
        total_findings = sum(ds.finding_count for ds in posture.domain_scores.values())
        lines.append(f"  Total Findings    : {total_findings}")

        lines.append("")
        lines.append("DOMAIN BREAKDOWN")
        lines.append("-" * 50)
        for domain_name, ds in posture.domain_scores.items():
            domain_label = f"[{domain_name:<10}]"
            lines.append(
                f"  {domain_label}  {ds.score:5.1f} / 100 (Grade: {ds.grade:<2}) | {ds.finding_count} findings ({ds.critical_count} Crit, {ds.high_count} High)"
            )

        if posture.deductions_explainability:
            lines.append("")
            lines.append("SCORE EXPLAINABILITY (DEDUCTIONS TRACE)")
            lines.append("-" * 50)
            for trace in posture.deductions_explainability:
                lines.append(
                    f"  -{trace.points_deducted:4.1f} pts : [{trace.domain}] {trace.rule_id} on '{trace.resource_id}' ({trace.severity}/{trace.confidence})"
                )

        if posture.remediations:
            lines.append("")
            lines.append("PRIORITIZED REMEDIATION GUIDANCE")
            lines.append("-" * 50)
            for rem in posture.remediations[:5]:  # Top 5 remediations
                path_flag = " [ATTACK PATH]" if rem.in_attack_path else ""
                lines.append(f"[Priority {rem.priority}] {rem.title}{path_flag}")
                lines.append(f"    Rule ID       : {rem.rule_id} ({rem.category})")
                lines.append(f"    Action        : {rem.action_item}")
                lines.append(f"    Impact        : {rem.impact_reduction}")
                if rem.affected_locations:
                    locs_str = ", ".join(rem.affected_locations)
                    lines.append(f"    Locations     : {locs_str}")
                lines.append("-" * 50)

        lines.append("EXECUTION COMPLETED.")
        lines.append("=" * 50)
        return "\n".join(lines)


class JsonPostureReporter:
    """Reporter rendering security posture scores and remediation guidance into structured machine-readable JSON."""

    def render(self, posture: PostureScore) -> str:
        """Render PostureScore into JSON string.

        Args:
            posture: PostureScore instance.

        Returns:
            str: Pretty-printed JSON string.
        """
        payload: dict[str, Any] = posture.to_dict()
        return json.dumps(payload, indent=2)
