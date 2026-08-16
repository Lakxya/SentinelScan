"""Reporters for rendering potential attack paths into terminal ASCII text and machine-readable JSON."""

import json
from typing import Any

from sentinelscan.models.attack_path import AttackPath


class TerminalPathReporter:
    """Reporter rendering potential attack paths into clean terminal ASCII text."""

    def render(self, paths: list[AttackPath], target_path_str: str = ".") -> str:
        """Render potential attack paths into formatted terminal text output.

        Args:
            paths: List of AttackPath instances.
            target_path_str: Target path string.

        Returns:
            str: Formatted terminal text output.
        """
        lines: list[str] = []
        lines.append("=" * 50)
        lines.append("     SentinelScan Potential Attack Path Analysis   ")
        lines.append("=" * 50)
        lines.append("")
        lines.append("TARGET DISCOVERY")
        lines.append(f"  Target Path       : {target_path_str}")
        lines.append(f"  Potential Paths   : {len(paths)}")

        if paths:
            highest_score = max(p.composite_risk_score for p in paths)
            highest_sev = paths[0].composite_severity.value
            lines.append(f"  Highest Risk Score: {highest_score:.1f} ({highest_sev})")

        lines.append("")
        lines.append("CORRELATED POTENTIAL ATTACK PATHS")
        lines.append("-" * 50)

        if not paths:
            lines.append("No potential attack paths or correlated risk chains identified.")
        else:
            for idx, path in enumerate(paths, start=1):
                sev_val = path.composite_severity.value if hasattr(path.composite_severity, "value") else str(path.composite_severity)
                conf_val = path.confidence.value if hasattr(path.confidence, "value") else str(path.confidence)
                lines.append(
                    f"[{idx}] [{sev_val}] (Risk Score: {path.composite_risk_score:.1f} | Confidence: {conf_val}) {path.title}"
                )
                lines.append(f"    Path ID       : {path.path_id}")
                lines.append(f"    Entry Point   : {path.entry_node_id}")
                lines.append(f"    Impact Target : {path.target_node_id}")
                lines.append("")
                lines.append("    Correlated Path Steps (Max Depth 5):")

                total_steps = len(path.steps)
                for s_idx, step in enumerate(path.steps, start=1):
                    prefix = "    └── " if s_idx == total_steps else "    ├── "
                    finding_str = f" [Finding: {step.rule_id} ({step.severity})]" if step.rule_id else ""
                    lines.append(
                        f"{prefix}Step {step.step_number}: [{step.node_type}] {step.node_name}{finding_str}"
                    )
                    lines.append(f"                 Description: {step.description}")

                lines.append("")
                lines.append(f"    Remediation   : {path.remediation_summary}")
                lines.append("-" * 50)

        lines.append("EXECUTION COMPLETED.")
        lines.append("=" * 50)
        return "\n".join(lines)


class JsonPathReporter:
    """Reporter rendering potential attack paths into structured machine-readable JSON."""

    def render(self, paths: list[AttackPath]) -> str:
        """Render potential attack paths into JSON string.

        Args:
            paths: List of AttackPath instances.

        Returns:
            str: Pretty-printed JSON string.
        """
        payload: dict[str, Any] = {
            "summary": {
                "total_potential_paths": len(paths),
                "highest_risk_score": round(max((p.composite_risk_score for p in paths), default=0.0), 1),
            },
            "attack_paths": [path.to_dict() for path in paths],
        }
        return json.dumps(payload, indent=2)
