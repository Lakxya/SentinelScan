"""Console terminal report renderer for SentinelScan."""

from sentinelscan.models.result import ScannerExecutionStatus, ScanResult
from sentinelscan.reporting.base import BaseReporter
from sentinelscan.reporting.json import sanitize_sensitive_data


class ConsoleReporter(BaseReporter):
    """Renders scan results to human-readable clean terminal format."""

    def render(self, result: ScanResult) -> str:
        """Render ScanResult as formatted multi-line terminal report string."""
        target = result.target
        lines: list[str] = []

        lines.append("==================================================")
        lines.append("        SentinelScan Security Assessment          ")
        lines.append("==================================================")
        lines.append("")
        lines.append("TARGET DISCOVERY")
        lines.append(f"  Path              : {target.path}")
        lines.append(f"  Target Type       : {'Directory' if target.is_directory else 'File'}")
        lines.append(f"  Git Repository    : {'Yes' if target.is_git_repo else 'No'}")
        lines.append(f"  Total Files       : {target.file_count}")
        lines.append(f"  Total Size        : {target.total_size_bytes} bytes")
        
        indicators_str = ", ".join(target.detected_indicators) if target.detected_indicators else "None detected"
        lines.append(f"  Detected Tech     : {indicators_str}")
        lines.append("")

        lines.append("SCANNER MODULES")
        if not result.scanner_results:
            lines.append("  Status            : Base architecture initialized (0 scanner modules currently registered)")
            lines.append("  Notice            : Detection engines (SAST, SCA, DAST, Secrets, Containers, IaC, Cloud)")
            lines.append("                      are being prepared for future milestones.")
        else:
            for sr in result.scanner_results:
                status_tag = {
                    ScannerExecutionStatus.SUCCESS: "OK",
                    ScannerExecutionStatus.FAILED: "ERR",
                    ScannerExecutionStatus.UNAVAILABLE: "N/A",
                    ScannerExecutionStatus.SKIPPED: "SKIP",
                }.get(sr.status, "INFO")
                lines.append(
                    f"  [{status_tag:<4}] {sr.scanner_name:<20} : {sr.status.value} "
                    f"({sr.finding_count} findings, {sr.duration_seconds:.3f}s)"
                )
                if sr.error_message:
                    lines.append(f"      Error Details : {sr.error_message}")

        lines.append("")

        lines.append("FINDINGS SUMMARY")
        lines.append(f"  Total Findings    : {result.total_findings}")
        lines.append("")

        if result.findings:
            lines.append("FINDINGS DETAILS")
            lines.append("--------------------------------------------------")
            for i, f in enumerate(result.findings, 1):
                sanitized_f = sanitize_sensitive_data(f.to_dict())
                loc_str = "N/A"
                if f.location:
                    loc_str = str(f.location.file_path)
                    if f.location.start_line is not None:
                        loc_str += f":L{f.location.start_line}"

                lines.append(f"  [{i}] [{sanitized_f['severity']}] {sanitized_f['title']}")
                lines.append(f"      Rule ID       : {sanitized_f['rule_id']} ({sanitized_f['scanner']})")
                lines.append(f"      Category      : {sanitized_f['category']}")
                lines.append(f"      Confidence    : {sanitized_f['confidence']}")
                lines.append(f"      Location      : {loc_str}")
                lines.append(f"      Description   : {sanitized_f['description']}")
                lines.append(f"      Impact        : {sanitized_f['impact']}")
                lines.append(f"      Remediation   : {sanitized_f['remediation']}")
                lines.append("--------------------------------------------------")

        lines.append(f"EXECUTION COMPLETED in {result.duration_seconds:.3f} seconds.")
        lines.append("==================================================")
        return "\n".join(lines)
