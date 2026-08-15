"""Integration tests verifying full scan execution pipeline from discovery to report generation."""

from sentinelscan.core.discovery import ProjectDiscoverer
from sentinelscan.core.engine import ScanEngine
from sentinelscan.models.finding import Category, Confidence, Finding, Location, Severity
from sentinelscan.models.target import Target
from sentinelscan.reporting.console import ConsoleReporter
from sentinelscan.reporting.json import JsonReporter
from sentinelscan.scanners.base import BaseScanner
from sentinelscan.scanners.registry import ScannerRegistry


class SampleIaCScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "sample-iac-scanner"

    @property
    def category(self) -> Category:
        return Category.IAC

    @property
    def description(self) -> str:
        return "Sample IaC security checker"

    def is_available(self, target: Target) -> bool:
        return "iac-terraform" in target.detected_indicators

    def scan(self, target: Target) -> list[Finding]:
        return [
            Finding(
                scanner=self.name,
                category=self.category,
                rule_id="IAC-001",
                title="Unencrypted S3 Bucket",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description="S3 bucket missing server-side encryption configuration.",
                impact="Potential unauthorized data exposure.",
                remediation="Enable AES-256 or KMS server-side encryption.",
                location=Location(file_path=target.path / "main.tf", start_line=1),
                resource_id="aws_s3_bucket.data_store",
                tags=["terraform", "aws", "s3"],
            )
        ]


def test_full_scan_pipeline_integration(tmp_path):
    """Test full end-to-end flow: target discovery -> engine run -> report generation."""
    # 1. Prepare target project with Terraform file
    tf_file = tmp_path / "main.tf"
    tf_file.write_text('resource "aws_s3_bucket" "data_store" {}')

    # 2. Discover target
    discoverer = ProjectDiscoverer()
    target = discoverer.discover(tmp_path)
    assert "iac-terraform" in target.detected_indicators

    # 3. Register scanner & execute scan engine
    registry = ScannerRegistry()
    registry.register(SampleIaCScanner())

    engine = ScanEngine(registry=registry)
    result = engine.run(target)

    # 4. Assert findings and scanner outcome
    assert result.total_findings == 1
    assert result.findings[0].rule_id == "IAC-001"
    assert result.successful_scanners == ["sample-iac-scanner"]

    # 5. Render reports
    console_out = ConsoleReporter().render(result)
    assert "Unencrypted S3 Bucket" in console_out

    json_out = JsonReporter().render(result)
    assert '"rule_id": "IAC-001"' in json_out
