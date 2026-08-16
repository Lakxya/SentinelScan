"""Full end-to-end v1.3.0 pipeline integration test verifying multi-domain discovery, scanner aggregation, architecture graph, attack path correlation, posture scoring, and report formatters."""

import json
import socket

from sentinelscan.core.attack_path_engine import AttackPathEngine
from sentinelscan.core.discovery import ProjectDiscoverer
from sentinelscan.core.engine import ScanEngine
from sentinelscan.core.graph_builder import ArchitectureGraphBuilder
from sentinelscan.core.posture_engine import PostureEngine
from sentinelscan.models.result import ScanResult
from sentinelscan.reporting.console import ConsoleReporter
from sentinelscan.reporting.graph_reporter import JsonGraphReporter, TerminalGraphReporter
from sentinelscan.reporting.json import JsonReporter
from sentinelscan.reporting.path_reporter import JsonPathReporter, TerminalPathReporter
from sentinelscan.reporting.posture_reporter import JsonPostureReporter, TerminalPostureReporter


def test_full_v130_end_to_end_pipeline(tmp_path, monkeypatch):
    """Verify complete v1.3.0 pipeline: discovery -> scan engine -> graph -> attack paths -> posture scoring -> reporters."""

    # Guarantee zero network calls throughout static pipeline
    def _forbidden_connect(*args, **kwargs):
        raise RuntimeError("Network socket call attempted during static pipeline execution!")

    monkeypatch.setattr(socket, "socket", _forbidden_connect)

    # 1. Create a rich target project directory with multiple domain assets
    (tmp_path / "main.tf").write_text(
        'resource "aws_s3_bucket" "public_data" {\n  bucket = "my-public-bucket"\n}\n'
        'resource "aws_iam_policy" "admin" {\n  name = "admin"\n}\n'
    )
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\nEXPOSE 3306\n")
    (tmp_path / "k8s.yaml").write_text(
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: db-secret\n  namespace: default\ndata:\n  password: c2VjcmV0cGFzc3dvcmQ=\n"
    )
    (tmp_path / "app.py").write_text("import os\nos.system('echo test')\n")
    (tmp_path / "aws_policy.json").write_text(
        '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::my-public-bucket/*"}]}'
    )

    # 2. Discover target
    discoverer = ProjectDiscoverer()
    target = discoverer.discover(tmp_path)
    assert target.is_directory is True
    assert target.file_count >= 5

    # 3. Run scan engine with default scanners
    engine = ScanEngine()
    scan_result = engine.run(target)
    assert isinstance(scan_result, ScanResult)
    assert len(scan_result.successful_scanners) >= 8
    assert scan_result.total_findings > 0

    # 4. Build architecture graph
    graph_builder = ArchitectureGraphBuilder()
    graph = graph_builder.build(target, scan_result=scan_result)
    assert len(graph.nodes) > 0

    # 5. Discover potential attack paths
    path_engine = AttackPathEngine(max_depth=5)
    attack_paths = path_engine.discover_paths(graph, scan_result=scan_result)
    assert isinstance(attack_paths, list)

    # 6. Evaluate DevSecOps posture score
    posture_engine = PostureEngine()
    posture_score = posture_engine.evaluate_posture(scan_result, attack_paths=attack_paths)
    assert 0.0 <= posture_score.overall_score <= 100.0
    assert posture_score.grade in ("A+", "A", "B", "C", "D", "F")
    assert len(posture_score.domain_scores) == 9

    # 7. Verify all reporters output valid non-empty data
    console_out = ConsoleReporter().render(scan_result)
    assert "FINDINGS SUMMARY" in console_out

    json_out = JsonReporter().render(scan_result)
    json_data = json.loads(json_out)
    assert "summary" in json_data
    assert "findings" in json_data

    term_graph_out = TerminalGraphReporter().render(graph, target_path_str=str(tmp_path))
    assert "SentinelScan Architecture Graph" in term_graph_out

    json_graph_out = JsonGraphReporter().render(graph)
    assert '"total_nodes":' in json_graph_out

    term_path_out = TerminalPathReporter().render(attack_paths, target_path_str=str(tmp_path))
    assert "SentinelScan Potential Attack Path Analysis" in term_path_out

    json_path_out = JsonPathReporter().render(attack_paths)
    assert '"total_potential_paths":' in json_path_out

    term_posture_out = TerminalPostureReporter().render(posture_score, target_path_str=str(tmp_path))
    assert "SentinelScan Posture & Remediation Report" in term_posture_out

    json_posture_out = JsonPostureReporter().render(posture_score)
    assert '"overall_score":' in json_posture_out
