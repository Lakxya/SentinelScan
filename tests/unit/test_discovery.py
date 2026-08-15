"""Unit tests for ProjectDiscoverer target validation and technology discovery."""

import pytest

from sentinelscan.core.discovery import ProjectDiscoverer
from sentinelscan.core.exceptions import TargetNotFoundError


def test_discover_current_directory():
    """Verify discovery of the project root directory."""
    discoverer = ProjectDiscoverer()
    target = discoverer.discover(".")

    assert target.is_directory is True
    assert target.is_file is False
    assert target.file_count > 0
    assert target.total_size_bytes >= 0
    assert isinstance(target.detected_indicators, list)


def test_discover_non_existent_path_raises_error():
    """Verify non-existent directory path raises TargetNotFoundError."""
    discoverer = ProjectDiscoverer()
    with pytest.raises(TargetNotFoundError):
        discoverer.discover("./path_that_definitely_does_not_exist_xyz123")


def test_discover_file_target(tmp_path):
    """Verify discovery of a single file target."""
    sample_file = tmp_path / "Dockerfile"
    sample_file.write_text("FROM alpine:latest")

    discoverer = ProjectDiscoverer()
    target = discoverer.discover(sample_file)

    assert target.is_file is True
    assert target.is_directory is False
    assert target.file_count == 1
    assert "docker" in target.detected_indicators


def test_discover_detects_indicators(tmp_path):
    """Verify detection of various tech indicators (Python, Docker, Terraform)."""
    (tmp_path / "pyproject.toml").write_text("[project]\nname='test'")
    (tmp_path / "main.tf").write_text("provider \"aws\" {}")

    discoverer = ProjectDiscoverer()
    target = discoverer.discover(tmp_path)

    assert "python" in target.detected_indicators
    assert "iac-terraform" in target.detected_indicators
