"""Target model representing a validated scan target."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Target:
    """Scan target metadata discovered during initial project analysis."""

    path: Path
    is_directory: bool
    is_file: bool
    is_git_repo: bool
    file_count: int
    total_size_bytes: int
    detected_indicators: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert target to a JSON-serializable dictionary."""
        return {
            "path": str(self.path.resolve()),
            "is_directory": self.is_directory,
            "is_file": self.is_file,
            "is_git_repo": self.is_git_repo,
            "file_count": self.file_count,
            "total_size_bytes": self.total_size_bytes,
            "detected_indicators": self.detected_indicators,
            "metadata": self.metadata,
        }
