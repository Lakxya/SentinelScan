"""Target validation and basic project discovery engine."""

import os
from pathlib import Path

from sentinelscan.core.exceptions import InvalidTargetError, TargetNotFoundError
from sentinelscan.models.target import Target

# Folders to ignore during file count and indicator scan
IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    "node_modules",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}


class ProjectDiscoverer:
    """Discovers project structure, technology indicators, and metadata safely."""

    def discover(self, target_path_str: str | Path) -> Target:
        """Validate and discover basic project information for a given target path.

        Args:
            target_path_str: Path string or Path object pointing to target directory or file.

        Returns:
            Target: Populated target model containing metadata and detected indicators.

        Raises:
            TargetNotFoundError: If target path does not exist.
            InvalidTargetError: If target path is inaccessible or invalid.
        """
        path = Path(target_path_str).expanduser().resolve()

        if not path.exists():
            raise TargetNotFoundError(f"Target path does not exist: {path}")

        try:
            is_dir = path.is_dir()
            is_file = path.is_file()
        except PermissionError as e:
            raise InvalidTargetError(f"Permission denied accessing target path: {path}") from e

        if not (is_dir or is_file):
            raise InvalidTargetError(f"Target path must be a file or directory: {path}")

        is_git_repo = False
        file_count = 0
        total_size_bytes = 0
        indicators: set[str] = set()

        if is_file:
            file_count = 1
            try:
                total_size_bytes = path.stat().st_size
            except OSError:
                total_size_bytes = 0
            self._inspect_file_indicator(path, indicators)
            if path.parent.joinpath(".git").exists():
                is_git_repo = True
        else:
            is_git_repo = path.joinpath(".git").exists()
            file_count, total_size_bytes, indicators = self._scan_directory(path)

        return Target(
            path=path,
            is_directory=is_dir,
            is_file=is_file,
            is_git_repo=is_git_repo,
            file_count=file_count,
            total_size_bytes=total_size_bytes,
            detected_indicators=sorted(indicators),
        )

    def _scan_directory(self, root: Path) -> tuple[int, int, set[str]]:
        """Safely traverse directory counting files and detecting technology indicators."""
        file_count = 0
        total_bytes = 0
        indicators: set[str] = set()

        for dirpath, dirnames, filenames in os.walk(root, topdown=True):
            # Prune ignored directories in place
            dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]

            current_dir = Path(dirpath)
            for fname in filenames:
                file_count += 1
                fpath = current_dir / fname
                try:
                    total_bytes += fpath.stat().st_size
                except OSError:
                    pass
                self._inspect_file_indicator(fpath, indicators)

        return file_count, total_bytes, indicators

    def _inspect_file_indicator(self, fpath: Path, indicators: set[str]) -> None:
        """Categorize file extensions or names into technology domain indicators."""
        name_lower = fpath.name.lower()
        ext_lower = fpath.suffix.lower()

        if name_lower in ("dockerfile", "docker-compose.yml", "docker-compose.yaml"):
            indicators.add("docker")
        elif ext_lower in (".tf", ".tfvars") or name_lower.endswith(".tf.json"):
            indicators.add("iac-terraform")
        elif name_lower in ("pyproject.toml", "requirements.txt", "setup.py", "pipfile"):
            indicators.add("python")
        elif name_lower in ("package.json", "pnpm-lock.yaml", "yarn.lock"):
            indicators.add("javascript")
        elif name_lower in ("template.yaml", "cdk.json") or fpath.parent.name == ".aws":
            indicators.add("aws-cloud")
        elif ext_lower in (".yaml", ".yml") and (
            "k8s" in str(fpath).lower() or "manifest" in str(fpath).lower()
        ):
            indicators.add("kubernetes")

