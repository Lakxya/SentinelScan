"""Logging setup and utility functions for SentinelScan."""

import logging
import sys


def setup_logging(verbose: bool = False) -> None:
    """Configure structured logging for SentinelScan CLI and core engine.

    Args:
        verbose: Enable DEBUG level logging if True, otherwise INFO level.
    """
    level = logging.DEBUG if verbose else logging.INFO
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(formatter)
    handler.setLevel(level)

    root_logger = logging.getLogger("sentinelscan")
    root_logger.setLevel(level)
    # Avoid duplicate handlers if setup_logging is called multiple times
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
