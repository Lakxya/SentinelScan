"""Structured JSON reporter for SentinelScan results."""

import json
from typing import Any

from sentinelscan.models.result import ScanResult
from sentinelscan.reporting.base import BaseReporter

# Descriptive metadata fields that should not be redacted by dictionary key matching
ALLOWED_METADATA_KEYS = {"secret_type", "detector", "masked_value"}

# Key substrings triggering automatic redaction in arbitrary metadata dictionaries
SENSITIVE_KEY_SUBSTRINGS = {"secret", "password", "token", "api_key", "apikey", "private_key", "credential"}


def sanitize_sensitive_data(obj: Any) -> Any:
    """Recursively redact potentially sensitive strings in dictionaries or metadata."""
    if isinstance(obj, dict):
        sanitized = {}
        for key, value in obj.items():
            key_lower = str(key).lower()
            if key_lower not in ALLOWED_METADATA_KEYS and any(s in key_lower for s in SENSITIVE_KEY_SUBSTRINGS):
                sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = sanitize_sensitive_data(value)
        return sanitized
    elif isinstance(obj, list):
        return [sanitize_sensitive_data(item) for item in obj]
    return obj


class JsonReporter(BaseReporter):
    """Formats scan output as structured JSON suitable for machine consumption and CI/CD."""

    def render(self, result: ScanResult) -> str:
        """Render ScanResult as formatted JSON string with sensitive value redaction."""
        raw_dict = result.to_dict()
        sanitized_dict = sanitize_sensitive_data(raw_dict)
        return json.dumps(sanitized_dict, indent=2)
