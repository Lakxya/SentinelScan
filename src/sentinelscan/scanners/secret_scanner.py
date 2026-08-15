"""Production-oriented Secret and Credential Detection Scanner for SentinelScan."""

import logging
import math
import os
import re
from collections import Counter
from pathlib import Path

from sentinelscan.models.finding import Category, Confidence, Finding, Location, Severity
from sentinelscan.models.target import Target
from sentinelscan.scanners.base import BaseScanner

logger = logging.getLogger("sentinelscan.scanners.secret_scanner")

# Maximum file size to scan (5 MB)
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024

# Directories ignored during recursive filesystem traversal
EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "build",
    "dist",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".sentinelscan",
}

# Known binary extensions skipped automatically
BINARY_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".bmp",
    ".ico",
    ".pdf",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".zip",
    ".tar",
    ".gz",
    ".7z",
    ".pyc",
    ".pyo",
    ".o",
    ".a",
    ".iso",
    ".db",
    ".sqlite",
    ".sqlite3",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp3",
    ".mp4",
    ".avi",
    ".mov",
}

# Common non-secret placeholder values to avoid false positives
COMMON_PLACEHOLDERS = {
    "example",
    "placeholder",
    "your_key_here",
    "your_api_key_here",
    "your_secret_here",
    "your_password_here",
    "xxxxxxxx",
    "xxxxxxxxxxxxxxxx",
    "12345678",
    "1234567890",
    "password",
    "secret",
    "changeme",
    "test",
    "demo",
    "dummy",
    "true",
    "false",
    "null",
    "undefined",
    "none",
}


def calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string in bits per character."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def mask_token(raw_val: str) -> str:
    """Mask a raw token string safely.

    Never returns the raw secret.
    """
    n = len(raw_val)
    if n <= 8:
        return raw_val[0] + "*" * (n - 2) + raw_val[-1] if n > 2 else "****"
    if n <= 16:
        return raw_val[:2] + "*" * (n - 4) + raw_val[-2:]
    return raw_val[:4] + "*" * (n - 8) + raw_val[-4:]


class SecretScanner(BaseScanner):
    """Local-first scanner identifying exposed secrets and credentials safely."""

    def __init__(self) -> None:
        # Pre-compile detector regular expressions for high performance
        self._regex_aws_access_key = re.compile(
            r"\b(?P<key>(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"
        )
        self._regex_aws_secret_key = re.compile(
            r"(?:AWS_SECRET_ACCESS_KEY|AWS_SECRET_KEY|aws_secret_access_key|aws_secret_key|AWS_SECRET|aws_secret)\s*[:=]\s*[\"']?(?P<key>[A-Za-z0-9/+=]{40})[\"']?"
        )
        self._regex_private_key = re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
        )
        self._regex_github_token = re.compile(
            r"\b(?P<tok>(?:ghp_|gho_|ghu_|ghs_|ghr_)[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\b"
        )
        self._regex_jwt = re.compile(
            r"\b(?P<jwt>eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b"
        )
        self._regex_slack_token = re.compile(r"\b(?P<tok>xox[baprs]-[0-9a-zA-Z]{10,48})\b")
        self._regex_stripe_key = re.compile(r"\b(?P<tok>sk_live_[0-9a-zA-Z]{24,32})\b")
        self._regex_google_api_key = re.compile(r"\b(?P<tok>AIzaSy[a-zA-Z0-9_-]{33})\b")
        self._regex_sendgrid_key = re.compile(
            r"\b(?P<tok>SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})\b"
        )
        self._regex_db_conn = re.compile(
            r"(?P<proto>mongodb(?:\+srv)?|postgres|postgresql|mysql|redis)://(?P<user>[^:\s]+):(?P<pass>[^@\s]+)@(?P<host>[^\s/:]+)(?P<rest>[:/\s][^\s]*)?",
            re.IGNORECASE,
        )
        self._regex_generic_secret = re.compile(
            r"(?:API_KEY|SECRET|PASSWORD|TOKEN|ACCESS_KEY|PASSPHRASE|AUTH_KEY|PRIVATE_KEY|DB_PASS)\s*[:=]\s*[\"'](?P<val>[^\"'\s]{8,128})[\"']",
            re.IGNORECASE,
        )

    @property
    def name(self) -> str:
        return "secret-scanner"

    @property
    def category(self) -> Category:
        return Category.SECRET

    @property
    def description(self) -> str:
        return "Detects exposed API tokens, access keys, private keys, connection strings, and high-entropy generic secrets safely."

    def is_available(self, target: Target) -> bool:
        return True

    def scan(self, target: Target) -> list[Finding]:
        """Recursively scan target path for exposed secrets with detector isolation."""
        findings: list[Finding] = []

        if target.is_file:
            self._scan_single_file(target.path, target.path, findings)
            return findings

        # Recursively traverse directory safely
        for root, dirs, files in os.walk(target.path, topdown=True, followlinks=False):
            dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
            root_path = Path(root)

            for fname in files:
                fpath = root_path / fname

                # Skip broken or external symlinks
                if fpath.is_symlink():
                    try:
                        resolved = fpath.resolve()
                        if not resolved.exists() or not str(resolved).startswith(str(target.path)):
                            continue
                    except OSError:
                        continue

                self._scan_single_file(fpath, target.path, findings)

        return findings

    def _scan_single_file(self, fpath: Path, root_path: Path, findings: list[Finding]) -> None:
        """Scan a single file safely handling errors, binary formats, and size limits."""
        if fpath.suffix.lower() in BINARY_EXTENSIONS:
            return

        try:
            stat = fpath.stat()
            if stat.st_size > MAX_FILE_SIZE_BYTES:
                logger.debug("Skipping file exceeding size limit: %s", fpath)
                return

            with open(fpath, "rb") as f:
                header = f.read(1024)
                if b"\x00" in header:
                    return  # Skip binary file
        except (OSError, PermissionError) as e:
            logger.debug("Skipping unreadable file %s: %s", fpath, e)
            return

        # Safely read line by line with encoding fallback
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                for line_idx, line in enumerate(f, 1):
                    self._analyze_line(line, line_idx, fpath, findings)
        except Exception as e:  # noqa: BLE001
            logger.debug("Error reading lines from file %s: %s", fpath, e)

    def _analyze_line(
        self, line: str, line_num: int, fpath: Path, findings: list[Finding]
    ) -> None:
        """Run all detectors against a single line with detector isolation."""
        detectors = [
            self._detect_aws_access_key,
            self._detect_aws_secret_key,
            self._detect_private_key,
            self._detect_github_token,
            self._detect_jwt,
            self._detect_api_key,
            self._detect_database_credential,
            self._detect_generic_secret,
        ]

        for detector in detectors:
            try:
                detector(line, line_num, fpath, findings)
            except Exception as e:  # noqa: BLE001
                # Detector failure isolation: log warning and allow other detectors to continue
                logger.warning(
                    "Detector '%s' failed on file %s line %d: %s",
                    detector.__name__,
                    fpath,
                    line_num,
                    e,
                )

    def _detect_aws_access_key(
        self, line: str, line_num: int, fpath: Path, findings: list[Finding]
    ) -> None:
        for match in self._regex_aws_access_key.finditer(line):
            raw_key = match.group("key")
            masked = mask_token(raw_key)

            findings.append(
                Finding(
                    scanner=self.name,
                    category=self.category,
                    rule_id="SECRET-AWS-ACCESS-KEY",
                    title="Exposed AWS Access Key ID",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    description="An AWS Access Key ID pattern was detected.",
                    impact="Allows unauthorized API authentication to AWS cloud infrastructure.",
                    remediation="Immediately revoke the access key in AWS IAM and generate a new key pair.",
                    location=Location(file_path=fpath, start_line=line_num, end_line=line_num),
                    metadata={
                        "detector": "aws-access-key",
                        "secret_type": "AWS Access Key ID",
                        "masked_value": masked,
                    },
                )
            )

    def _detect_aws_secret_key(
        self, line: str, line_num: int, fpath: Path, findings: list[Finding]
    ) -> None:
        for match in self._regex_aws_secret_key.finditer(line):
            raw_key = match.group("key")
            if raw_key.lower() in COMMON_PLACEHOLDERS:
                continue

            masked = mask_token(raw_key)
            findings.append(
                Finding(
                    scanner=self.name,
                    category=self.category,
                    rule_id="SECRET-AWS-SECRET-KEY",
                    title="Exposed AWS Secret Access Key",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    description="An AWS Secret Access Key variable assignment pattern was detected.",
                    impact="Grants full programmatic authentication to AWS cloud services when paired with an Access Key ID.",
                    remediation="Revoke key pair in AWS IAM and rotate credentials immediately.",
                    location=Location(file_path=fpath, start_line=line_num, end_line=line_num),
                    metadata={
                        "detector": "aws-secret-key",
                        "secret_type": "AWS Secret Access Key",
                        "masked_value": masked,
                    },
                )
            )

    def _detect_private_key(
        self, line: str, line_num: int, fpath: Path, findings: list[Finding]
    ) -> None:
        if self._regex_private_key.search(line):
            # Raw PEM content is NEVER captured or included
            findings.append(
                Finding(
                    scanner=self.name,
                    category=self.category,
                    rule_id="SECRET-PRIVATE-KEY",
                    title="Exposed Private Key Block",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    description="A PEM or OpenSSH private key header block was detected.",
                    impact="Allows unauthorized cryptographic authentication or decrypting sensitive communication.",
                    remediation="Revoke private key, remove key file, and re-issue a new key pair.",
                    location=Location(file_path=fpath, start_line=line_num, end_line=line_num),
                    metadata={
                        "detector": "private-key",
                        "secret_type": "private_key",
                        "masked_value": "[PRIVATE KEY REDACTED]",
                    },
                )
            )

    def _detect_github_token(
        self, line: str, line_num: int, fpath: Path, findings: list[Finding]
    ) -> None:
        for match in self._regex_github_token.finditer(line):
            raw_tok = match.group("tok")
            masked = mask_token(raw_tok)

            findings.append(
                Finding(
                    scanner=self.name,
                    category=self.category,
                    rule_id="SECRET-GITHUB-TOKEN",
                    title="Exposed GitHub Personal Access Token",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    description="A GitHub Personal Access Token or OAuth token pattern was detected.",
                    impact="Grants access to GitHub repositories, API actions, or organization resources.",
                    remediation="Revoke token immediately in GitHub developer settings.",
                    location=Location(file_path=fpath, start_line=line_num, end_line=line_num),
                    metadata={
                        "detector": "github-token",
                        "secret_type": "GitHub Access Token",
                        "masked_value": masked,
                    },
                )
            )

    def _detect_jwt(
        self, line: str, line_num: int, fpath: Path, findings: list[Finding]
    ) -> None:
        for match in self._regex_jwt.finditer(line):
            raw_jwt = match.group("jwt")
            masked = mask_token(raw_jwt)

            findings.append(
                Finding(
                    scanner=self.name,
                    category=self.category,
                    rule_id="SECRET-JWT",
                    title="Exposed JSON Web Token (JWT)",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description="A signed JSON Web Token pattern was detected.",
                    impact="May allow unauthorized session hijacking or API access until token expiration.",
                    remediation="Invalidate active token session and avoid committing hardcoded JWT tokens.",
                    location=Location(file_path=fpath, start_line=line_num, end_line=line_num),
                    metadata={
                        "detector": "jwt",
                        "secret_type": "JSON Web Token",
                        "masked_value": masked,
                    },
                )
            )

    def _detect_api_key(
        self, line: str, line_num: int, fpath: Path, findings: list[Finding]
    ) -> None:
        patterns = [
            (self._regex_slack_token, "Slack Token"),
            (self._regex_stripe_key, "Stripe Secret Key"),
            (self._regex_google_api_key, "Google API Key"),
            (self._regex_sendgrid_key, "SendGrid API Key"),
        ]

        for regex, service_name in patterns:
            for match in regex.finditer(line):
                raw_tok = match.group("tok")
                masked = mask_token(raw_tok)

                findings.append(
                    Finding(
                        scanner=self.name,
                        category=self.category,
                        rule_id="SECRET-API-KEY",
                        title=f"Exposed API Key ({service_name})",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description=f"A service API key pattern for {service_name} was detected.",
                        impact="May allow unauthorized API actions and quota consumption.",
                        remediation="Revoke the API key in the provider admin console.",
                        location=Location(file_path=fpath, start_line=line_num, end_line=line_num),
                        metadata={
                            "detector": "api-key",
                            "secret_type": service_name,
                            "masked_value": masked,
                        },
                    )
                )

    def _detect_database_credential(
        self, line: str, line_num: int, fpath: Path, findings: list[Finding]
    ) -> None:
        for match in self._regex_db_conn.finditer(line):
            proto = match.group("proto")
            user = match.group("user")
            raw_pass = match.group("pass")
            host = match.group("host")
            rest = match.group("rest") or ""

            if raw_pass.lower() in COMMON_PLACEHOLDERS:
                continue

            # Completely replace raw password with [REDACTED] in masked connection string
            masked_url = f"{proto}://{user}:[REDACTED]@{host}{rest}"

            findings.append(
                Finding(
                    scanner=self.name,
                    category=self.category,
                    rule_id="SECRET-DATABASE-CREDENTIAL",
                    title="Exposed Database Connection Credentials",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    description="A database connection URL containing embedded password credentials was detected.",
                    impact="Direct access to database instances, potential data breach or manipulation.",
                    remediation="Remove embedded password credentials and load via environment variables or secret managers.",
                    location=Location(file_path=fpath, start_line=line_num, end_line=line_num),
                    metadata={
                        "detector": "database-credential",
                        "secret_type": "Database Connection String",
                        "masked_value": masked_url,
                    },
                )
            )

    def _detect_generic_secret(
        self, line: str, line_num: int, fpath: Path, findings: list[Finding]
    ) -> None:
        for match in self._regex_generic_secret.finditer(line):
            raw_val = match.group("val")
            val_lower = raw_val.lower()

            if val_lower in COMMON_PLACEHOLDERS or any(p in val_lower for p in ("example", "placeholder", "your_")):
                continue

            entropy = calculate_entropy(raw_val)
            # Require minimum entropy threshold (>= 3.6 bits/char) to avoid reporting plain strings
            if entropy < 3.6:
                continue

            confidence = Confidence.MEDIUM if entropy >= 4.2 else Confidence.LOW
            masked = mask_token(raw_val)

            findings.append(
                Finding(
                    scanner=self.name,
                    category=self.category,
                    rule_id="SECRET-GENERIC",
                    title="Exposed Generic Secret Assignment",
                    severity=Severity.MEDIUM,
                    confidence=confidence,
                    description="A suspicious secret variable assignment containing a high-entropy string was detected.",
                    impact="Potential exposure of sensitive credentials or private tokens.",
                    remediation="Verify if the value is a secret and move to a secure secret management store.",
                    location=Location(file_path=fpath, start_line=line_num, end_line=line_num),
                    metadata={
                        "detector": "generic-secret",
                        "secret_type": "Generic Secret",
                        "masked_value": masked,
                        "entropy": round(entropy, 2),
                    },
                )
            )
