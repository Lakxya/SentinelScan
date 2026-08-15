"""Static Application Security Testing (SAST) Scanner for Python using AST parsing."""

import ast
import logging
import os
from pathlib import Path

from sentinelscan.models.finding import Category, Confidence, Finding, Location, Severity
from sentinelscan.models.target import Target
from sentinelscan.scanners.base import BaseScanner

logger = logging.getLogger("sentinelscan.scanners.sast_scanner")

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


def _get_call_func_name(node: ast.Call) -> str | None:
    """Extract full callable function name from an ast.Call node (e.g., 'eval', 'os.system')."""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    elif isinstance(func, ast.Attribute):
        if isinstance(func.value, ast.Name):
            return f"{func.value.id}.{func.attr}"
        elif isinstance(func.value, ast.Attribute):
            val_name = _get_attribute_name(func.value)
            return f"{val_name}.{func.attr}" if val_name else func.attr
    return None


def _get_attribute_name(node: ast.Attribute) -> str | None:
    """Recursively reconstruct attribute chain (e.g., 'os.path')."""
    if isinstance(node.value, ast.Name):
        return f"{node.value.id}.{node.attr}"
    elif isinstance(node.value, ast.Attribute):
        parent = _get_attribute_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _has_shell_true_keyword(node: ast.Call) -> bool:
    """Check if an ast.Call node contains explicit keyword argument 'shell=True'."""
    for kw in node.keywords:
        if kw.arg == "shell":
            val = kw.value
            if (isinstance(val, ast.Constant) and val.value is True) or (
                isinstance(val, ast.NameConstant) and val.value is True
            ):
                return True
    return False


class PythonSecurityASTVisitor(ast.NodeVisitor):
    """AST Node Visitor detecting high-risk security patterns in Python source code."""

    def __init__(self, fpath: Path) -> None:
        self.fpath = fpath
        self.findings: list[Finding] = []

    def visit_Call(self, node: ast.Call) -> None:
        """Inspect function call AST nodes."""
        func_name = _get_call_func_name(node)
        line_num = getattr(node, "lineno", 1)

        if func_name:
            self._check_dynamic_execution(func_name, line_num)
            self._check_command_execution(func_name, node, line_num)
            self._check_unsafe_deserialization(func_name, line_num)
            self._check_weak_cryptography(func_name, line_num)

        self.generic_visit(node)

    def _check_dynamic_execution(self, func_name: str, line_num: int) -> None:
        if func_name == "eval":
            self.findings.append(
                Finding(
                    scanner="sast-scanner",
                    category=Category.SAST,
                    rule_id="SAST-PY-EVAL",
                    title="Dynamic Code Execution via eval()",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    description="An eval() call was detected. Dynamic code evaluation can lead to arbitrary code execution if untrusted input is evaluated.",
                    impact="Potential Remote Code Execution (RCE) vulnerability.",
                    remediation="Avoid eval(). Parse data using structured formats like json.loads() or ast.literal_eval() if literal data parsing is required.",
                    location=Location(file_path=self.fpath, start_line=line_num, end_line=line_num),
                    metadata={"function": "eval"},
                )
            )
        elif func_name == "exec":
            self.findings.append(
                Finding(
                    scanner="sast-scanner",
                    category=Category.SAST,
                    rule_id="SAST-PY-EXEC",
                    title="Dynamic Code Execution via exec()",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    description="An exec() call was detected. Dynamic code execution executes string data as bytecode, posing severe RCE risk.",
                    impact="Arbitrary Python code execution within the process context.",
                    remediation="Refactor code to avoid exec(). Use standard control structures and explicit function calls.",
                    location=Location(file_path=self.fpath, start_line=line_num, end_line=line_num),
                    metadata={"function": "exec"},
                )
            )

    def _check_command_execution(self, func_name: str, node: ast.Call, line_num: int) -> None:
        if func_name.startswith("subprocess."):
            if _has_shell_true_keyword(node):
                self.findings.append(
                    Finding(
                        scanner="sast-scanner",
                        category=Category.SAST,
                        rule_id="SAST-PY-SHELL-TRUE",
                        title="Shell Command Execution with shell=True",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description="A subprocess call with shell=True was detected. Shell execution interprets command strings through system shell (/bin/sh or cmd.exe).",
                        impact="High risk of command injection if unescaped dynamic arguments are passed to the shell.",
                        remediation="Set shell=False and pass command arguments as a list of strings (e.g., subprocess.run(['cmd', 'arg'])).",
                        location=Location(file_path=self.fpath, start_line=line_num, end_line=line_num),
                        metadata={"function": func_name, "shell_true": True},
                    )
                )
        elif func_name == "os.system":
            self.findings.append(
                Finding(
                    scanner="sast-scanner",
                    category=Category.SAST,
                    rule_id="SAST-PY-OS-SYSTEM",
                    title="Command Execution via os.system()",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    description="An os.system() call was detected. os.system() invokes a system shell; command injection risk depends on whether untrusted input reaches the command string.",
                    impact="Command injection risk if untrusted data is concatenated into the command string.",
                    remediation="Replace os.system() with subprocess.run() passing arguments as an array with shell=False.",
                    location=Location(file_path=self.fpath, start_line=line_num, end_line=line_num),
                    metadata={"function": "os.system"},
                )
            )

    def _check_unsafe_deserialization(self, func_name: str, line_num: int) -> None:
        if func_name == "pickle.load":
            self.findings.append(
                Finding(
                    scanner="sast-scanner",
                    category=Category.SAST,
                    rule_id="SAST-PY-PICKLE-LOAD",
                    title="Unsafe Deserialization via pickle.load()",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description="A pickle.load() call was detected. Python pickle deserialization is unsafe for untrusted input and can trigger arbitrary code execution during unpickling.",
                    impact="Remote Code Execution (RCE) via malicious pickled payload object instantiation.",
                    remediation="Use safe serialization formats like JSON, Protocol Buffers, or msgpack.",
                    location=Location(file_path=self.fpath, start_line=line_num, end_line=line_num),
                    metadata={"function": "pickle.load"},
                )
            )
        elif func_name == "pickle.loads":
            self.findings.append(
                Finding(
                    scanner="sast-scanner",
                    category=Category.SAST,
                    rule_id="SAST-PY-PICKLE-LOADS",
                    title="Unsafe Deserialization via pickle.loads()",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description="A pickle.loads() call was detected. Deserializing raw byte strings using pickle is insecure.",
                    impact="Remote Code Execution (RCE) during byte string unpickling.",
                    remediation="Replace pickle.loads() with safe serialization standards such as json.loads().",
                    location=Location(file_path=self.fpath, start_line=line_num, end_line=line_num),
                    metadata={"function": "pickle.loads"},
                )
            )

    def _check_weak_cryptography(self, func_name: str, line_num: int) -> None:
        if func_name == "hashlib.md5":
            self.findings.append(
                Finding(
                    scanner="sast-scanner",
                    category=Category.SAST,
                    rule_id="SAST-PY-MD5",
                    title="Weak Cryptographic Hash Function (MD5)",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    description="Use of hashlib.md5() was detected. MD5 is cryptographically broken and vulnerable to collision attacks.",
                    impact="Collision vulnerabilities if used for security authentication or integrity checks.",
                    remediation="Use secure hash algorithms such as SHA-256 or SHA-3 (e.g., hashlib.sha256()).",
                    location=Location(file_path=self.fpath, start_line=line_num, end_line=line_num),
                    metadata={"function": "hashlib.md5"},
                )
            )
        elif func_name == "hashlib.sha1":
            self.findings.append(
                Finding(
                    scanner="sast-scanner",
                    category=Category.SAST,
                    rule_id="SAST-PY-SHA1",
                    title="Weak Cryptographic Hash Function (SHA-1)",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    description="Use of hashlib.sha1() was detected. SHA-1 is cryptographically weak against collision attacks.",
                    impact="Collision risks in digital signatures or certificate validation.",
                    remediation="Migrate to modern cryptographic hash functions like SHA-256 or SHA-512.",
                    location=Location(file_path=self.fpath, start_line=line_num, end_line=line_num),
                    metadata={"function": "hashlib.sha1"},
                )
            )


class SastScanner(BaseScanner):
    """Static Application Security Testing scanner analyzing Python source code via AST."""

    @property
    def name(self) -> str:
        return "sast-scanner"

    @property
    def category(self) -> Category:
        return Category.SAST

    @property
    def description(self) -> str:
        return "Static application security testing analyzer identifying unsafe Python code execution, shell command injection, weak crypto, and insecure deserialization using Python AST."

    def is_available(self, target: Target) -> bool:
        return True

    def scan(self, target: Target) -> list[Finding]:
        """Recursively scan Python files in target path using AST inspection."""
        findings: list[Finding] = []

        if target.is_file:
            if target.path.suffix.lower() in (".py", ".pyw"):
                self._scan_python_file(target.path, findings)
            return findings

        # Recursively traverse directory safely
        for root, dirs, files in os.walk(target.path, topdown=True, followlinks=False):
            dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
            root_path = Path(root)

            for fname in files:
                fpath = root_path / fname
                if fpath.suffix.lower() not in (".py", ".pyw"):
                    continue

                # Skip broken or external symlinks
                if fpath.is_symlink():
                    try:
                        resolved = fpath.resolve()
                        if not resolved.exists() or not str(resolved).startswith(str(target.path)):
                            continue
                    except OSError:
                        continue

                self._scan_python_file(fpath, findings)

        return findings

    def _scan_python_file(self, fpath: Path, findings: list[Finding]) -> None:
        """Parse and analyze a single Python source file using AST without executing code."""
        try:
            stat = fpath.stat()
            if stat.st_size > MAX_FILE_SIZE_BYTES:
                logger.debug("Skipping Python file exceeding size limit: %s", fpath)
                return

            with open(fpath, "rb") as f:
                header = f.read(1024)
                if b"\x00" in header:
                    return  # Skip binary file
        except (OSError, PermissionError) as e:
            logger.debug("Skipping unreadable file %s: %s", fpath, e)
            return

        # Strict UTF-8 decoding strategy: do NOT use errors="ignore"
        try:
            with open(fpath, "r", encoding="utf-8", errors="strict") as f:
                source_code = f.read()
        except UnicodeDecodeError as e:
            logger.debug("Strict UTF-8 decoding failed for file %s: %s", fpath, e)
            return
        except Exception as e:  # noqa: BLE001
            logger.debug("Failed to read file %s: %s", fpath, e)
            return

        # Parse AST without code execution, import, or evaluation
        try:
            tree = ast.parse(source_code, filename=str(fpath))
        except SyntaxError as e:
            logger.debug("Syntax error in Python file %s line %s: %s", fpath, e.lineno, e.msg)
            return
        except Exception as e:  # noqa: BLE001
            logger.debug("Failed to parse AST for file %s: %s", fpath, e)
            return

        visitor = PythonSecurityASTVisitor(fpath)
        try:
            visitor.visit(tree)
            findings.extend(visitor.findings)
        except Exception as e:  # noqa: BLE001
            logger.warning("AST visitor encountered error on file %s: %s", fpath, e)
