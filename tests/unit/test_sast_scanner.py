"""Unit tests for SastScanner, AST visitors, strict UTF-8 decoding, and zero-execution safeguards."""

from sentinelscan.models.finding import Category, Confidence, Severity
from sentinelscan.models.result import ScannerExecutionResult, ScannerExecutionStatus, ScanResult
from sentinelscan.models.target import Target
from sentinelscan.reporting.json import JsonReporter
from sentinelscan.scanners.sast_scanner import SastScanner


def test_sast_positive_detections(tmp_path):
    """Verify positive detections for eval, exec, shell=True, os.system, pickle, and weak crypto."""
    code_file = tmp_path / "vulnerable_app.py"
    code_file.write_text(
        "import eval_mod\n"
        "import exec_mod\n"
        "import os\n"
        "import subprocess\n"
        "import pickle\n"
        "import hashlib\n"
        "\n"
        "eval('user_input')\n"
        "exec('user_input')\n"
        "subprocess.run('ls -la', shell=True)\n"
        "os.system('reboot')\n"
        "pickle.load(f)\n"
        "pickle.loads(b'data')\n"
        "hashlib.md5(b'test')\n"
        "hashlib.sha1(b'test')\n"
    )

    scanner = SastScanner()
    target = Target(
        path=code_file,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(code_file.read_bytes()),
    )

    findings = scanner.scan(target)
    rule_ids = [f.rule_id for f in findings]

    assert "SAST-PY-EVAL" in rule_ids
    assert "SAST-PY-EXEC" in rule_ids
    assert "SAST-PY-SHELL-TRUE" in rule_ids
    assert "SAST-PY-OS-SYSTEM" in rule_ids
    assert "SAST-PY-PICKLE-LOAD" in rule_ids
    assert "SAST-PY-PICKLE-LOADS" in rule_ids
    assert "SAST-PY-MD5" in rule_ids
    assert "SAST-PY-SHA1" in rule_ids

    # Verify severity and confidence for specific rules
    eval_f = next(f for f in findings if f.rule_id == "SAST-PY-EVAL")
    assert eval_f.severity == Severity.CRITICAL
    assert eval_f.confidence == Confidence.HIGH
    assert eval_f.category == Category.SAST

    sys_f = next(f for f in findings if f.rule_id == "SAST-PY-OS-SYSTEM")
    assert sys_f.severity == Severity.HIGH
    assert sys_f.confidence == Confidence.MEDIUM


def test_sast_negative_ordinary_subprocess(tmp_path):
    """Verify ordinary subprocess calls without shell=True do NOT produce findings."""
    code_file = tmp_path / "safe_process.py"
    code_file.write_text(
        "import subprocess\n"
        "subprocess.run(['ls', '-la'])\n"
        "subprocess.Popen(['git', 'status'])\n"
        "print('eval() in a string comment')\n"
    )

    scanner = SastScanner()
    target = Target(
        path=code_file,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(code_file.read_bytes()),
    )

    findings = scanner.scan(target)
    # Should produce 0 findings (generic SAST-PY-SUBPROCESS-CALL was removed)
    assert len(findings) == 0


def test_sast_strict_utf8_decoding_error_handling(tmp_path):
    """Verify non-UTF-8 bytes trigger strict decoding error handling and do NOT crash scan."""
    bad_file = tmp_path / "invalid_encoding.py"
    bad_file.write_bytes(b"# \x80\xff\xfe invalid utf8\neval('test')\n")

    scanner = SastScanner()
    target = Target(
        path=bad_file,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(bad_file.read_bytes()),
    )

    findings = scanner.scan(target)
    # File is safely skipped due to UnicodeDecodeError
    assert len(findings) == 0


def test_sast_zero_code_execution_guarantee(tmp_path):
    """Verify target Python code containing self-destruct or exit commands is NEVER executed."""
    malicious_file = tmp_path / "danger.py"
    malicious_file.write_text(
        "import sys\n"
        "raise RuntimeError('IF THIS EXECUTED THE TEST FAILS')\n"
        "eval('test')\n"
    )

    scanner = SastScanner()
    target = Target(
        path=malicious_file,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(malicious_file.read_bytes()),
    )

    # Must complete AST scan cleanly without raising RuntimeError from target code
    findings = scanner.scan(target)
    assert len(findings) == 1
    assert findings[0].rule_id == "SAST-PY-EVAL"


def test_sast_syntax_error_handling(tmp_path):
    """Verify syntax error in target file is caught and skipped safely."""
    bad_syntax = tmp_path / "syntax_error.py"
    bad_syntax.write_text("def unclosed_func(:\n    pass\n")

    scanner = SastScanner()
    target = Target(
        path=bad_syntax,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(bad_syntax.read_bytes()),
    )

    findings = scanner.scan(target)
    assert len(findings) == 0


def test_sast_line_numbers_and_json_serialization(tmp_path):
    """Verify correct line numbers and JSON output serialization."""
    code_file = tmp_path / "multiline.py"
    code_file.write_text(
        "# Line 1\n"
        "# Line 2\n"
        "import os\n"
        "# Line 4\n"
        "os.system('dir')\n"  # Line 5
    )

    scanner = SastScanner()
    target = Target(
        path=code_file,
        is_directory=False,
        is_file=True,
        is_git_repo=False,
        file_count=1,
        total_size_bytes=len(code_file.read_bytes()),
    )

    findings = scanner.scan(target)
    assert len(findings) == 1
    f = findings[0]
    assert f.location is not None
    assert f.location.start_line == 5

    res = ScanResult(
        target=target,
        findings=findings,
        scanner_results=[
            ScannerExecutionResult(scanner_name="sast-scanner", status=ScannerExecutionStatus.SUCCESS)
        ],
    )
    json_out = JsonReporter().render(res)
    assert '"rule_id": "SAST-PY-OS-SYSTEM"' in json_out
    assert '"start_line": 5' in json_out
