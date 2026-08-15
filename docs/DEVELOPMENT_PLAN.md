# SentinelScan - Development Plan & Engineering Workflow

> [!IMPORTANT]
> **SOURCE OF TRUTH**: The repository documentation in `docs/` is the long-term source of truth for SentinelScan's architecture, development process, security principles, testing standards, and roadmap.
>
> Future contributors and AI coding agents MUST consult the relevant documentation in `docs/` before modifying the codebase.

---

## 🎯 1. Project Vision & Development Philosophy

SentinelScan is an open-source, local-first security engineering CLI. It unifies static application security, secret detection, software composition analysis, container/IaC checks, cloud posture assessment, and attack-path risk correlation into a single developer-centric tool.

### Engineering Philosophy
- **Local-First & Privacy Preserving**: The SecretScanner and filesystem assessment modules perform local analysis without transmitting discovered data. Future network-enabled scanners must use explicit authorization, least privilege, safe defaults, and documented network boundaries.

- **Fail-Safe & Isolated**: Individual scanner or detector failures must never terminate an entire scan.
- **Auditable & Deterministic**: Scan outputs are reproducible, machine-readable, and deterministic.
- **Zero Hallucinated Findings**: Only report verified patterns or deterministic rules; do not produce fake findings.

---

## 🔄 2. Milestone Workflow

Every feature, scanner, or architectural addition in SentinelScan follows a strict multi-phase milestone workflow:

```
Plan
 → Review
   → Implement
     → Test
       → Security Review
         → Documentation
           → Git Commit
             → Next Milestone
```

### Phase 1: Planning
- Define the scope, specific detection rules, models, and boundaries in an `implementation_plan.md`.
- Explicitly state security constraints (e.g., secret masking, filesystem safety limits, leak prevention).

### Phase 2: Review & Alignment
- Review architectural implications, model compatibility, and potential false positives before writing code.

### Phase 3: Implementation
- Implement minimal, readable Python code adhering to standard type hints (`typing`), dataclasses, and standard libraries.
- Avoid unnecessary external dependencies.

### Phase 4: Testing
- Write comprehensive unit and integration tests under `tests/unit/` and `tests/integration/`.
- Ensure tests verify positive matches, negative false-positive exclusions, filesystem edge cases, and error isolation.

### Phase 5: Security Review & Leak Verification
- Perform mandatory secret leak prevention tests (`assert raw_secret not in output`).
- Verify raw credential values do not appear in console reports, JSON output, exception tracebacks, or logs.

### Phase 6: Documentation
- Update `docs/`, `README.md`, `IMPLEMENTATION.md`, and `CONTRIBUTING.md`.
- Record milestone progress in `docs/milestones/`.

### Phase 7: Git Commit & Release
- Execute `python -m pytest`, `python -m ruff check .`, and `python -m mypy src/sentinelscan`.
- Commit changes using clean conventional commit messages.

---

## 🤖 3. Instructions for AI Coding Agents

When working on SentinelScan, AI coding agents MUST:
1. **Read Existing Documentation**: Consult `docs/ARCHITECTURE.md`, `docs/SECURITY_PRINCIPLES.md`, `docs/TESTING.md`, and `docs/SCANNER_DEVELOPMENT.md` before making code edits.
2. **Respect Architectural Boundaries**: Integrate new scanners via `BaseScanner` and `ScannerRegistry`. Do not mutate core interfaces unnecessarily.
3. **Enforce Secret Masking**: Ensure raw secret values are masked before constructing `Finding` instances.
4. **Run Full Toolchain Verification**: Always run `pytest`, `ruff check .`, and `mypy src/sentinelscan` to verify changes.
