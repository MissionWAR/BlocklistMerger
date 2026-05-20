---
phase: 04
slug: runtime-scaling-reproducibility
status: draft
nyquist_compliant: true
wave_0_complete: false
created: 2026-05-18
---

# Phase 04 - Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest `>=9.0.3` plus Ruff `>=0.15.10` |
| **Config file** | `pyproject.toml` |
| **Quick run command** | `python -m pytest tests/test_downloader.py tests/test_pipeline.py tests/test_compiler.py tests/test_release_validator.py tests/test_ci_workflow.py -x` |
| **Full suite command** | `python -m pytest` and `python -m ruff check .` |
| **Estimated runtime** | Unknown locally; CI is the authoritative runner until local Python is repaired. |

---

## Sampling Rate

- **After every task commit:** Run the narrow pytest command for the touched module.
- **After every plan wave:** Run `python -m pytest tests/test_downloader.py tests/test_pipeline.py tests/test_compiler.py tests/test_release_validator.py tests/test_ci_workflow.py -x`.
- **Before `$gsd-verify-work`:** `python -m pytest` and `python -m ruff check .` must pass.
- **Max feedback latency:** One focused pytest command per task, full suite per wave.

---

## Per-Requirement Verification Map

| Requirement | Behavior | Test Type | Automated Command | File Exists | Status |
|-------------|----------|-----------|-------------------|-------------|--------|
| RUN-01 | Successful 2xx downloads stream response chunks into a temporary cache-side file, promote only after complete success, and leave prior cache/output files intact on partial failure. | async unit | `python -m pytest tests/test_downloader.py -x` | Yes | pending |
| RUN-01 | 304, HTTP error, timeout, and exception fallback paths copy cached content through bounded helpers instead of full-file reads. | async unit | `python -m pytest tests/test_downloader.py -x` | Yes | pending |
| RUN-02 | Bounded cleaner/pipeline processing avoids returning full cleaned `list[str]` payloads across worker boundaries while preserving sorted file/chunk order. | pipeline integration | `python -m pytest tests/test_pipeline.py tests/test_integration_pipeline.py -x` | Yes | pending |
| RUN-03 | Compiler removes unused allocation waste without changing output ordering, pruning stats, or semantic whitelist behavior. | compiler unit | `python -m pytest tests/test_compiler.py tests/test_rule_semantics.py -x` | Yes | pending |
| RUN-03 | `reports/pipeline-stats.json` exposes inspect-only `runtime_profile` fields for durations, byte sizes, worker count, cardinalities, and best-effort memory. | report schema | `python -m pytest tests/test_pipeline.py tests/test_release_validator.py -x` | Yes | pending |
| RUN-04 | Scheduled release installation uses committed pip constraints, and dependency cache invalidation includes the constraints file path. | static workflow | `python -m pytest tests/test_ci_workflow.py -x` | Yes | pending |
| RUN-05 | CI audits Python 3.13 and 3.14 compatibility separately from scheduled release publishing, without lowering `requires-python`. | static workflow | `python -m pytest tests/test_ci_workflow.py -x` | Yes | pending |

---

## Wave 0 Requirements

- [ ] `tests/test_downloader.py` - streamed success path, chunked cache fallback copies, atomic promotion order, and failed-stream cleanup coverage without real network calls.
- [ ] `tests/test_pipeline.py` - bounded cleaning/spooling behavior, deterministic ordered consumption, runtime profile schema, and cleanup after success/failure.
- [ ] `tests/test_compiler.py` - no-output-change regression for compiler allocation cleanup and runtime cardinality counters.
- [ ] `tests/test_release_validator.py` - validator compatibility with `runtime_profile` as inspect-only report data.
- [ ] `tests/test_ci_workflow.py` - constraints install, setup-python cache dependency path, and Python 3.13/3.14 audit matrix assertions.
- [ ] `constraints/release.txt` or equivalent committed constraints artifact - reproducible release dependency pins generated from `pyproject.toml`.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Initial constraints refresh workflow | RUN-04 | Constraint generation depends on an available Python/pip environment; local aliases are currently broken in this sandbox. | Generate or refresh constraints in a working CPython environment, then inspect the diff to confirm only expected direct/transitive pins changed. |
| Python 3.13 compatibility interpretation | RUN-05 | CI can provide evidence before the project decides whether to lower `requires-python`; the decision itself is explicitly deferred. | Review the compatibility audit result after implementation and keep `requires-python = ">=3.14"` unchanged in Phase 04. |
| Runtime metric baseline | RUN-03 | Phase 04 records metrics but intentionally avoids thresholds until real scheduled-run history exists. | Inspect the first `runtime_profile` artifact from GitHub Actions and note suspicious values without adding release blockers. |

---

## Validation Sign-Off

- [x] All phase requirements have automated verification targets or Wave 0 dependencies.
- [x] Sampling continuity is defined for task commits, waves, and phase verification.
- [x] Wave 0 covers missing downloader, pipeline, compiler, report, workflow, and constraints coverage.
- [x] No watch-mode commands are required.
- [x] Feedback latency is bounded by focused pytest commands.
- [x] `nyquist_compliant: true` set in frontmatter.

**Approval:** pending execution
