---
phase: 04-runtime-scaling-reproducibility
verified: 2026-05-20T10:59:53Z
status: passed
score: "5/5 must-haves verified"
overrides_applied: 0
human_verification:
  - test: "Run or inspect one workflow_dispatch build on GitHub Actions after merge."
    expected: "build_validate installs with constraints, writes reports/pipeline-stats.json, appends the compact runtime profile summary, gates publish on validation success, and python_compatibility_audit runs read-only on Python 3.13 and 3.14."
    why_human: "Static tests and YAML inspection verify workflow wiring, but actual runner behavior, artifact creation, pip cache behavior, and token permissions are external GitHub Actions integration."
    result: "passed via workflow_dispatch run 26160556184"
---

# Phase 4: Runtime Scaling & Reproducibility Verification Report

**Phase Goal:** Maintainer can run the pinned-safe pipeline with lower memory/runtime risk and auditable release environments.  
**Verified:** 2026-05-20T10:59:53Z  
**Status:** passed  
**Re-verification:** No - initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|---|---|---|
| 1 | Downloader handles large responses through bounded streaming and atomic replacement instead of full-response buffering. | VERIFIED | `scripts/downloader.py:56` defines `DOWNLOAD_CHUNK_SIZE`; `_stream_response_to_file()` streams `response.content.iter_chunked()` into a temp file and replaces the final cache at `scripts/downloader.py:300-314`; `fetch_url()` copies completed cache to raw output before state mutation at `scripts/downloader.py:551-563`. Guard checks found no `response.read()` path. |
| 2 | Cleaner, pipeline, and compiler large-run paths avoid unnecessary full-list materialization or unused allocations where practical. | VERIFIED | Worker cleaning writes per-source spool files and returns `CleanWorkerResult` metadata at `scripts/pipeline.py:181-215`; `ProcessPoolExecutor` remains at `scripts/pipeline.py:224`; sorted source-index consumption streams spool lines into `compile_rules()` at `scripts/pipeline.py:403-429`. Compiler no longer contains `abp_blocking_domains`; `_build_coverage_lookups()` returns only wildcard keys at `scripts/compiler.py:699-701`. |
| 3 | Maintainer can inspect runtime-size metrics for large compiler and pipeline runs. | VERIFIED | `process_files_with_profile()` produces `worker_count`, `stage_durations_seconds`, `byte_sizes`, `compiler_cardinalities`, and `memory` at `scripts/pipeline.py:456-468`; `save_stats_json()` writes schema 2 plus top-level `runtime_profile` at `scripts/pipeline.py:528-557`; validator accepts schema 2 at `scripts/release_validator.py:37`. |
| 4 | Scheduled release dependencies are reproducible through a lockfile or constraints file. | VERIFIED | `constraints/release-py314.txt` exists with exact `==` pins; workflow cache dependency path includes it at `.github/workflows/update.yml:37-39`; release install uses `python -m pip install -q -c constraints/release-py314.txt ".[dev]"` at `.github/workflows/update.yml:41-42`. |
| 5 | Maintainer can audit Python 3.13 and 3.14 compatibility in CI before changing the declared Python requirement. | VERIFIED | `pyproject.toml:5` keeps `requires-python = ">=3.14"` and `pyproject.toml:32` keeps Ruff target `py314`; workflow defines read-only `python_compatibility_audit` with matrix `["3.13", "3.14"]` at `.github/workflows/update.yml:180-188`; audit install uses `--ignore-requires-python` with constraints at `.github/workflows/update.yml:205-206`. |

**Score:** 5/5 roadmap truths verified. Plan frontmatter must-haves for 04-01 through 04-04 were also checked against implementation, tests, and workflow wiring.

### Required Artifacts

| Artifact | Expected | Status | Details |
|---|---|---|---|
| `scripts/downloader.py` | Bounded HTTP streaming, bounded cache copies, atomic cache/raw promotion, content identity metrics | VERIFIED | Exists and substantive. Contains chunk constant, temp cleanup, `_copy_file_bounded()`, `_stream_response_to_file()`, bounded `_content_identity()`, and success/fallback wiring. |
| `tests/test_downloader.py` | RUN-01 regression tests | VERIFIED | Covers D-01 through D-05: streamed success, no `response.read()`, failed-stream cleanup, fallback copies, and no source-size/content-type gate. |
| `scripts/pipeline.py` | Ordered bounded cleaning worker/spool pipeline plus runtime profile report data | VERIFIED | Exists and substantive. Uses `CleanWorkerResult`, `TemporaryDirectory`, `ProcessPoolExecutor`, sorted input files, spool streaming, and schema 2 runtime profile output. |
| `tests/test_pipeline.py` | RUN-02 and runtime profile regression tests | VERIFIED | Covers non-list worker result shape, sorted source order independent of completion order, spool cleanup, `process_files_with_profile()`, and JSON `runtime_profile`. |
| `scripts/compiler.py` | Allocation cleanup and compiler cardinality counters | VERIFIED | No `abp_blocking_domains` symbol remains. `CompileStats` has cardinality fields populated by `_record_compiler_cardinalities()`. |
| `tests/test_compiler.py` | Compiler no-output-change and cardinality tests | VERIFIED | Mixed semantic regression asserts output/counters and new cardinality values. |
| `scripts/release_validator.py` | Pipeline stats schema 2 compatibility without runtime gates | VERIFIED | `PIPELINE_STATS_SCHEMA_VERSION = 2`; no runtime/memory/cardinality thresholds are consumed by validation. |
| `tests/test_release_validator.py` | Runtime profile inspect-only tests | VERIFIED | `test_runtime_profile_is_inspect_only_for_release_validation()` mutates extreme duration/memory values and asserts no runtime findings. |
| `constraints/release-py314.txt` | Committed pip-native release constraints | VERIFIED | Exists with exact pins for `aiofiles`, `aiohttp`, `pytest`, `ruff`, `tldextract`, and transitive dependencies. |
| `.github/workflows/update.yml` | Constraints install, cache invalidation, runtime summary, compatibility audit, scoped permissions | VERIFIED | Build uses constraints; summary reads `runtime_profile`; audit job is read-only; publish remains `contents: write`; cache cleanup remains `actions: write`. |
| `tests/test_ci_workflow.py` | Static workflow assertions | VERIFIED | Covers constraints, cache dependency path, audit matrix/install order, unchanged Python posture, package discovery, compact runtime summary, and no non-pip dependency manager. |
| `pyproject.toml` | Unchanged Python requirement and explicit package discovery | VERIFIED | Keeps `requires-python = ">=3.14"` and `target-version = "py314"`; `[tool.setuptools] packages = ["scripts"]` prevents the new top-level `constraints/` directory from entering package builds. |

### Key Link Verification

| From | To | Via | Status | Details |
|---|---|---|---|---|
| `scripts/downloader.py` | `.cache/` | Cache-side temp file promotion before raw output copy | WIRED | `fetch_url()` streams to `cache_path`, then calls `_copy_cache_to_output()` before `state[url]` is updated. |
| `scripts/downloader.py` | `lists/_raw/` | Bounded copy from completed cache file to raw output temp | WIRED | `_copy_cache_to_output()` delegates to `_copy_file_bounded()`; 304, HTTP fallback, timeout fallback, and exception fallback all use it. |
| `scripts/pipeline.py` | `scripts.cleaner.clean_line` | Worker cleaning delegates single-line decisions | WIRED | `_clean_single_file_to_spool()` calls `clean_line()` for every input line. |
| `scripts/pipeline.py` | `scripts.compiler.compile_rules` | Ordered generator reads cleaned spools | WIRED | Source files are sorted, worker results are keyed by source index, and `_get_cleaned_lines()` yields by index into `compile_rules()`. |
| `scripts/compiler.py` | `scripts/pipeline.py` | CompileStats cardinalities projected into `runtime_profile` | WIRED | `_record_compiler_cardinalities()` populates stats; `_compiler_cardinalities()` maps those fields into runtime profile. |
| `scripts/pipeline.py` | `scripts/release_validator.py` | Pipeline-stats schema version | WIRED | Both modules use schema version 2; validator schema check rejects unsupported versions but does not gate on runtime values. |
| `.github/workflows/update.yml` | `constraints/release-py314.txt` | `python -m pip install -c` | WIRED | Release and audit install commands both reference the committed constraints file. |
| `.github/workflows/update.yml` | `pyproject.toml` | setup-python cache dependency path and unchanged metadata | WIRED | Cache dependency path includes `pyproject.toml` and constraints; `pyproject.toml` keeps Python 3.14 declaration. |

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|---|---|---|---|---|
| `scripts/downloader.py` | Raw/cache bytes and source identity | HTTP `response.content.iter_chunked()` or existing cache files | Yes - streamed chunks reach cache temp, final cache, raw temp, raw final, then byte count/SHA-256 metrics. | FLOWING |
| `scripts/pipeline.py` | Cleaned rule lines | Raw `*.txt` files through `clean_line()` into per-source spools | Yes - spool files are streamed into `compile_rules()` in sorted source order and deleted afterward. | FLOWING |
| `scripts/compiler.py` | Compiler cardinalities | Existing ABP/wildcard/exception/duplicate/other rule structures | Yes - counts are populated after parse and before pruning/output, then returned in `CompileStats`. | FLOWING |
| `scripts/pipeline.py` | `runtime_profile` | Processed files, `CompileStats`, output file size, `tracemalloc`, optional `resource` | Yes - profile is returned by `process_files_with_profile()` and written to `reports/pipeline-stats.json` by CLI. | FLOWING |
| `.github/workflows/update.yml` | Runtime step summary | `reports/pipeline-stats.json` from compile step | Yes - summary step reads JSON after compile and before release validation, emitting only worker count, raw bytes, output bytes, and peak memory. | FLOWING |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|---|---|---|---|
| Phase 04 implementation and workflow regression gate | `.venv\Scripts\python.exe -m pytest tests/test_downloader.py tests/test_pipeline.py tests/test_compiler.py tests/test_release_validator.py tests/test_ci_workflow.py -x -q --tb=short` | 232 passed in 5.96s | PASS |
| Source compilation sanity | `.venv\Scripts\python.exe -m compileall -q run.py scripts tests` | Exit code 0 | PASS |
| Downloader full-response guard | `.venv\Scripts\python.exe -c "... re.search(r'response\\.read\\(', scripts/downloader.py) ..."` | Exit code 0 | PASS |
| Compiler allocation guard | `.venv\Scripts\python.exe -c "... 'abp_blocking_domains' in scripts/compiler.py ..."` | Exit code 0 | PASS |
| Full lint gate | `.venv\Scripts\python.exe -m ruff check .` | All checks passed | PASS |
| Dependency-manager guard | `rg -n "uv|poetry|pipenv|pip-tools" .github/workflows/update.yml constraints/release-py314.txt pyproject.toml` | No matches | PASS |
| SDK artifact/key-link checks | `gsd-sdk query verify.artifacts/verify.key-links` for all four plans | 13/13 artifacts passed; 8/8 key links verified | PASS |

### Probe Execution

| Probe | Command | Result | Status |
|---|---|---|---|
| None discovered | Searched `scripts/**/probe-*.sh` and phase PLAN/SUMMARY artifacts | No probe files or declared probe paths found | SKIPPED |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|---|---|---|---|---|
| RUN-01 | 04-01 | Downloader writes large responses through bounded streaming and atomic replacement instead of full-response buffering. | SATISFIED | Stream helper, bounded copy helper, final promotion order, state update order, and downloader tests verified. |
| RUN-02 | 04-02 | Cleaner and pipeline processing avoid unnecessary full-list materialization where practical. | SATISFIED | Worker process results return `CleanWorkerResult` metadata, not `list[str]`; spools feed compiler lazily in deterministic order. |
| RUN-03 | 04-03, 04-04 | Compiler removes unused allocations and records runtime-size metrics for large runs. | SATISFIED | `abp_blocking_domains` removed; compiler cardinalities recorded; schema 2 runtime profile written; workflow mirrors compact fields only. |
| RUN-04 | 04-04 | Release dependencies are reproducible through a lockfile or constraints file. | SATISFIED | Committed `constraints/release-py314.txt` has exact pins and release install uses it with cache invalidation. |
| RUN-05 | 04-04 | Maintainer can audit Python 3.13/3.14 compatibility through CI before changing `requires-python`. | SATISFIED | Read-only audit job has Python 3.13/3.14 matrix and audit-only install; workflow_dispatch run 26160556184 passed both audit jobs. |

No orphaned Phase 4 requirements were found. `RUN-01` through `RUN-05` are present in `.planning/REQUIREMENTS.md`, mapped to Phase 4, and claimed by one or more Phase 04 plans.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|---|---|---|---|---|
| Phase 04 source/test/workflow artifacts | n/a | `TBD` / `FIXME` / `XXX` debt markers | NONE | No blocker debt markers found. |
| `scripts/downloader.py`, `scripts/pipeline.py`, `scripts/compiler.py`, `scripts/release_validator.py`, tests | various | Empty list/dict initializers | INFO | Accumulators, defaults, or tests that are populated by runtime flow; not hardcoded output stubs. |
| `.planning/ROADMAP.md`, `.planning/REQUIREMENTS.md` | `Phase 3`, `REL-03`, `REL-05` | Planning status inconsistency | INFO | Phase 4 depends on Phase 3, and Phase 3 still shows in progress with two pending requirements in planning docs. This does not block RUN-01 through RUN-05, and Phase 04 code evidence is complete. |

### Human Verification Completed

### 1. GitHub Actions Runtime Smoke Check

**Test:** Run or inspect one `workflow_dispatch` build on GitHub Actions after merge.  
**Expected:** `build_validate` installs with `constraints/release-py314.txt`, generates `reports/pipeline-stats.json`, appends the compact runtime profile summary, gates publish on successful release validation, and `python_compatibility_audit` runs read-only on Python 3.13 and 3.14.  
**Result:** Passed. Initial run 26158900950 exposed a real timeout gap in `build_validate`; commit `1f156ec` raised the release job budget and pinned it in tests. Follow-up run 26160556184 passed end-to-end on `origin/main` at commit `1f156ec`, including constrained install, runtime profile stats artifact generation, release validation, artifact upload, publish, cache cleanup, and Python 3.13/3.14 compatibility audit jobs.

### Gaps Summary

No blocker gaps remain. Phase 04's runtime-scaling and reproducibility outcomes are implemented in the codebase, covered by focused tests, source guards, lint, and validated by a successful live GitHub Actions `workflow_dispatch` run.

### Disconfirmation Notes

- Potential partial requirement checked: `RUN-05` was initially static-only, then validated through workflow_dispatch run 26160556184.
- Potential misleading test checked: `tests/test_ci_workflow.py` proves YAML wiring and command order; live GitHub runner/cache/token behavior was separately verified by the passing workflow run.
- Potential uncovered error path checked: downloader success/fallback, pipeline compile failure cleanup, and release validator runtime-profile extremes all have focused regression coverage.

---

_Verified: 2026-05-20T10:59:53Z_  
_Verifier: the agent (gsd-verifier)_
