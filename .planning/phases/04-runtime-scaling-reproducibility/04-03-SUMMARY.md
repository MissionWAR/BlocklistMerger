---
phase: 04-runtime-scaling-reproducibility
plan: 03
subsystem: runtime-scaling
tags: [compiler, pipeline, runtime-profile, release-validator, pytest]

requires:
  - phase: 04-runtime-scaling-reproducibility
    provides: RUN-01 streamed downloader and RUN-02 bounded ordered pipeline cleaning.
provides:
  - Compiler allocation cleanup that removes the unused coverage lookup set.
  - Inspect-only compiler cardinality counters on CompileStats.
  - Pipeline stats schema 2 with top-level runtime_profile diagnostics.
  - Release validator compatibility with schema 2 without runtime gates.
affects: [runtime-scaling-reproducibility, release-validation, pipeline-stats]

tech-stack:
  added: []
  patterns:
    - Inspect-only runtime_profile data on the existing pipeline stats report.
    - Compatibility wrapper preserving process_files() while adding process_files_with_profile().
    - Compiler cardinalities populated from existing dictionary, set, and list structures.

key-files:
  created:
    - .planning/phases/04-runtime-scaling-reproducibility/04-03-SUMMARY.md
  modified:
    - scripts/compiler.py
    - scripts/pipeline.py
    - scripts/release_validator.py
    - tests/test_compiler.py
    - tests/test_pipeline.py
    - tests/test_release_validator.py

key-decisions:
  - "Removed only the unused compiler coverage allocation and kept dictionary/set compiler storage unchanged."
  - "Exposed runtime-size observations through pipeline-stats schema 2 instead of a separate report family."
  - "Kept runtime profile data inspect-only; release validation performs schema compatibility checks but no runtime thresholds."

patterns-established:
  - "process_files_with_profile() returns PipelineStats plus RuntimeProfile while process_files() keeps the old return type."
  - "Runtime profile fields are grouped as worker_count, stage_durations_seconds, byte_sizes, compiler_cardinalities, and memory."

requirements-completed: [RUN-03]

duration: 12 min
completed: 2026-05-18
---

# Phase 04 Plan 03: Compiler Allocation Cleanup and Runtime Profile Report Summary

**Unused compiler lookup removal plus schema-versioned pipeline runtime_profile diagnostics for large-run inspection**

## Performance

- **Duration:** 12 min
- **Started:** 2026-05-18T18:55:59Z
- **Completed:** 2026-05-18T19:08:02Z
- **Tasks:** 2
- **Files modified:** 7

## Accomplishments

- Removed the unused `abp_blocking_domains` allocation from compiler coverage lookup construction.
- Added `CompileStats` cardinalities for ABP rule keys, wildcard keys, exception keys, duplicate-index size, and other-rule count.
- Added `process_files_with_profile()` so CLI execution can collect runtime diagnostics while `process_files()` remains compatible.
- Bumped pipeline stats to schema 2 and writes top-level `runtime_profile` with worker count, stage durations, byte sizes, compiler cardinalities, and best-effort memory.
- Updated release validation to accept pipeline-stats schema 2 without adding runtime warnings or hard gates.

## Task Commits

1. **Task 1 RED: Compiler allocation regression coverage** - `338539a` (test)
2. **Task 1 GREEN: Compiler cardinalities and allocation cleanup** - `792980e` (feat)
3. **Task 2 RED: Runtime profile report coverage** - `031edf1` (test)
4. **Task 2 GREEN: Runtime profile implementation and schema compatibility** - `bdf5ba6` (feat)

## Files Created/Modified

- `scripts/compiler.py` - Removes the unused coverage lookup allocation and adds inspect-only cardinality fields to `CompileStats`.
- `scripts/pipeline.py` - Adds `RuntimeProfile`, `process_files_with_profile()`, schema 2 JSON output, stage timing, byte-size, compiler-cardinality, and memory reporting.
- `scripts/release_validator.py` - Updates the expected pipeline-stats schema version to 2 without consuming runtime fields for policy.
- `tests/test_compiler.py` - Adds mixed semantic regression coverage for pruning counters, output order, and cardinalities.
- `tests/test_pipeline.py` - Covers profiled processing and schema 2 `runtime_profile` JSON output.
- `tests/test_release_validator.py` - Covers schema 2 compatibility and proves runtime data is inspect-only.
- `.planning/phases/04-runtime-scaling-reproducibility/04-03-SUMMARY.md` - Documents execution results.

## Decisions Made

- Removed only the unused compiler lookup allocation; no trie, SQLite, partitioned compilation, external sorting, or semantic pruning rewrite was introduced.
- Kept the original `process_files(input_dir, output_file) -> PipelineStats` contract and added a profiled helper for CLI/report use.
- Treated runtime metrics as diagnostics only. The release validator checks schema compatibility but does not inspect memory, duration, byte-size, or cardinality thresholds.

## Verification

- RED: `.venv\Scripts\python.exe -m pytest tests/test_compiler.py tests/test_rule_semantics.py -x` failed as expected because `CompileStats` lacked the new cardinality fields.
- RED: `.venv\Scripts\python.exe -m pytest tests/test_pipeline.py tests/test_release_validator.py -x` failed as expected because `process_files_with_profile()` did not exist.
- `.venv\Scripts\python.exe -m pytest tests/test_compiler.py tests/test_rule_semantics.py -x` - passed, 193 tests.
- `.venv\Scripts\python.exe -m pytest tests/test_pipeline.py tests/test_release_validator.py -x` - passed, 37 tests.
- `.venv\Scripts\python.exe -c "from pathlib import Path; import sys; text = Path('scripts/compiler.py').read_text(encoding='utf-8'); sys.exit(1 if 'abp_blocking_domains' in text else 0)"` - passed.
- `.venv\Scripts\python.exe -m pytest tests/test_downloader.py tests/test_pipeline.py tests/test_compiler.py tests/test_release_validator.py tests/test_ci_workflow.py -x` - passed, 224 tests.
- `.venv\Scripts\python.exe -m ruff check scripts/compiler.py scripts/pipeline.py scripts/release_validator.py tests/test_compiler.py tests/test_pipeline.py tests/test_release_validator.py` - passed.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- The repository still uses `.venv\Scripts\python.exe` for verification because prior Phase 04 execution established that the global Windows Python alias is unreliable in this workspace.
- `tests/` is ignored by this repository, so plan-owned test files were force-staged for the test commits, matching earlier phase execution.

## Known Stubs

None - stub scan found only ordinary test helper defaults, optional `None` memory fields, and initialized empty collections used by runtime logic.

## Threat Flags

None - the new compiler-to-pipeline and pipeline-report-to-validator surfaces are the planned T-04-03 trust boundaries, and runtime data remains inspect-only.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

Plan 04-04 can build on schema 2 runtime diagnostics while adding release dependency constraints and Python compatibility auditing.

## Self-Check: PASSED

- Found `.planning/phases/04-runtime-scaling-reproducibility/04-03-SUMMARY.md`.
- Found task commit `338539a`.
- Found task commit `792980e`.
- Found task commit `031edf1`.
- Found task commit `bdf5ba6`.
- Focused RUN-03 gates, broad Phase 04 regression gate, and Ruff passed.

---
*Phase: 04-runtime-scaling-reproducibility*
*Completed: 2026-05-18*
