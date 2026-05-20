---
phase: 04-runtime-scaling-reproducibility
plan: 02
subsystem: runtime-scaling
tags: [pipeline, process-pool, spooling, determinism, pytest]

requires:
  - phase: 03-release-validation-observability
    provides: Versioned pipeline stats and deterministic release-output expectations.
provides:
  - Ordered process-pool cleaner spools that avoid returning full cleaned lists.
  - Source-index merge ordering independent of worker completion order.
  - Cleanup coverage for successful compilation and forced compile failures.
affects: [runtime-scaling-reproducibility, pipeline, release-determinism]

tech-stack:
  added: []
  patterns:
    - CleanWorkerResult metadata boundary for process-pool cleaner workers.
    - Generator-scoped temporary spool directory feeding compile_rules lazily.
    - Parent-side source-index ordering for completion-order independent merges.

key-files:
  created:
    - .planning/phases/04-runtime-scaling-reproducibility/04-02-SUMMARY.md
  modified:
    - scripts/pipeline.py
    - tests/test_pipeline.py

key-decisions:
  - "Kept ProcessPoolExecutor cleaning while replacing worker cleaned-list returns with per-source spool metadata."
  - "Collected completed worker metadata by source index so compiler input follows sorted filenames regardless of completion timing."
  - "Stored temporary cleaned spools in a TemporaryDirectory and removed spool files in success and exception paths."

patterns-established:
  - "Bounded cleaner worker results: workers return CleanWorkerResult(source_index, spool_path, stats) instead of list[str]."
  - "Ordered spool merge: parent reads spools by sorted source-file index after collecting worker completion results."

requirements-completed: [RUN-02]

duration: 6 min
completed: 2026-05-18
---

# Phase 04 Plan 02: Bounded Ordered Pipeline Cleaning Summary

**Process-pool cleaner workers now return bounded spool metadata while compiler input remains deterministic by sorted source-file order**

## Performance

- **Duration:** 6 min
- **Started:** 2026-05-18T18:45:13Z
- **Completed:** 2026-05-18T18:51:15Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments

- Added RED tests proving the worker boundary must not return full cleaned `list[str]` payloads.
- Added deterministic-order coverage where simulated worker completion order differs from sorted source-file order.
- Added cleanup coverage for temporary cleaned spools after successful compile and forced compile failure.
- Replaced `_clean_single_file()` materialization with `_clean_single_file_to_spool()` and `CleanWorkerResult` metadata.
- Preserved process-level parallel cleaning, flat pipeline stats, CLI behavior, and lazy `compile_rules()` input.

## Task Commits

1. **Task 1: Pin ordered bounded cleaning behavior** - `1584fc7` (test)
2. **Task 2: Replace full cleaned-list worker returns with ordered spools** - `77b25d3` (feat)

## Files Created/Modified

- `scripts/pipeline.py` - Adds `CleanWorkerResult`, worker spool writing, completion-order collection, ordered spool reads, and cleanup.
- `tests/test_pipeline.py` - Adds RUN-02 regression tests for bounded worker metadata, deterministic merge order, and spool cleanup.
- `.planning/phases/04-runtime-scaling-reproducibility/04-02-SUMMARY.md` - Documents execution results.

## Decisions Made

- Kept `ProcessPoolExecutor` as the parallel cleaning mechanism and changed only the worker result payload.
- Used per-source temporary spool files instead of adding a public runtime tuning surface or broad config.
- Reordered worker results in the parent by `source_index` so release-visible input order remains tied to `sorted(input_path.glob("*.txt"))`.

## Verification

- RED: `.venv\Scripts\python.exe -m pytest tests/test_pipeline.py tests/test_integration_pipeline.py -x` failed as expected before implementation because `_clean_single_file_to_spool` did not exist.
- `.venv\Scripts\python.exe -m pytest tests/test_pipeline.py tests/test_integration_pipeline.py -x` - passed, 25 tests.
- `.venv\Scripts\python.exe -c "from pathlib import Path; import re, sys; text = Path('scripts/pipeline.py').read_text(encoding='utf-8'); sys.exit(1 if re.search(r'tuple\\[list\\[str\\]', text) else 0)"` - passed.
- `.venv\Scripts\python.exe -m ruff check scripts/pipeline.py tests/test_pipeline.py` - passed.
- `.venv\Scripts\python.exe -m pytest tests/test_downloader.py tests/test_pipeline.py tests/test_compiler.py tests/test_release_validator.py tests/test_ci_workflow.py -x` - passed, 221 tests.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- Verification used the repository `.venv\Scripts\python.exe`, consistent with the Phase 04 environment notes that the system Python alias is unreliable in this workspace.

## Known Stubs

None - stub scan found only the test helper default `max_workers=None`, not placeholder runtime behavior.

## Threat Flags

None - the new worker spool boundary is the planned mitigation for T-04-02-01, T-04-02-02, and T-04-02-03.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

Plan 04-03 can now focus on compiler allocation cleanup and runtime profile reporting. The Wave 1 regression gate passes after 04-01 and 04-02.

## Self-Check: PASSED

- Found `.planning/phases/04-runtime-scaling-reproducibility/04-02-SUMMARY.md`.
- Found task commit `1584fc7`.
- Found task commit `77b25d3`.
- Focused RUN-02 gate and Wave 1 regression gate passed.

---
*Phase: 04-runtime-scaling-reproducibility*
*Completed: 2026-05-18*
