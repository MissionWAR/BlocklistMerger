---
phase: 04-runtime-scaling-reproducibility
plan: 01
subsystem: runtime-scaling
tags: [downloader, aiohttp, streaming, atomic-writes, cache]

requires:
  - phase: 03-release-validation-observability
    provides: Stable FetchResult and source-health report contracts for downloader output.
provides:
  - Cache-primary streamed downloader success path using aiohttp chunk iteration.
  - Bounded atomic cache-to-raw fallback copies for 304, HTTP error, timeout, and exception paths.
  - RUN-01 regression tests for streaming, failed-stream cleanup, fallback copies, and no new source gates.
affects: [runtime-scaling-reproducibility, source-health, github-actions]

tech-stack:
  added: []
  patterns:
    - Cache-side temp file promotion before raw output replacement.
    - Shared bounded aiofiles copy helper for cache fallback paths.
    - Bounded content identity hashing for source-health metrics.

key-files:
  created:
    - .planning/phases/04-runtime-scaling-reproducibility/04-01-SUMMARY.md
  modified:
    - scripts/downloader.py
    - tests/test_downloader.py

key-decisions:
  - "Kept FetchResult and source-health report contracts stable while changing downloader byte movement."
  - "Used cache-primary streaming so successful responses complete cache promotion before raw output copy and state mutation."
  - "Kept source size and content type policy-neutral; no hard source-size or content-type gates were added."

patterns-established:
  - "Downloader byte movement uses DOWNLOAD_CHUNK_SIZE for HTTP streams, cache/raw copies, and content hashing."
  - "Cache fallbacks reuse one bounded copy helper and preserve old final files until temp replacement succeeds."

requirements-completed: [RUN-01]

duration: 21 min
completed: 2026-05-18
---

# Phase 04 Plan 01: Downloader Streamed Atomic Fetch Summary

**Cache-primary aiohttp streaming with bounded fallback copies and atomic raw/cache promotion for large blocklist downloads**

## Performance

- **Duration:** 21 min
- **Started:** 2026-05-18T17:55:36Z
- **Completed:** 2026-05-18T18:16:26Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments

- Added focused async tests proving successful downloads use `response.content.iter_chunked()` and never `response.read()`.
- Added failed-stream coverage proving old cache/raw files and state survive partial response failures.
- Added shared bounded fallback-copy coverage for 304, HTTP error, timeout, and exception paths.
- Reworked downloader byte movement to stream into cache temp files, promote cache atomically, copy raw output atomically, and update state last.
- Changed source-health content identity from whole-file `read_bytes()` to bounded chunk hashing.

## Task Commits

1. **Task 1: Pin streamed downloader atomicity behavior** - `2750f7b` (test)
2. **Task 2: Implement bounded downloader streaming and fallback copies** - `9bedb4b` (feat)

## Files Created/Modified

- `scripts/downloader.py` - Adds chunk-size, temp cleanup, streamed response write, bounded cache/raw copy, and bounded content identity helpers; routes success and fallback paths through them.
- `tests/test_downloader.py` - Adds fake async response/session coverage for D-01 through D-05 without real HTTP requests.
- `.planning/phases/04-runtime-scaling-reproducibility/04-01-SUMMARY.md` - Documents execution results.

## Decisions Made

- Kept downloader public return and report contracts unchanged so Phase 03 release validation remains compatible.
- Used cache-primary promotion: a successful HTTP response must finish cache replacement before raw output copy and state update.
- Preserved source-health byte size and SHA-256 as metrics only; no hard source-size, memory, runtime, or content-type release gate was added.

## Verification

- `.venv\Scripts\python.exe -m pytest tests/test_downloader.py -x` - passed, 33 tests.
- `.venv\Scripts\python.exe -m ruff check scripts/downloader.py tests/test_downloader.py` - passed.
- `.venv\Scripts\python.exe -c "from pathlib import Path; import re, sys; text = Path('scripts/downloader.py').read_text(encoding='utf-8'); sys.exit(1 if re.search(r'response\\.read\\(', text) else 0)"` - passed.
- `.venv\Scripts\python.exe -c "from pathlib import Path; import re, sys; text = Path('scripts/downloader.py').read_text(encoding='utf-8'); sys.exit(1 if re.search(r'await\\s+src\\.read\\(\\s*\\)', text) else 0)"` - passed.
- `.venv\Scripts\python.exe -m pytest tests/test_downloader.py tests/test_pipeline.py tests/test_compiler.py tests/test_release_validator.py tests/test_ci_workflow.py -x` - passed, 217 tests.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- The system `python.exe` alias is still blocked by the WindowsApps/PyManager logon-session error, so verification used the repository `.venv\Scripts\python.exe` path as in prior phase execution.

## Known Stubs

None - stub scan found only normal test state literals, not placeholder or unwired runtime behavior.

## Threat Flags

None - the downloader trust-boundary changes were the planned T-04-01-01 and T-04-01-02 mitigations.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

Plan 04-02 can build on the same bounded-data-flow pattern for pipeline cleaning. The formal Wave 1 gate should run again after 04-02, but the listed subset already passes after 04-01.

## Self-Check: PASSED

- Found `.planning/phases/04-runtime-scaling-reproducibility/04-01-SUMMARY.md`.
- Found task commit `2750f7b`.
- Found task commit `9bedb4b`.

---
*Phase: 04-runtime-scaling-reproducibility*
*Completed: 2026-05-18*
