---
phase: 04-runtime-scaling-reproducibility
plan: 04
subsystem: release-workflow
tags: [github-actions, pip-constraints, python-compatibility, runtime-profile, pytest]

requires:
  - phase: 03-release-validation-observability
    provides: Least-privilege release workflow, diagnostics artifacts, and validation summary wiring.
  - phase: 04-runtime-scaling-reproducibility
    provides: Pipeline stats schema 2 with inspect-only runtime_profile data.
provides:
  - Committed pip-native Python 3.14 release constraints.
  - Constraints-backed scheduled release install and setup-python cache invalidation.
  - Compact GitHub step summary mirror for key runtime profile fields.
  - Read-only Python 3.13 and 3.14 compatibility audit job.
affects: [runtime-scaling-reproducibility, release-workflow, python-compatibility]

tech-stack:
  added: []
  patterns:
    - Pip constraints file as release resolution artifact while pyproject.toml remains the dependency contract.
    - Separate read-only compatibility audit matrix using audit-only --ignore-requires-python install.
    - Compact runtime_profile step-summary projection from reports/pipeline-stats.json.
    - Explicit setuptools package discovery for the scripts package in a flat-layout repo.

key-files:
  created:
    - constraints/release-py314.txt
    - .planning/phases/04-runtime-scaling-reproducibility/04-04-SUMMARY.md
  modified:
    - .github/workflows/update.yml
    - tests/test_ci_workflow.py
    - pyproject.toml

key-decisions:
  - "Kept pyproject.toml as the human dependency declaration and used constraints/release-py314.txt only as the scheduled-release resolution artifact."
  - "Kept Python 3.13/3.14 compatibility evidence in a separate read-only audit job without lowering requires-python."
  - "Mirrored only worker count, raw input bytes, output bytes, and peak memory into the GitHub step summary."
  - "Pinned setuptools package discovery to scripts after the new constraints directory exposed flat-layout package discovery failure."

patterns-established:
  - "Release installs use python -m pip install -q -c constraints/release-py314.txt \".[dev]\"."
  - "Compatibility audits use python -m pip install -e \".[dev]\" --ignore-requires-python -c constraints/release-py314.txt."
  - "Workflow static tests assert constraints, cache dependency paths, audit permissions, and compact runtime summary wiring."

requirements-completed: [RUN-03, RUN-04, RUN-05]

duration: 16 min
completed: 2026-05-20
---

# Phase 04 Plan 04: Release Constraints, Runtime Summary, and Python Audit Summary

**Pip-constrained scheduled release installs with compact runtime summary output and a read-only Python 3.13/3.14 compatibility audit**

## Performance

- **Duration:** 16 min
- **Started:** 2026-05-20T10:31:02Z
- **Completed:** 2026-05-20T10:46:37Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments

- Added `constraints/release-py314.txt` from a verified CPython 3.14.5 environment.
- Added static workflow assertions for release constraints, cache dependency paths, audit matrix, audit install command, unchanged Python metadata, least privilege, and compact runtime summary output.
- Changed scheduled release installs to use the committed constraints file while keeping `pyproject.toml` as the source dependency contract.
- Added a separate read-only `python_compatibility_audit` job for Python 3.13 and 3.14.
- Added a runtime profile summary step that appends only key fields from `reports/pipeline-stats.json` to `$GITHUB_STEP_SUMMARY`.
- Fixed package discovery so the new top-level `constraints/` directory does not break package builds.

## Task Commits

1. **Task 1 RED: Add workflow assertions and release constraints artifact** - `873170d` (test)
2. **Task 2 GREEN: Wire constraints install, runtime summary, and Python audit CI** - `bac05f5` (feat)
3. **Rule 3 fix: Constrain package discovery for constraints dir** - `f71c783` (fix)

## Files Created/Modified

- `constraints/release-py314.txt` - Exact pip pins for the reviewed Python 3.14 scheduled-release dependency set.
- `.github/workflows/update.yml` - Adds constraints-backed install/cache keys, compact runtime summary, and read-only Python compatibility audit.
- `tests/test_ci_workflow.py` - Extends static workflow coverage for reproducibility, audit separation, unchanged Python posture, permissions, runtime summary output, and package discovery.
- `pyproject.toml` - Limits setuptools package discovery to `scripts` so top-level runtime/config directories are not treated as packages.
- `.planning/phases/04-runtime-scaling-reproducibility/04-04-SUMMARY.md` - Documents execution results.

## Decisions Made

- Used a pip constraints artifact instead of introducing a new dependency manager or hash-required workflow.
- Kept release publishing on the normal Python 3.14 install path; only the audit job uses `--ignore-requires-python`.
- Kept runtime profile data inspect-only by rendering a compact summary without adding runtime thresholds or validation gates.
- Added explicit package discovery after install verification showed the new constraints directory affected setuptools flat-layout discovery.

## Verification

- RED: `C:\Users\User\AppData\Local\Programs\Python\Python314\python.exe -m pytest tests/test_ci_workflow.py -x` failed as expected before workflow wiring because the constraints-backed install command was missing.
- Python 3.14 provenance: `C:\Users\User\AppData\Local\Programs\Python\Python314\python.exe -c "import sys; assert sys.version_info[:2] == (3, 14), sys.version"` passed.
- Constraints install dry-run: `C:\Users\User\AppData\Local\Programs\Python\Python314\python.exe -m pip install --dry-run -q -c constraints/release-py314.txt ".[dev]"` passed after the package-discovery fix.
- Focused workflow gate: `C:\Users\User\AppData\Local\Programs\Python\Python314\python.exe -m pytest tests/test_ci_workflow.py -x` passed, 13 tests.
- Phase 04 broad gate: `TLDEXTRACT_CACHE=C:\tmp\tldextract-cache C:\Users\User\AppData\Local\Programs\Python\Python314\python.exe -m pytest tests/test_downloader.py tests/test_pipeline.py tests/test_compiler.py tests/test_release_validator.py tests/test_ci_workflow.py -x` passed, 232 tests.
- Full suite: `TLDEXTRACT_CACHE=C:\tmp\tldextract-cache C:\Users\User\AppData\Local\Programs\Python\Python314\python.exe -m pytest` passed, 354 tests.
- Lint: `C:\Users\User\AppData\Local\Programs\Python\Python314\python.exe -m ruff check .` passed.
- Python posture check: `rg -n 'requires-python = ">=3\.14"|target-version = "py314"' pyproject.toml` passed.
- Dependency-manager guard: scanned `.github/workflows/update.yml` and `constraints/release-py314.txt` for `uv`, `poetry`, `pipenv`, and `pip-tools`; none found.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Explicit package discovery for new constraints directory**
- **Found during:** Task 2 verification.
- **Issue:** Adding top-level `constraints/` caused setuptools flat-layout discovery to report multiple top-level packages (`lists`, `config`, and `constraints`) during `python -m pip install -c constraints/release-py314.txt ".[dev]"`.
- **Fix:** Added `[tool.setuptools] packages = ["scripts"]` and a static regression test so runtime/config/constraints directories are not included in package builds.
- **Files modified:** `pyproject.toml`, `tests/test_ci_workflow.py`.
- **Verification:** Constraints install dry-run, focused workflow tests, broad Phase 04 gate, full pytest, and Ruff passed.
- **Committed in:** `f71c783`.

---

**Total deviations:** 1 auto-fixed blocking issue.
**Impact on plan:** The fix was required for the planned constraints-backed install to work. It did not change `requires-python`, dependencies, Ruff target, or release semantics.

## Issues Encountered

- The repository `.venv` is Python 3.12.13, so constraints generation and verification used the installed CPython 3.14.5 interpreter at `C:\Users\User\AppData\Local\Programs\Python\Python314\python.exe`.
- The Windows system `python` alias remains broken in this workspace, consistent with earlier Phase 04 notes.
- The first broad Python 3.14 test run hit a `tldextract` suffix-cache file lock under global site-packages. Re-running with `TLDEXTRACT_CACHE=C:\tmp\tldextract-cache` isolated the cache and the broad/full suites passed.

## Known Stubs

None - stub scan found no placeholder or unwired behavior in the created/modified plan files.

## Threat Flags

None - new CI trust-boundary changes were planned mitigations. The audit job is read-only, `publish` remains the contents-write job, and `cache_cleanup` remains the actions-write job.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

Phase 04 runtime scaling and reproducibility work is complete. The project is ready for phase-level verification and then Phase 05 public reuse polish planning.

## Self-Check: PASSED

- Found `constraints/release-py314.txt`.
- Found `.planning/phases/04-runtime-scaling-reproducibility/04-04-SUMMARY.md`.
- Found task commit `873170d`.
- Found task commit `bac05f5`.
- Found deviation fix commit `f71c783`.
- Focused workflow gate, broad Phase 04 gate, full pytest, Ruff, Python posture check, and dependency-manager guard passed.

---
*Phase: 04-runtime-scaling-reproducibility*
*Completed: 2026-05-20*
