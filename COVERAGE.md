# Coverage Declaration — Phase 22 Weekly Perf-Evidence Workflow

This phase integrates no external API.

- Measurement runs on preinstalled GitHub runner tooling only: the `gh` CLI
  resolves the rolling-baseline run id, and `lscpu` plus `/etc/os-release`
  supply the environment receipts.
- The only third-party components are the four official `actions/*` workflow
  steps already pinned in this repository (checkout, setup-python,
  upload-artifact, download-artifact).
- No SaaS benchmark service and no Pages dashboard: evidence lands in dated
  workflow artifacts with 90-day retention plus the run step summary, and no
  committed result bytes enter git.
- No new pip package: the install line reuses the existing
  `constraints/release-py314.txt` entry, and `scripts/benchmark.py` plus
  `scripts/downloader.py` are consumed unchanged.

# Coverage Declaration — Phase 23 Hygiene Sweep (HYG-06)

This sweep integrates no external API.

- All edits are local text, config, and test changes: one `.gitignore`
  Agents-section addition, four added ignore-policy pins in
  `tests/test_public_docs.py` (v2 stem, dirb stem, two tooling-state paths),
  and this declaration itself.
- The only subprocess contact is the pre-existing `git check-ignore` /
  `git ls-files` probe helpers in `tests/test_public_docs.py`, called with
  fixed path literals; no new subprocess call is introduced.
- No network fetch, no pip install, and no new workflow step: the change
  touches no downloader, compiler, pipeline, or workflow publish path.
