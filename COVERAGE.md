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
