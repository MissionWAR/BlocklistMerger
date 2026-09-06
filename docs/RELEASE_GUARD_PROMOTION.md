# Release Guard Promotion

This document defines which release evidence can block the scheduled publish
workflow today and what proof is required before diagnostics become hard gates.
The default path remains the lightweight 12-hour `build_validate -> publish`
chain in `.github/workflows/update.yml`.

## Current Hard Gates

Scheduled publishing may fail only on deterministic artifact safety,
evidence-integrity failures, and scoped hard canary failures that are
fixture-backed and intentionally configured as hard gates.

The current hard-gate set is:

- Invalid, unsupported, URL-path, or exception-rule syntax in `lists/merged.txt`.
- Unsupported or unusable validation input schemas.
- Missing, invalid, or mismatched trusted output counts from pipeline stats.
- Output below the configured hard minimum rule count.
- Catastrophic source-health failure or stale-cache thresholds.
- Existing previous-output aggregate extreme count deltas.
- Schema v1 must-block and must-allow canary failures.
- Schema v2 scoped hard canary failures when a scoped record explicitly sets
  `gate: hard` and fixture coverage proves the behavior is deterministic.

### Previous-output extreme absolute delta recalibration

On 2026-08-23 the hard gate `previous_output_extreme_absolute_delta` was raised
from 1,000,000 to 2,000,000 rules. The gate is backed by the constant
DEFAULT_PREVIOUS_EXTREME_ABSOLUTE_DELTA in scripts/release_validator.py.

The first scheduled run after the v1.2 denyallow wildcard compression milestone
legitimately shrank merged.txt by 1,074,698 rules (-22.9%) by folding many
subdomain rules into denyallow wildcards. Source health, syntax checks,
canaries, and the 25% drop-ratio guard all stayed green, so the old 1,000,000
absolute guard blocked a healthy publish. The new value is sized from that
measured legitimate churn plus headroom for further compression gains.

The proportional protection is unchanged: previous_extreme_drop_ratio (25%)
remains the guard against proportional collapses, and the absolute gate
continues to catch raw-count catastrophes on top of it.

This threshold was changed by maintainer decision with the validator constant,
boundary tests in tests/test_release_validator.py, and this documentation
updated in the same change set.

## Inspect-Only Evidence

The release evidence sidecar at `reports/release-evidence.json` is diagnostic
review evidence. It is uploaded with `reports/*.json` and `reports/*.md` in the
scheduled release-candidate artifact, but `publish` stages only
`release-candidate/lists/merged.txt`.

These evidence classes are inspect-only unless explicitly promoted later:

- Membership churn, including added and removed counts and capped samples.
- Output fingerprints for current, previous, added, and removed membership.
- Runtime profiles and resource summaries from pipeline stats.
- Stage summaries and compiler cardinality diagnostics.
- Semantic diagnostics from rule classification and scoped coverage records.
- Heavy evidence from benchmark and profiling workflows.
- Normal source-health degradation below the existing hard thresholds.

These diagnostics do not block scheduled publishing by themselves. The existing
previous-output aggregate count gates remain the only hard churn blockers.

## Scoped Canary Promotion

Schema v1 canaries remain the public compatibility baseline. Schema v2 scoped
canaries can describe apex, subdomain, wildcard, allowlist, and modifier-aware
intent, but scoped records are diagnostic by default.

A scoped canary may become a hard gate only when all of the following are true:

- Deterministic fixture coverage proves the release validator can evaluate the
  scoped behavior without relying on live upstream churn.
- The scoped record explicitly sets `gate: hard`.
- The behavior maps to AdGuard Home DNS release safety, not browser-only ABP
  behavior.
- The expected failure mode is stable, actionable, and owned by this project.

## Manual Heavy Evidence

`.github/workflows/heavy-evidence.yml` is a separate manual workflow_dispatch
surface. It is read-only, non-publishing, and uploads retained diagnostics under:

- `reports/heavy-evidence/**`
- `reports/benchmarks/**`
- `reports/profiles/**`

The manual workflow has no schedule, no publish job, no release upload, no tag
creation, no artifact download handoff, and no cache deletion behavior. Its
artifacts can inform later decisions, but they do not create release findings in
this phase.

The weekly heavy-evidence schedule is not active. The weekly perf-evidence
schedule in `.github/workflows/perf-evidence.yml` (Tuesday 03:17 UTC plus
manual dispatch) is the intentional source change that introduces a recurring
non-publishing benchmark-evidence workflow; it satisfies the promotion evidence
listed below as advisory-only evidence that never gates publishing. Adding any
further recurring non-publishing heavy-evidence workflow requires an intentional
source change and the promotion evidence listed below.

## Promotion Criteria

Before any inspect-only diagnostic becomes a hard release gate or before any
weekly non-publishing heavy-evidence schedule is introduced, the maintainer
should require:

- Deterministic fixture coverage for the exact failure class.
- Stable report schema with compatibility expectations documented.
- Stable budgets from repeated manual runs on production-shaped inputs.
- Low-noise false-positive behavior across normal upstream source movement.
- Explicit threshold ownership, including who changes it and how it is reviewed.
- Intentional source change that names the promoted diagnostic and updates
  tests, docs, and workflow boundaries together.

Until those criteria are met, diagnostics remain retained evidence for review,
not scheduled hard release gates.
