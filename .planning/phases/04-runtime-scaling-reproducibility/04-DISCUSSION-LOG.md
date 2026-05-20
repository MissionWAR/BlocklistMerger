# Phase 4: Runtime Scaling & Reproducibility - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md - this log preserves the alternatives considered.

**Date:** 2026-05-18
**Phase:** 4-Runtime Scaling & Reproducibility
**Areas discussed:** Downloader bounded streaming, Large-run memory strategy, Runtime metrics surface, Reproducible dependencies and Python compatibility

---

## Downloader Bounded Streaming

| Option | Description | Selected |
|--------|-------------|----------|
| Cache-primary | Stream to a temp cache file, promote after success, update state last; safest consistency model. | yes |
| Dual-temp fanout | Write cache and raw output in one streaming pass; faster disk path but more failure handling. | |
| Minimal streaming | Smallest change that removes full-response reads, but weaker cache/output consistency. | |

**User's choice:** Cache-primary.
**Notes:** User accepted the recommended strategy. Follow-up guardrail decision: use metrics first for source byte/content risk rather than a hard default cap.

### Source Size / Content Guardrails

| Option | Description | Selected |
|--------|-------------|----------|
| Metrics first | Record per-source bytes and avoid hard caps until real data supports a safe threshold. | yes |
| High opt-in cap | Add a disabled or very high max-bytes knob for manual protection without changing default coverage. | |
| Hard default cap | Fail/fallback when sources exceed a configured byte cap; safer for runaway responses but higher false-failure risk. | |

**User's choice:** Metrics first.
**Notes:** Coverage remains more important than strict response-size enforcement.

---

## Large-Run Memory Strategy

| Option | Description | Selected |
|--------|-------------|----------|
| Bounded parallel | Keep parallel cleaning but use bounded chunks/temp spooling and remove obvious compiler waste. | yes |
| Minimal cleanup | Only remove known unused allocations and add metrics; lowest risk but leaves main materialization issue. | |
| Sequential stream | Simplest bounded memory path, but may slow CI by dropping process-parallel cleaning. | |

**User's choice:** Bounded parallel.
**Notes:** User accepted the recommended middle path: materially reduce peak memory without redesigning semantic compiler storage.

### Ordering Policy

| Option | Description | Selected |
|--------|-------------|----------|
| Preserve order | Keep deterministic sorted-file/chunk ordering even if it waits for slower workers. | yes |
| As-ready output | Stream cleaned chunks as they complete for throughput, accepting more ordering complexity. | |
| Planner decides | Leave exact ordering mechanics to planning as long as existing determinism tests pass. | |

**User's choice:** Preserve order.
**Notes:** Deterministic output remains more important than as-ready throughput.

---

## Runtime Metrics Surface

| Option | Description | Selected |
|--------|-------------|----------|
| Pipeline stats | Extend versioned pipeline stats with runtime_profile and mirror key fields in the step summary. | yes |
| Separate report | Create runtime-metrics JSON/Markdown for deeper instrumentation, at the cost of another report surface. | |
| Workflow-only | Use shell-level CI timing and sizes only; minimal code but not locally testable. | |

**User's choice:** Pipeline stats.
**Notes:** User accepted the recommendation to reuse the Phase 3 report surface.

### Runtime Release Gates

| Option | Description | Selected |
|--------|-------------|----------|
| Inspect only | Report runtime/memory/size metrics but do not warn or fail releases in Phase 4. | yes |
| Warnings only | Add non-blocking warnings for extreme runtime or memory growth. | |
| Hard gates | Fail releases on runtime/resource thresholds; strongest protection but highest flake risk. | |

**User's choice:** Inspect only.
**Notes:** Runtime metrics should establish baseline visibility before any thresholds affect scheduled releases.

---

## Reproducible Dependencies And Python Compatibility

| Option | Description | Selected |
|--------|-------------|----------|
| pip constraints | Keep pip/pyproject as the main flow with generated Python-version constraints; lightweight for v1. | yes |
| Hash lock | Stronger exact install integrity, but more generated churn and install complexity. | |
| uv lock | Modern lock/sync workflow, but adds a new toolchain to a currently pip-simple repo. | |

**User's choice:** pip constraints.
**Notes:** User accepted the lightweight pip-native path.

### Python Compatibility Policy

| Option | Description | Selected |
|--------|-------------|----------|
| Audit only | Add CI evidence for 3.13 and 3.14, but do not lower requires-python in this phase. | yes |
| Lower if green | If 3.13 tests pass, update pyproject/Ruff/workflow to support >=3.13 in the same phase. | |
| 3.14 only | Skip 3.13 audit and keep the declared requirement unchanged. | |

**User's choice:** Audit only.
**Notes:** Python compatibility evidence should be gathered before changing the declared support range.

### Runtime Control Surface

| Option | Description | Selected |
|--------|-------------|----------|
| Internal defaults | Use tested constants and existing CLI knobs; avoid adding public configuration surface in Phase 4. | yes |
| CLI knobs | Expose chunk size, temp directory, or similar options for maintainer tuning. | |
| Config file | Add structured config for runtime controls, which is broader and closer to deferred v2 scope. | |

**User's choice:** Internal defaults.
**Notes:** New runtime/scaling behavior should stay implementation-level unless an existing CLI option naturally fits.

---

## Agent's Discretion

- Exact downloader chunk size, temp-file naming, and cleanup helper boundaries.
- Exact bounded cleaning mechanics, provided ordering remains deterministic and memory is bounded.
- Exact runtime metric field names and memory measurement implementation.
- Exact constraints file naming/layout, provided the release install is reproducible.

## Deferred Ideas

- Hard source-size/content-type release gates.
- Runtime warning or hard gates.
- Deep compiler storage redesign.
- Hash-pinned install or `uv` migration.
- Lowering `requires-python` before reviewing compatibility evidence.
- Broad runtime configuration files.
