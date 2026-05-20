# Roadmap: Blocklist Merger

## Overview

This v1 roadmap tightens the existing Python/GitHub Actions blocklist compiler in the order that protects the core value: first establish parser correctness and CI gates, then make deduplication and whitelist handling semantic, then prevent unsafe releases with validation and observability, then reduce runtime and reproducibility risk, and finally polish lightweight public reuse without expanding into a HostlistCompiler-style platform.

**Granularity:** standard
**Requirement coverage:** 23/23 v1 requirements mapped

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 1: Parser Contract & CI Baseline** - Cleaner/compiler syntax behavior is pinned and tests/lint guard scheduled publishing. (completed 2026-05-16)
- [x] **Phase 2: Semantic Deduplication & Whitelist Safety** - Rules are pruned only when structured semantics prove behavior is preserved. (completed 2026-05-16)
- [ ] **Phase 3: Release Validation & Observability** - Scheduled releases fail closed using source health, pipeline stats, deltas, syntax checks, canaries, determinism, and scoped permissions.
- [x] **Phase 4: Runtime Scaling & Reproducibility** - Large runs use bounded data flow and reproducible release dependencies after semantics and release safety are pinned. (completed 2026-05-20)
- [ ] **Phase 5: Lightweight Public Reuse Polish** - Public users can fork and operate the main workflow safely while v2 configuration-platform ideas remain deferred.

## Phase Details

### Phase 1: Parser Contract & CI Baseline
**Goal**: Maintainer can trust cleaner/compiler syntax handling and scheduled release quality gates before deeper dedupe refactors begin.
**Depends on**: Nothing (first phase)
**Requirements**: [PARS-01, PARS-02, PARS-03, PARS-04, REL-01]
**Success Criteria** (what must be TRUE):
  1. Maintainer can discard DNS-incompatible URL-path rules while valid regex rules and slash-like modifier values remain eligible for compilation.
  2. Maintainer can inspect pipeline stats that include every cleaner discard category, including URL path and invalid-rule categories.
  3. Maintainer can run focused fixtures proving cleaner and compiler agree on URL paths, regex rules, modifiers, and unsupported browser-only rules.
  4. Scheduled release publishing is blocked when pytest or Ruff fails.
**Plans**:
- Wave 1: `01-01` - Shared parser classifier and cleaner wiring.
- Wave 2 *(blocked on Wave 1 completion)*: `01-02` - Compiler agreement and parser contract matrix.
- Wave 2 *(blocked on Wave 1 completion)*: `01-03` - Cleaner discard stats and pipeline projection.
- Wave 3 *(blocked on Wave 2 completion)*: `01-04` - Inline CI Ruff/pytest release gate.
**UI hint**: no

### Phase 2: Semantic Deduplication & Whitelist Safety
**Goal**: Maintainer can reduce redundant rules only when modifier semantics and whitelist coverage prove the resulting blocking behavior is equivalent.
**Depends on**: Phase 1
**Requirements**: [DEDUP-01, DEDUP-02, DEDUP-03, DEDUP-04, DEDUP-05]
**Success Criteria** (what must be TRUE):
  1. Maintainer can represent ABP modifiers as structured semantic data with name, value, negation, and raw form.
  2. Exact duplicate rules are removed only when their semantic behavior is equivalent.
  3. Parent-covered child rules are pruned only when parent coverage preserves the child's scope and behavior.
  4. Rules are preserved when modifier equivalence is uncertain, including behavior-sensitive modifiers such as client, ctag, dnstype, dnsrewrite, denyallow, badfilter, and important.
  5. Whitelist handling removes block rules only when equivalent coverage is proven by tests.
**Plans**: 4 plans
Plans:
- [x] `02-01-PLAN.md` - Structured modifier semantics foundation.
- [x] `02-02-PLAN.md` - Exact semantic duplicate indexing.
- [x] `02-03-PLAN.md` - Conservative parent, wildcard, and TLD coverage pruning.
- [x] `02-04-PLAN.md` - Modifier-aware whitelist consumption and integration fixtures.
**UI hint**: no

### Phase 3: Release Validation & Observability
**Goal**: Maintainer can inspect release health and scheduled runs fail before publishing unsafe, partial, stale, or noisy outputs.
**Depends on**: Phase 2
**Requirements**: [REL-02, REL-03, REL-04, REL-05, REL-06]
**Success Criteria** (what must be TRUE):
  1. Maintainer can inspect a machine-readable source-health report for every configured upstream URL.
  2. Maintainer can inspect machine-readable pipeline stats covering input counts, discard counts, pruning counts, output counts, and runtime.
  3. Scheduled releases fail before publishing when source health, output deltas, syntax checks, or canary checks violate configured thresholds.
  4. Workflow write permissions are limited to jobs that need them.
  5. Release output ordering is deterministic enough for meaningful scheduled-run diffs.
**Plans**: TBD
**UI hint**: no

### Phase 4: Runtime Scaling & Reproducibility
**Goal**: Maintainer can run the pinned-safe pipeline with lower memory/runtime risk and auditable release environments.
**Depends on**: Phase 3
**Requirements**: [RUN-01, RUN-02, RUN-03, RUN-04, RUN-05]
**Success Criteria** (what must be TRUE):
  1. Downloader handles large responses through bounded streaming and atomic replacement instead of full-response buffering.
  2. Cleaner, pipeline, and compiler large-run paths avoid unnecessary full-list materialization or unused allocations where practical.
  3. Maintainer can inspect runtime-size metrics for large compiler and pipeline runs.
  4. Scheduled release dependencies are reproducible through a lockfile or constraints file.
  5. Maintainer can audit Python 3.13 and 3.14 compatibility in CI before changing the declared Python requirement.
**Plans**: 4 plans
Plans:
- [ ] `04-01-PLAN.md` - Downloader streamed atomic fetch and fallback copies.
- [ ] `04-02-PLAN.md` - Bounded ordered pipeline cleaning.
- [ ] `04-03-PLAN.md` - Compiler allocation cleanup and runtime profile report.
- [ ] `04-04-PLAN.md` - Release constraints, runtime summary, and Python compatibility audit.
**UI hint**: no

### Phase 5: Lightweight Public Reuse Polish
**Goal**: Public users can safely fork and operate the existing AdGuard Home release workflow without v1 expanding into a general configuration platform.
**Depends on**: Phase 4
**Requirements**: [PUB-01, PUB-02, PUB-03]
**Success Criteria** (what must be TRUE):
  1. Public users can understand how to edit config/sources.txt, run the pipeline locally, and use the published release URL.
  2. Repository ignore rules clearly separate source assets from generated and runtime artifacts.
  3. v2 configuration-platform ideas are documented as deferred scope rather than mixed into v1 compiler work.
**Plans**: TBD
**UI hint**: no

## Progress

**Execution Order:**
Phases execute in numeric order: 1 -> 2 -> 3 -> 4 -> 5

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Parser Contract & CI Baseline | 4/4 | Complete   | 2026-05-16 |
| 2. Semantic Deduplication & Whitelist Safety | 4/4 | Complete   | 2026-05-16 |
| 3. Release Validation & Observability | 3/4 | In Progress|  |
| 4. Runtime Scaling & Reproducibility | 4/4 | Complete   | 2026-05-20 |
| 5. Lightweight Public Reuse Polish | 0/TBD | Not started | - |
