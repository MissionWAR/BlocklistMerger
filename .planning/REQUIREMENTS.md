# Requirements: Blocklist Merger

**Defined:** 2026-05-16
**Core Value:** Produce one safe, compact, AdGuard Home-compatible blocklist that preserves maximum blocking coverage while removing only rules that are truly redundant.

## v1 Requirements

Requirements for the current improvement milestone. Each maps to roadmap phases.

### Parser & Cleaner Contract

- [x] **PARS-01**: Maintainer can discard DNS-incompatible URL-path rules without discarding valid regex rules.
- [x] **PARS-02**: Maintainer can preserve rules whose modifier values contain slash-like text, such as `$domain=foo/bar.com`, when AdGuard Home semantics allow them.
- [x] **PARS-03**: Maintainer can see every cleaner discard category in pipeline stats, including URL path and invalid-rule categories.
- [x] **PARS-04**: Maintainer can run focused fixtures proving cleaner and compiler agree on URL paths, regex rules, modifiers, and unsupported browser-only rules.

### Semantic Deduplication

- [x] **DEDUP-01**: Maintainer can parse ABP modifiers as structured semantic data, including modifier name, value, negation, and raw form.
- [x] **DEDUP-02**: Maintainer can deduplicate exact duplicate rules only when their semantic behavior is equivalent.
- [x] **DEDUP-03**: Maintainer can prune parent-covered child rules only when parent coverage preserves child scope and behavior.
- [x] **DEDUP-04**: Maintainer can keep both rules when modifier equivalence is uncertain, especially for `client`, `ctag`, `dnstype`, `dnsrewrite`, `denyallow`, `badfilter`, and `important`.
- [x] **DEDUP-05**: Maintainer can apply whitelist handling only when removing a block rule is provably equivalent and covered by tests.

### Release Safety & Observability

- [x] **REL-01**: Scheduled GitHub Actions releases run pytest and Ruff before publishing `merged.txt`.
- [x] **REL-02**: Maintainer can inspect a machine-readable source-health report for every configured upstream URL.
- [ ] **REL-03**: Maintainer can inspect machine-readable pipeline stats for input counts, discard counts, pruning counts, output counts, and runtime.
- [x] **REL-04**: Scheduled releases fail before publishing when source health, output deltas, syntax checks, or canary checks violate configured thresholds.
- [ ] **REL-05**: Workflow permissions are scoped so write permissions are only granted to jobs that need them.
- [x] **REL-06**: Release output is deterministic enough for meaningful scheduled-run diffs.

### Runtime & Reproducibility

- [x] **RUN-01**: Downloader writes large responses through bounded streaming and atomic replacement instead of full-response buffering.
- [ ] **RUN-02**: Cleaner and pipeline processing avoid unnecessary full-list materialization where practical.
- [ ] **RUN-03**: Compiler removes unused allocations and records runtime-size metrics for large runs.
- [ ] **RUN-04**: Release dependencies are reproducible through a lockfile or constraints file.
- [ ] **RUN-05**: Maintainer can audit Python 3.13/3.14 compatibility through CI before changing `requires-python`.

### Public Reuse Polish

- [ ] **PUB-01**: Public users can understand how to edit `config/sources.txt`, run the pipeline locally, and use the published release URL.
- [ ] **PUB-02**: Repository ignore rules clearly separate source assets from generated/runtime artifacts.
- [ ] **PUB-03**: v2 configuration ideas are documented as deferred scope, not mixed into the v1 compiler work.

## v2 Requirements

Deferred to a future HostlistCompiler-like milestone after v1 correctness and release safety are trustworthy.

### Configuration Platform

- **CFG-01**: User can define blocklist sources and metadata in a structured JSON or YAML configuration file.
- **CFG-02**: User can apply global and per-source transformations with a documented execution order.
- **CFG-03**: User can define inclusion and exclusion lists with dry-run stats that explain the effect of each rule.
- **CFG-04**: User can choose named pruning policies such as conservative, balanced, or aggressive.
- **CFG-05**: User can generate multiple output profiles after AdGuard Home strict output is proven stable.

## Out of Scope

Explicitly excluded from v1 to prevent scope creep.

| Feature | Reason |
|---------|--------|
| Full HostlistCompiler-style configuration | Useful for v2, but v1 must first make the single AGH output path correct and safe. |
| Web UI or hosted service | The production model is GitHub Actions plus release artifacts. |
| Non-AdGuard output targets | v1 compatibility target is AdGuard Home DNS blocklists. |
| Aggressive pruning when semantics are uncertain | Maximum blocking coverage has priority over minimum rule count. |
| Language rewrite | Python is not proven to be the blocker; correctness, validation, and data flow come first. |
| Exhaustive generated-list diffs in git | `lists/` and `.cache/` are runtime artifacts; use reports, stats, and fixtures instead. |

## Traceability

Which phases cover which requirements. Updated during roadmap creation.

| Requirement | Phase | Status |
|-------------|-------|--------|
| PARS-01 | Phase 1 | Complete |
| PARS-02 | Phase 1 | Complete |
| PARS-03 | Phase 1 | Complete |
| PARS-04 | Phase 1 | Complete |
| DEDUP-01 | Phase 2 | Complete |
| DEDUP-02 | Phase 2 | Complete |
| DEDUP-03 | Phase 2 | Complete |
| DEDUP-04 | Phase 2 | Complete |
| DEDUP-05 | Phase 2 | Complete |
| REL-01 | Phase 1 | Complete |
| REL-02 | Phase 3 | Complete |
| REL-03 | Phase 3 | Pending |
| REL-04 | Phase 3 | Complete |
| REL-05 | Phase 3 | Pending |
| REL-06 | Phase 3 | Complete |
| RUN-01 | Phase 4 | Complete |
| RUN-02 | Phase 4 | Pending |
| RUN-03 | Phase 4 | Pending |
| RUN-04 | Phase 4 | Pending |
| RUN-05 | Phase 4 | Pending |
| PUB-01 | Phase 5 | Pending |
| PUB-02 | Phase 5 | Pending |
| PUB-03 | Phase 5 | Pending |

**Coverage:**
- v1 requirements: 23 total
- Mapped to phases: 23
- Unmapped: 0

---
*Requirements defined: 2026-05-16*
*Last updated: 2026-05-16 after roadmap creation*
