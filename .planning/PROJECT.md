# Blocklist Merger

## What This Is

Blocklist Merger is a Python-based AdGuard Home blocklist compiler that fetches many public DNS blocklists, cleans unsupported rules, compresses multiple input formats into AdGuard-compatible ABP-style rules, deduplicates safely, and publishes one merged list through GitHub Actions.

The project is built primarily for the maintainer's own AdGuard Home instance, where using many upstream lists directly would create excessive duplicates and load overhead. It is public so other people can use or fork the same workflow, but v1 is not trying to become a broad configuration platform.

## Core Value

Produce one safe, compact, AdGuard Home-compatible blocklist that preserves maximum blocking coverage while removing only rules that are truly redundant.

## Requirements

### Validated

- Existing fetch pipeline downloads configured upstream blocklists from `config/sources.txt` into `lists/_raw/` with HTTP cache support.
- Existing clean pipeline removes comments, empty lines, cosmetic rules, and browser-only modifiers before compilation.
- Existing compiler compresses hosts/plain-domain inputs into ABP-style rules so equivalent domains can deduplicate across formats.
- Existing deduplication removes exact duplicates and parent-covered subdomains for normal blocking rules.
- Existing whitelist handling removes blocked domains that are covered by whitelist rules.
- Existing GitHub Actions workflow runs every 12 hours and publishes `lists/merged.txt` to the `latest` release.
- Existing tests cover cleaner, compiler, downloader helpers, pipeline behavior, fixtures, and performance sanity checks.
- Existing documentation records the priority order: maximum blocking coverage, minimum rule count, AdGuard Home compatibility, and GitHub Actions friendliness.
- Phase 04 validated bounded downloader streaming, ordered cleaner spooling, compiler runtime cardinality metrics, and schema 2 runtime profiles without adding release gates.
- Phase 04 validated pinned release constraints for Python 3.14 and a read-only Python 3.13/3.14 compatibility audit, including a successful live GitHub Actions `workflow_dispatch` smoke check.

### Active

- [ ] Improve deduplication correctness so scoped or behavior-changing AdGuard modifiers are never pruned unsafely.
- [ ] Improve cleaner/compiler agreement around URL path rules, regex rules, and modifiers containing slash-like values.
- [ ] Add CI quality gates so tests and lint run before scheduled release publishing.
- [ ] Add stronger release validation beyond minimum output line count, including source health, output deltas, and canary allow/block checks.
- [ ] Keep public reuse lightweight in v1 through clearer docs, safer defaults, and fork-friendly knobs where they directly support the main workflow.

### Out of Scope

- Full HostlistCompiler-style configuration platform in v1 - desirable for a later v2 direction, but current work should improve the main pipeline first.
- Web UI or hosted service - the production model is GitHub Actions plus release artifact, not an interactive application.
- Supporting non-AdGuard Home output targets in v1 - compatibility priority is AdGuard Home DNS blocklists.
- Maximum rule reduction at the expense of blocking coverage - when in doubt, preserve rules.
- Rewriting the project in another language before profiling proves Python is the blocker - correctness and data-flow improvements come first.

## Context

The project exists because adding many public DNS blocklists directly to AdGuard Home creates large overlap and redundant rules. The intended workflow is to maintain a source catalog, fetch upstream lists automatically, merge them into one deduplicated output, and point AdGuard Home at the published `merged.txt` release asset.

The documented priority order is:

1. Maximum blocking coverage: every domain that should be blocked is blocked.
2. Minimum rule count: smaller lists load faster and use less memory in AdGuard Home.
3. AdGuard Home compatibility: output only rules AGH understands.
4. GitHub Actions friendliness: scheduled runs every 12 hours with minimal resource usage.

The current architecture is a layered CLI pipeline:

- `scripts/downloader.py` handles async source downloads and caching.
- `scripts/cleaner.py` filters raw rules down to DNS-level candidates.
- `scripts/pipeline.py` orchestrates multiprocess cleaning and compilation.
- `scripts/compiler.py` parses, compresses, deduplicates, prunes, and writes output.
- `.github/workflows/update.yml` is the main production runtime.

The project is public, but personal-first. Public improvements should make the existing workflow safer and easier to fork rather than turning v1 into a general-purpose product. A future v2 can explore a HostlistCompiler-like direction with richer configuration points, but only after the core pipeline is trustworthy.

Known improvement themes from the codebase map:

- Deduplication must preserve modifier semantics, especially `client`, `ctag`, `dnsrewrite`, `denyallow`, `badfilter`, and `important`.
- Cleaner and compiler rules are regex-heavy and need focused regression tests for every behavior change.
- The release workflow should run tests/lint and validate output semantics before publishing.
- Runtime scaling work now streams large downloads, spools cleaned rules across process boundaries, records inspect-only runtime metrics, and gives live GitHub Actions runs enough timeout headroom for the current production dataset.
- Generated data under `lists/`, `.cache/`, and `__pycache__/` is runtime output, not source truth.

## Constraints

- **Primary runtime**: GitHub Actions is the production environment because the project is designed to rebuild and publish automatically every 12 hours.
- **Primary target**: AdGuard Home DNS blocklists; browser-only ABP behavior should not leak into output.
- **Priority order**: Blocking coverage beats smaller output; smaller output beats cosmetic optimization.
- **Language**: Python is the current implementation language and remains the default unless profiling shows a hard limitation.
- **Python version**: Python 3.14 is the current declared requirement, chosen for modern language features; compatibility with older versions should be audited before changing.
- **Public scope**: External users are supported through docs and fork-friendly behavior, but v1 should not become a full configurable compiler platform.
- **Generated artifacts**: Large blocklist outputs and raw downloads should remain generated/runtime artifacts and should not drive source-level changes.
- **Safety**: Release validation must prevent overblocking, catastrophic source failures, and unsafe deduplication from reaching the public artifact.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Keep v1 focused on the main blocklist compiler pipeline | The project's value is the quality of the merged AGH list, not breadth of product features | Pending |
| Treat correctness as the first milestone priority | Unsafe pruning can reduce blocking coverage or change rule semantics, which violates the core value | Pending |
| Keep public reuse lightweight for now | The repo is public, but the maintainer's AGH/GitHub Actions workflow remains primary | Pending |
| Defer HostlistCompiler-like configurability to v2 | Rich configuration is useful later, but would distract from v1 pipeline reliability | Pending |
| Audit Python version before broadening support | Python 3.14 was chosen intentionally, but public usability may benefit from 3.12/3.13 if feasible | Pending |
| Do not rewrite away from Python without profiling evidence | The current risks are correctness, CI, validation, and data flow; language speed is not yet proven to be the blocker | Pending |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** via `$gsd-transition`:
1. Requirements invalidated? Move to Out of Scope with reason.
2. Requirements validated? Move to Validated with phase reference.
3. New requirements emerged? Add to Active.
4. Decisions to log? Add to Key Decisions.
5. "What This Is" still accurate? Update if drifted.

**After each milestone** via `$gsd-complete-milestone`:
1. Full review of all sections.
2. Core Value check: still the right priority?
3. Audit Out of Scope: reasons still valid?
4. Update Context with current state.

---
*Last updated: 2026-05-20 after Phase 04 completion*
