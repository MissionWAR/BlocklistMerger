# Phase 4: Runtime Scaling & Reproducibility - Context

**Gathered:** 2026-05-18
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 4 makes the already safety-pinned pipeline cheaper and more reproducible to run at
large blocklist scale. It covers bounded downloader streaming, lower-risk cleaner/pipeline
memory reductions, obvious compiler allocation cleanup, runtime-size observability, release
dependency reproducibility, and Python 3.13/3.14 compatibility auditing.

This phase does not change blocking semantics, redesign semantic pruning storage, add broad
runtime configuration, turn dependency management into a new toolchain migration, or broaden
public-reuse documentation. Blocking coverage and release safety remain more important than
runtime optimization.

</domain>

<decisions>
## Implementation Decisions

### Downloader Streaming
- **D-01:** Use a cache-primary streamed promotion strategy for successful downloads.
  Stream response bytes into a temporary cache-side file first, then promote to cache/raw
  output only after the full response succeeds.
- **D-02:** Keep old cache/output files intact until a full streamed replacement is ready.
  State updates for ETag, Last-Modified, and fetched_at must happen after successful file
  replacement, not before.
- **D-03:** Reuse bounded copy/hash helpers for 304 Not Modified, HTTP fallback cache,
  timeout fallback cache, and exception fallback cache paths. Phase 4 should remove full
  cache-file reads as well as full response reads.
- **D-04:** Use source-size metrics first instead of hard default byte/content caps. Planner
  may record per-source byte counts and checksums, but should not introduce a default cap
  that could silently reduce coverage from legitimate large upstreams.
- **D-05:** Treat strict content-type checks and hard source-size caps as deferred unless
  implemented as non-default diagnostics or a very high/manual knob. Public blocklist hosts
  can have inconsistent headers, so false source failures are a coverage risk.

### Large-Run Memory Strategy
- **D-06:** Use bounded parallel cleaning as the primary memory strategy. Keep process-level
  parallelism, but avoid returning full cleaned `list[str]` payloads from each worker where
  practical.
- **D-07:** Preserve deterministic sorted-file/chunk ordering even if some workers finish
  earlier. Throughput should not come at the cost of noisy release diffs or nondeterministic
  pipeline behavior.
- **D-08:** Remove obvious compiler waste, especially the unused `abp_blocking_domains`
  allocation produced by `_build_coverage_lookups()`.
- **D-09:** Do not redesign compiler storage with tries, SQLite, partitioned compilation, or
  external sorting in this phase. The compiler's global indexes are semantically important
  for whitelist, wildcard, modifier-aware parent pruning, and deterministic output.
- **D-10:** Deeper compiler storage redesign should be considered only after Phase 4 metrics
  prove current compiler indexes are the dominant memory ceiling.

### Runtime Metrics Surface
- **D-11:** Extend the existing versioned `reports/pipeline-stats.json` surface with a
  `runtime_profile` section instead of adding a separate report family.
- **D-12:** Mirror only key runtime-size fields in the GitHub step summary. Full detail should
  stay in JSON workflow artifacts.
- **D-13:** Runtime metrics are inspect-only in Phase 4. Do not add warning thresholds or hard
  validation gates for runtime, memory, or size yet.
- **D-14:** Useful metrics include phase durations, raw/input/output byte sizes, worker count,
  compiler structure cardinalities, and best-effort peak memory on GitHub Actions. Exact
  field names and platform-specific memory implementation are planner discretion.

### Reproducible Dependencies And Python Compatibility
- **D-15:** Use pip-native generated constraints for reproducible scheduled releases. Keep
  `pyproject.toml` as the human dependency contract and use constraints to pin release
  resolution.
- **D-16:** Do not migrate to `uv` or a new package manager in Phase 4. Do not require a
  hash-pinned install unless planning finds constraints cannot satisfy RUN-04.
- **D-17:** Add a Python 3.13 and 3.14 compatibility audit in CI, but do not lower
  `requires-python` in this phase. Compatibility evidence comes first; changing the declared
  support range is a later explicit decision.
- **D-18:** Runtime/scaling controls should use internal tested defaults and existing CLI
  surfaces where possible. Do not add a broad runtime config file or HostlistCompiler-style
  configuration surface.

### Agent Discretion
- The planner may choose exact chunk sizes, temporary file naming, cleanup helpers, and
  whether bounded cleaning uses per-worker temp files or chunk spools, provided ordering,
  bounded memory, and cleanup behavior are tested.
- The planner may choose exact JSON field names and schema-version bump mechanics for
  pipeline runtime metrics.
- The planner may choose the constraints file layout, such as a single release constraints
  file or Python-version-specific constraints files, as long as the scheduled release install
  is reproducible and CI proves the intended Python audit.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Planning Scope
- `.planning/PROJECT.md` - Core value, v1/v2 boundary, priority order, and safety
  constraints.
- `.planning/REQUIREMENTS.md` - Phase 4 requirement IDs `RUN-01` through `RUN-05`.
- `.planning/ROADMAP.md` - Phase 4 goal, dependencies, and success criteria.
- `.planning/STATE.md` - Current project position. Treat state as current focus for Phase 4;
  the local roadmap progress table may lag after PR #13 merge.
- `.planning/phases/03-release-validation-observability/03-CONTEXT.md` - Phase 3 report,
  validation, artifact, and release-safety decisions that Phase 4 must reuse rather than
  replace.

### Codebase Maps
- `.planning/codebase/STACK.md` - Python, pip, GitHub Actions, dependencies, and missing
  lockfile context.
- `.planning/codebase/ARCHITECTURE.md` - Downloader, pipeline, compiler, report, and workflow
  boundaries.
- `.planning/codebase/CONCERNS.md` - Existing streaming, materialization, unused allocation,
  dependency reproducibility, and Python-version risks.
- `.planning/codebase/CONVENTIONS.md` - Python style, atomic writes, generated artifact rules,
  and testing conventions.

### Source, Workflow, And Tests
- `scripts/downloader.py` - Current full-response reads, cache fallback paths, source-health
  reporting, state writes, and fetch CLI.
- `scripts/pipeline.py` - Process-pool cleaning, full cleaned-list materialization,
  `PipelineStats`, and JSON stats writer.
- `scripts/compiler.py` - Global rule indexes, unused coverage lookup allocation, output
  writer, and compiler stats.
- `scripts/cleaner.py` - Cleaner line processing and discard stats feeding pipeline memory
  strategy.
- `scripts/release_validator.py` - Existing validation summary surface that Phase 4 should
  not expand into runtime gates.
- `.github/workflows/update.yml` - Python setup, dependency installation, reports,
  validation, artifact upload, and scheduled release flow.
- `pyproject.toml` - Declared Python requirement, dependencies, dev dependencies, Ruff target,
  and pytest config.
- `.github/dependabot.yml` - Existing dependency update automation.
- `tests/test_downloader.py` - Downloader source-health and cache behavior tests to extend for
  streamed writes and fallback copies.
- `tests/test_pipeline.py` - Pipeline stats/report behavior to extend for runtime metrics and
  bounded cleaning.
- `tests/test_compiler.py` - Compiler behavior and deterministic output tests to protect while
  removing allocation waste.
- `tests/test_ci_workflow.py` - Workflow static tests to extend for constraints install and
  Python compatibility audit.

### External Specs
- No external local specs were provided. Planning/research should use official docs for
  `aiohttp` streaming, pip constraints/repeatable installs, GitHub Actions Python matrices,
  and Python memory/resource APIs as needed.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `scripts.downloader.save_state()` and `save_source_health_report()` already use temp-file
  replacement patterns that should inform streamed download promotion.
- `scripts.downloader.SourceHealth` already records byte size and SHA-256, so source-size
  metrics can extend existing reporting instead of creating a new policy surface.
- `scripts.pipeline.save_stats_json()` already writes a versioned report consumed by the
  workflow and validator.
- `scripts.compiler.CompileStats` already carries compiler counters and can expose additional
  cardinalities or allocation-related metrics without changing rule semantics.

### Established Patterns
- CLI modules use `main() -> int`, explicit encodings, stderr for recoverable errors, and
  focused pytest coverage.
- Generated files under `lists/`, `.cache/`, and `reports/` are runtime artifacts and should
  not become committed source truth.
- Atomic replacement is preferred for generated state/output integrity.
- Existing tests use small focused fixtures rather than real generated blocklist data.

### Integration Points
- Downloader streaming connects `scripts/downloader.py`, `.cache/`, `lists/_raw/`,
  source-health reports, and `.github/workflows/update.yml`.
- Bounded cleaning connects `scripts/pipeline.py`, `scripts.cleaner.clean_line()`, temporary
  runtime artifacts, compiler input iteration, and deterministic output ordering.
- Runtime metrics connect `scripts/pipeline.py`, `scripts.compiler.CompileStats`,
  `reports/pipeline-stats.json`, workflow artifacts, and GitHub step summaries.
- Reproducible dependencies connect `pyproject.toml`, constraints files, Dependabot, CI
  install commands, `actions/setup-python`, and Python-version test matrices.

</code_context>

<specifics>
## Specific Ideas

- Downloader implementation should use `aiohttp` chunk iteration rather than
  `response.read()`.
- Cache fallback should not read whole cached files into memory before writing raw output.
- The first memory win should target pipeline process-boundary materialization and the known
  unused compiler allocation, not semantic-pruning storage redesign.
- Runtime metrics should explain behavior, not block releases, until the project has real
  historical baseline data.
- The PR #13 Codex connector review fix is merged in Git history at `ba7c1b4`, but it was
  not written into a GSD review artifact. That is expected for a PR/inbox review path unless
  manually folded into phase artifacts.
- Local GSD metadata drift was observed after PR #13: `.planning/STATE.md` points to Phase 4,
  while `.planning/ROADMAP.md` still shows Phase 3 in progress. Repair this through a GSD
  roadmap/state workflow rather than direct manual edits.

</specifics>

<deferred>
## Deferred Ideas

- Hard source-size/content-type release gates are deferred until source-size metrics establish
  safe thresholds.
- Runtime warning or hard gates are deferred until the project has enough baseline data to
  avoid noisy scheduled-release failures.
- Deep compiler storage redesign is deferred until runtime metrics prove it is necessary.
- Hash-pinned dependency installs and `uv` migration are deferred unless constraints prove
  insufficient.
- Lowering `requires-python` below 3.14 is deferred until CI compatibility evidence is
  reviewed in a later explicit decision.
- Broad runtime configuration files and HostlistCompiler-style runtime tuning remain out of
  v1 scope.

</deferred>

---

*Phase: 4-Runtime Scaling & Reproducibility*
*Context gathered: 2026-05-18*
