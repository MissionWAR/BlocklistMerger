# Runtime Language Gate

This decision record is the RUN-04 gate for discussing any future implementation
language change. It is a gate for evidence and review, not a rewrite plan, a
prototype request, or a scheduled release blocker.

## Policy Baseline

- D-14: Python remains the default implementation language for the fetch, clean,
  compile, validate, and publish pipeline.
- D-15: Python is acceptable while the frozen-input p95 benchmark time and the
  scheduled `build_validate` job time both stay below the 2x headroom threshold:
  half of the current 30-minute CI timeout, or 15 minutes.
- D-15: Runtime evidence must also show memory and disk use staying inside the
  production GitHub-hosted runner envelope used by the scheduled workflow.
- Runtime diagnostics, benchmark outputs, profile outputs, and language-gate
  evidence remain inspect-only in Phase 10. They do not create release findings
  or scheduled hard gates.

## Required Evidence Before Rewrite Discussion

A rewrite discussion is blocked until all D-16 evidence exists and still points
to a hard Python/runtime limitation after algorithmic fixes have been considered:

1. Frozen-input benchmark evidence that excludes downloader and network
   variance, including p95 timing from the benchmark runner.
2. Scheduled runner evidence from the production `build_validate` job, including
   elapsed job time and runner resource fit.
3. Stdlib profile output generated with `cProfile` and `pstats`, so hot paths are
   attributed before language speed is debated.
4. Optional profiler artifacts where useful, kept manual and outside scheduled
   publish installs.
5. Review notes showing algorithmic fixes were considered before language
   replacement.
6. Proof that the remaining bottleneck is a hard Python/runtime limitation, not
   code structure, IO shape, fixture choice, or missing cache/source-health
   evidence.

## Correctness Before Speed

Any non-Python candidate must satisfy D-17 before speed is considered:

- AGH correctness must remain intact, including modifier and exception behavior.
- Coverage proof expectations must show no lost/changed coverage.
- Release-validation evidence must remain at least as strong as the Python path.
- Output parity must be stable where parity is expected.
- The proof-ledger must not be weakened or bypassed.

Speed measurements are meaningful only after those checks pass.

## Candidate Direction

If the gate fails after the evidence above is collected:

- Go is the first candidate for persistent CPU-bound string/set work.
- Rust is the candidate for hard memory/RSS or allocation-control limits.
- JavaScript and TypeScript are only candidates for contributor or tooling
  integration. They are not preferred for raw cleaner/compiler performance.

The candidate direction follows the evidence. It is not permission to add
tracked rewrite artifacts, compiler prototypes, or scheduled toolchain installs.

## Generated Evidence Boundary

Benchmark and profile evidence is runtime data, not source truth:

- Frozen raw snapshots, benchmark manifests produced from local raw data,
  benchmark reports, merged benchmark outputs, and repeated-run JSON belong
  under ignored `reports/benchmarks` paths or other ignored runtime paths.
- `pipeline.cprofile`, `pstats` summaries, optional profiler dumps,
  speedscope/flamegraph files, profile `pipeline-stats.json`, and profiled
  merged outputs belong under ignored `reports/profiles` paths.
- Generated evidence can be cited in maintainer review, but source changes must
  track only stable docs, schema/contracts, scripts, and tests.

## Sources

- Phase 10 decisions D-14 through D-18:
  `.planning/phases/10-runtime-language-evidence/10-CONTEXT.md`
- Runtime evidence summary:
  `.planning/phases/10-runtime-language-evidence/10-01-SUMMARY.md`
- Frozen benchmark summary:
  `.planning/phases/10-runtime-language-evidence/10-02-SUMMARY.md`
- Profiling summary:
  `.planning/phases/10-runtime-language-evidence/10-03-SUMMARY.md`
- AGH correctness baseline: `docs/AGH_SEMANTICS.md`
- Public scope boundary: `docs/SCOPE.md`
