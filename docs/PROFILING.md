# Manual Profiling

RUN-03 profiling uses a dedicated wrapper so the scheduled release pipeline stays compact.
The default path uses only Python stdlib `cProfile` and `pstats`.

## Stdlib Profile Run

```bash
python -m scripts.profile_pipeline lists/_raw --run-id manual-YYYYMMDD
```

The command writes all base artifacts under the ignored report root:

- `reports/profiles/<run-id>/pipeline.cprofile`
- `reports/profiles/<run-id>/pstats-cumulative.txt`
- `reports/profiles/<run-id>/pstats-total-time.txt`
- `reports/profiles/<run-id>/pipeline-stats.json`
- `reports/profiles/<run-id>/merged.txt`

Use `--report-dir` only for a directory that still resolves under `reports/profiles/`.
Run IDs must be a single safe path segment.

## Optional Manual Tools

Optional profiler tooling is manual-only. It is not installed or invoked by the scheduled
`build_validate` workflow.

```bash
python -m pip install -e ".[profile]"
python -m scripts.profile_pipeline lists/_raw --run-id sampled --py-spy-speedscope
python -m scripts.profile_pipeline lists/_raw --run-id dns-check --dns-diagnostics
```

`py-spy` can be requested for speedscope or flamegraph artifacts. `dnspython` can be
requested for a local DNS diagnostics artifact. If a requested optional tool is unavailable,
the wrapper exits nonzero and names the missing manual/profiling-only tool and requested
artifact.

`pyperf` was not approved for tracked dependency metadata or install documentation in the
Task 2 package-legitimacy checkpoint. The wrapper keeps `--pyperf-json` as an explicit
manual request, but no tracked install command is provided for it; unavailable `pyperf`
requests fail with an actionable diagnostic.

## Scheduled Boundary

No manual GitHub Actions profiling workflow is added by default per D-13. Scheduled publish
installs continue to use only the constrained `".[dev]"` dependency set, and the workflow
does not invoke `scripts.profile_pipeline`.

## Disclosure Warning

Profile artifacts are local evidence, not release artifacts. `cProfile` and `pstats` output
can include local source paths, Python function names, and execution details. Keep the
contents under ignored `reports/profiles/` paths unless a maintainer intentionally shares
them for runtime investigation.
