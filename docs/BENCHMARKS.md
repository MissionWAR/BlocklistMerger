# Benchmarks

RUN-02 benchmark evidence separates downloader and network variability from
cleaner/compiler runtime. The stable path is: fetch local raw inputs and
source-health metadata first, freeze that local input set, then benchmark only
the frozen manifest.

## Create Source Health

Use the existing fetch path to update local raw inputs and source-health
metadata:

```bash
python -m scripts.downloader --sources config/sources.txt --outdir lists/_raw --cache .cache --health-report reports/source-health.json
```

`lists/_raw` is mutable smoke input. It is useful for local freshness checks, but
it is not stable benchmark evidence until it is copied into a frozen manifest.

## Freeze Raw Inputs

Create a frozen snapshot under `reports/benchmarks/frozen/<dataset-id>/`:

```bash
python -m scripts.benchmark_pipeline freeze --input-dir lists/_raw --source-health-report reports/source-health.json --dataset-id local-2026-05-31
```

The command copies only `.txt` raw files to
`reports/benchmarks/frozen/<dataset-id>/raw/` and writes
`reports/benchmarks/frozen/<dataset-id>/manifest.json`. The manifest records the
source URL, filename, byte size, SHA-256, source-health status, cache status,
Python version, package version, git revision, and runner metadata.

## Run Frozen Benchmarks

Benchmark cleaner/compiler runtime from the validated frozen manifest:

```bash
python -m scripts.benchmark_pipeline run-frozen --manifest reports/benchmarks/frozen/<dataset-id>/manifest.json --iterations 3 --report reports/benchmarks/runs/<run-id>/benchmark.json
```

`run-frozen` validates the manifest before each iteration and writes per-run
merged outputs under `reports/benchmarks/runs/<run-id>/`. It does not fetch
network sources and does not treat `lists/_raw` as stable evidence.

## Run Synthetic Checks

Use deterministic synthetic data for CI-friendly sanity checks:

```bash
python -m scripts.benchmark_pipeline run-synthetic --dataset-id synthetic-ci --files 2 --rules-per-file 100 --iterations 1 --report reports/benchmarks/runs/synthetic-ci/benchmark.json
```

Synthetic data exercises the same benchmark wrapper path with fixed arithmetic
inputs. It is a loose sanity guard, not a hardware benchmark.

## Corpus Benchmark Harness (scripts/benchmark.py)

`scripts.benchmark` is a median-of-N wall-clock benchmark of `compile_rules()`
run directly over a corpus directory. It self-pins its input through a
hash-in-place corpus manifest computed at run time, so it does not require the
freeze step used by `scripts.benchmark_pipeline`. The two tools complement each
other: frozen-manifest runs produce stable evidence sets, while this harness
produces repeatable timing, memory, profile, and baseline-comparison legs over
whatever is currently fetched.

Timing leg (median over N runs):

```bash
python -m scripts.benchmark --corpus lists/_raw --runs 3 --json reports/benchmarks/runs/<run-id>/benchmark.json
```

Memory and profile legs replace timing mode in their own invocations:

```bash
python -m scripts.benchmark --corpus lists/_raw --json reports/benchmarks/runs/<run-id>/memory.json --track-memory --memory-top 20
python -m scripts.benchmark --corpus lists/_raw --json reports/benchmarks/runs/<run-id>/profile.json --profile
```

`--track-memory` ignores `--runs` and records tracemalloc peak numbers instead
of wall-clock medians. `--profile` runs exactly one compile under cProfile and
writes a `.pstats` artifact beside the JSON target. Neither leg combines with
timing summaries or memory numbers.

To compare against the tracked reference, run a fresh timing leg with
`--compare-baseline`:

```bash
python -m scripts.benchmark --corpus lists/_raw --runs 3 --json reports/benchmarks/runs/<run-id>/post.json --compare-baseline
```

The comparison target defaults to the tracked baseline at
`tests/fixtures/benchmarks/corpus-baseline.json`; an optional path argument
selects a different baseline report. `--compare PRE POST` performs a
document-only comparison of two existing timing reports and writes nothing.
Comparisons exit nonzero unless the measured improvement meets
`--min-improve-percent`, an inclusive floor that defaults to 15.

`tests/fixtures/benchmarks/corpus-baseline.json` pins the v1.2 POST-flip,
pre-optimization reference: `median_seconds` 752.35524 over 3 runs and
`tracemalloc_peak_bytes` 2,513,219,430, hash-pinned to the corpus manifest
SHA-256 `ecd3b624...`. Compare mode re-detects corpus drift by this manifest
digest before any improvement claim is evaluated.

### v1.2 Results

On the pinned 6,246,486-record production corpus, enabling denyallow-aware
TLD-wildcard pruning removes 518,475 provably-covered rules, roughly 20% of
the merged.txt output, with blocking behavior verified identical by a
full-corpus shadow-equivalence gate. Subsequent profile-guided work (an
order-preserving exception-domain index and single-classification parse
consolidation) cut median compile time by 67.71% against that baseline
(752.355 s -> 242.946 s median-of-3) with byte-identical output confirmed by
SHA-256 anchors on both sides. These figures are measurements from one
maintainer machine on the pinned corpus; like all benchmark artifacts they are
local evidence under the Artifact Boundary below, not universal performance
claims.

## Artifact Boundary

Generated raw snapshots, manifests, merged outputs, and benchmark reports are
ignored runtime evidence under `reports/benchmarks/**`. They are for local or CI
diagnostics only; do not commit them. Track source changes in `scripts/`,
`tests/`, and docs, then recreate benchmark artifacts when evidence is needed.
