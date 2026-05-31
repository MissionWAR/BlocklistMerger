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

## Artifact Boundary

Generated raw snapshots, manifests, merged outputs, and benchmark reports are
ignored runtime evidence under `reports/benchmarks/**`. They are for local or CI
diagnostics only; do not commit them. Track source changes in `scripts/`,
`tests/`, and docs, then recreate benchmark artifacts when evidence is needed.
