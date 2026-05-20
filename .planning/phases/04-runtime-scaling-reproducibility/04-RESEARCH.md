# Phase 04: Runtime Scaling & Reproducibility - Research

**Researched:** 2026-05-18
**Domain:** Python async downloader streaming, pipeline memory reduction, runtime metrics, pip constraints, GitHub Actions Python compatibility audit
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

Copied verbatim from `.planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md`. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md]

### Locked Decisions

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

### the agent's Discretion
- The planner may choose exact chunk sizes, temporary file naming, cleanup helpers, and
  whether bounded cleaning uses per-worker temp files or chunk spools, provided ordering,
  bounded memory, and cleanup behavior are tested.
- The planner may choose exact JSON field names and schema-version bump mechanics for
  pipeline runtime metrics.
- The planner may choose the constraints file layout, such as a single release constraints
  file or Python-version-specific constraints files, as long as the scheduled release install
  is reproducible and CI proves the intended Python audit.

### Deferred Ideas (OUT OF SCOPE)

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
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| RUN-01 | Downloader writes large responses through bounded streaming and atomic replacement instead of full-response buffering. [VERIFIED: .planning/REQUIREMENTS.md] | Use `aiohttp` response streaming with `resp.content.iter_chunked()` and sibling temp-file promotion; remove full `response.read()` and cache `read()` fallback paths. [VERIFIED: Context7 /aio-libs/aiohttp] [CITED: https://docs.aiohttp.org/en/stable/client_quickstart.html] [VERIFIED: scripts/downloader.py] |
| RUN-02 | Cleaner and pipeline processing avoid unnecessary full-list materialization where practical. [VERIFIED: .planning/REQUIREMENTS.md] | Replace process-boundary `list[str]` returns with ordered per-file or chunk spools while keeping sorted file order and `clean_line()` semantics. [VERIFIED: scripts/pipeline.py] [VERIFIED: scripts/cleaner.py] |
| RUN-03 | Compiler removes unused allocations and records runtime-size metrics for large runs. [VERIFIED: .planning/REQUIREMENTS.md] | Remove unused `abp_blocking_domains`, add compiler cardinalities to `CompileStats`/`runtime_profile`, and record best-effort memory through stdlib APIs. [VERIFIED: scripts/compiler.py] [CITED: https://docs.python.org/3/library/tracemalloc.html] [CITED: https://docs.python.org/3.14/library/resource.html] |
| RUN-04 | Release dependencies are reproducible through a lockfile or constraints file. [VERIFIED: .planning/REQUIREMENTS.md] | Use pip constraints in the scheduled release install and keep `pyproject.toml` as the human contract. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md] [CITED: https://pip.pypa.io/en/stable/user_guide/#constraints-files] |
| RUN-05 | Maintainer can audit Python 3.13/3.14 compatibility through CI before changing `requires-python`. [VERIFIED: .planning/REQUIREMENTS.md] | Add a separate CI audit matrix for Python 3.13 and 3.14; keep release publishing on 3.14 and keep `requires-python = ">=3.14"` unchanged. [VERIFIED: pyproject.toml] [CITED: https://docs.github.com/en/actions/tutorials/build-and-test-code/python] |
</phase_requirements>

## Project Constraints (from AGENTS.md)

- Preserve the project priority order: blocking coverage beats smaller output, smaller output beats cosmetic optimization. [VERIFIED: AGENTS.md]
- Keep GitHub Actions as the production runtime for scheduled 12-hour rebuilds and publishing. [VERIFIED: AGENTS.md]
- Keep Python as the implementation language unless profiling proves a hard limitation. [VERIFIED: AGENTS.md]
- Keep Python 3.14 as the declared requirement until compatibility evidence supports a later explicit change. [VERIFIED: AGENTS.md] [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md]
- Treat `lists/`, `lists/_raw/`, `.cache/`, and `__pycache__/` as generated/runtime artifacts, not source truth. [VERIFIED: AGENTS.md]
- Use Ruff-backed 100-column Python style, modern type syntax, explicit encodings, and atomic writes for generated state/output files. [VERIFIED: AGENTS.md] [VERIFIED: pyproject.toml]
- Keep CLI modules testable through `main() -> int`, stderr for recoverable warnings, and focused pytest coverage. [VERIFIED: AGENTS.md]
- Do not make direct repo edits outside a GSD workflow unless explicitly bypassed; this research artifact is produced by the active GSD phase workflow. [VERIFIED: AGENTS.md] [VERIFIED: gsd-sdk query init.phase-op 04]

## Summary

Phase 04 should be planned as a conservative runtime hardening layer over the Phase 01-03 correctness and release-safety work. [VERIFIED: .planning/STATE.md] [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md] The primary implementation work is in `scripts/downloader.py`, `scripts/pipeline.py`, `scripts/compiler.py`, `scripts/release_validator.py`, `.github/workflows/update.yml`, `pyproject.toml`, and existing focused tests. [VERIFIED: codebase grep]

The downloader has the clearest mandatory change: `fetch_url()` currently uses `await response.read()` for successful downloads and reads whole cached files during 304/error/timeout fallback paths. [VERIFIED: scripts/downloader.py] `aiohttp` documents chunked response iteration through `resp.content.iter_chunked(chunk_size)` as the large-response pattern because `read()`, `json()`, and `text()` load the whole body into memory. [VERIFIED: Context7 /aio-libs/aiohttp] [CITED: https://docs.aiohttp.org/en/stable/client_quickstart.html]

The pipeline/compiler work should target proven waste before structural rewrites. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md] `_clean_single_file()` currently returns full cleaned `list[str]` payloads from worker processes, and `_build_coverage_lookups()` currently returns an unused `abp_blocking_domains` set. [VERIFIED: scripts/pipeline.py] [VERIFIED: scripts/compiler.py] Runtime metrics should extend `reports/pipeline-stats.json` with inspect-only `runtime_profile` data and should not become release gates in this phase. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md]

**Primary recommendation:** Plan three implementation waves: downloader streaming/copy helpers, bounded ordered cleaning plus compiler metric cleanup, then constraints-backed release CI plus Python 3.13/3.14 audit. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md] [VERIFIED: codebase grep]

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|--------------|----------------|-----------|
| Bounded source downloads | Source Fetch Layer (`scripts/downloader.py`) | Generated cache/raw storage | HTTP bytes enter through the downloader, and cache/raw promotion is downloader-owned. [VERIFIED: scripts/downloader.py] [VERIFIED: .planning/codebase/ARCHITECTURE.md] |
| Ordered bounded cleaning | Processing Orchestrator (`scripts/pipeline.py`) | Cleaner (`scripts/cleaner.py`) | The pipeline owns worker orchestration and deterministic source-file order; the cleaner owns single-line decisions. [VERIFIED: scripts/pipeline.py] [VERIFIED: scripts/cleaner.py] |
| Compiler allocation cleanup | Deduplication Engine (`scripts/compiler.py`) | Pipeline stats projection | Compiler owns global rule indexes and `CompileStats`; pipeline only projects compiler counters into JSON. [VERIFIED: scripts/compiler.py] [VERIFIED: scripts/pipeline.py] |
| Runtime-size reporting | Pipeline report surface (`reports/pipeline-stats.json`) | GitHub step summary | Phase context locks `runtime_profile` into the existing pipeline stats family and mirrors only key fields in the summary. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md] [VERIFIED: .github/workflows/update.yml] |
| Reproducible release dependencies | CI workflow and pip constraints | `pyproject.toml` | `pyproject.toml` remains the human dependency contract while the scheduled release install uses constraints for pinned resolution. [VERIFIED: pyproject.toml] [CITED: https://pip.pypa.io/en/stable/user_guide/#constraints-files] |
| Python 3.13/3.14 audit | CI compatibility job | Ruff/pytest configuration | GitHub Actions supports matrix Python versions, while `requires-python` remains unchanged until audit evidence is reviewed. [CITED: https://docs.github.com/en/actions/tutorials/build-and-test-code/python] [VERIFIED: pyproject.toml] |

## Standard Stack

### Core

| Library / Tool | Version | Purpose | Why Standard |
|----------------|---------|---------|--------------|
| CPython | Declared `>=3.14`; release workflow currently uses `3.14`. [VERIFIED: pyproject.toml] [VERIFIED: .github/workflows/update.yml] | Runtime for downloader, cleaner, compiler, validator, and CI. [VERIFIED: .planning/codebase/STACK.md] | Locked project runtime; audit 3.13 before changing the declaration. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md] |
| `aiohttp` | Declared `>=3.13.5`; PyPI shows 3.13.5 uploaded 2026-03-31 with CPython 3.13 and 3.14 wheels. [VERIFIED: pyproject.toml] [VERIFIED: PyPI search pypi.org/project/aiohttp/] | Async HTTP client and streaming response API. [VERIFIED: scripts/downloader.py] | Official docs recommend `resp.content.iter_chunked()` for large downloads instead of whole-body reads. [VERIFIED: Context7 /aio-libs/aiohttp] [CITED: https://docs.aiohttp.org/en/stable/client_quickstart.html] |
| `aiofiles` | Declared `>=25.1.0`; PyPI shows 25.1.0 uploaded 2025-10-09. [VERIFIED: pyproject.toml] [VERIFIED: PyPI search pypi.org/project/aiofiles/] | Existing async file I/O for downloader cache/output writes. [VERIFIED: scripts/downloader.py] | Fits current async downloader style without adding a new dependency. [VERIFIED: scripts/downloader.py] |
| `tldextract` | Declared `>=5.3.1`; PyPI shows 5.3.1 uploaded 2025-12-28 and classifiers include Python 3.13/3.14. [VERIFIED: pyproject.toml] [VERIFIED: PyPI search pypi.org/project/tldextract/] | Public-suffix-aware domain parsing in compiler pruning. [VERIFIED: scripts/compiler.py] | Existing semantic dedup logic depends on suffix-aware parent walking; do not replace in this phase. [VERIFIED: scripts/compiler.py] [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md] |
| pip constraints | pip docs v26.1.1 | Reproducible release dependency resolution. [CITED: https://pip.pypa.io/en/stable/user_guide/#constraints-files] | Constraints control installed versions without becoming the human dependency contract. [CITED: https://pip.pypa.io/en/stable/user_guide/#constraints-files] [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md] |
| GitHub Actions `actions/setup-python` | Workflow pins v6.2.0 by SHA. [VERIFIED: .github/workflows/update.yml] | CI Python setup, pip cache, and Python version matrix. [VERIFIED: .github/workflows/update.yml] | Official GitHub docs show Python matrix patterns; setup-python documents pip cache and dependency-file cache keys. [CITED: https://docs.github.com/en/actions/tutorials/build-and-test-code/python] [CITED: https://github.com/actions/setup-python] |

### Supporting

| Library / Tool | Version | Purpose | When to Use |
|----------------|---------|---------|-------------|
| `pytest` | Declared `>=9.0.3`; PyPI shows 9.0.3 uploaded 2026-04-07. [VERIFIED: pyproject.toml] [VERIFIED: PyPI search pypi.org/project/pytest/] | Regression tests for streaming fallback, bounded cleaning, stats JSON, compiler metrics, and workflow assertions. [VERIFIED: tests/] | Required for validation architecture and CI audit. [VERIFIED: pyproject.toml] |
| Ruff | Declared `>=0.15.10`; PyPI search shows 0.15.13 released 2026-05-14, while current pyproject lower bound is 0.15.10. [VERIFIED: pyproject.toml] [VERIFIED: PyPI search pypi.org/project/ruff/] | Lint gate and Python target-version audit. [VERIFIED: pyproject.toml] | Use existing `python -m ruff check .`; CI can add `--target-version=py313` in audit mode if planner wants syntax-specific signal. [CITED: https://docs.github.com/en/actions/tutorials/build-and-test-code/python] [VERIFIED: Context7 /astral-sh/ruff] |
| `tracemalloc` | Python stdlib. [CITED: https://docs.python.org/3/library/tracemalloc.html] | Optional Python allocation peak metrics. [CITED: https://docs.python.org/3/library/tracemalloc.html] | Use only when metric overhead is acceptable; docs note storing more frames increases memory and CPU overhead. [CITED: https://docs.python.org/3/library/tracemalloc.html] |
| `resource` | Python stdlib, Unix availability. [CITED: https://docs.python.org/3.14/library/resource.html] | Best-effort peak resident set metrics on Ubuntu GitHub runners. [CITED: https://docs.python.org/3.14/library/resource.html] | Use for CI/runtime profile on Linux; record field/unit explicitly and degrade gracefully elsewhere. [CITED: https://docs.python.org/3.14/library/resource.html] |
| `pathlib.Path.replace()` | Python stdlib. [CITED: https://docs.python.org/3.14/library/pathlib.html] | Atomic-style sibling temp promotion already used by project reports/output. [VERIFIED: scripts/downloader.py] [VERIFIED: scripts/compiler.py] [VERIFIED: scripts/release_validator.py] | Use for temp-to-final promotion after a successful full write. [CITED: https://docs.python.org/3.14/library/pathlib.html] |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| pip constraints | `uv`, Poetry, or another resolver/lock workflow | Explicitly deferred; adding a new toolchain would expand Phase 04 beyond the locked decision. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md] |
| Inspect-only runtime metrics | Runtime thresholds or hard gates | Explicitly deferred until baseline data exists. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md] |
| Per-worker temp/chunk spools | Trie, SQLite, external sort, or partitioned compiler | Deep compiler storage redesign is deferred until metrics show current indexes are the dominant memory ceiling. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md] |
| Source-size metrics | Hard default byte caps or strict content-type checks | Default caps/checks can cause false source failures and reduce coverage; diagnostics are acceptable, gates are deferred. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md] |

**Installation:**
```bash
python -m pip install -q -c constraints/release-py314.txt ".[dev]"
```
This command pattern is recommended for the release job after a constraints file exists. [CITED: https://pip.pypa.io/en/stable/user_guide/#constraints-files] [VERIFIED: .github/workflows/update.yml]

**Version verification:** Local `python` and `pip` could not launch in this sandbox because both resolve to WindowsApps/PyManager aliases that fail with `0x80070520` or a logon-session error. [VERIFIED: shell probe] Package versions above were verified from `pyproject.toml`, official docs, and PyPI search results instead of local `pip index`. [VERIFIED: pyproject.toml] [VERIFIED: PyPI search pypi.org]

## Package Legitimacy Audit

> Phase 04 should not introduce new external runtime packages. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md] Existing dependencies are already declared in `pyproject.toml`; slopcheck was not run because local Python/pip is unavailable and no new package install is recommended. [VERIFIED: pyproject.toml] [VERIFIED: shell probe]

| Package | Registry | Age / Current Evidence | Downloads | Source Repo | slopcheck | Disposition |
|---------|----------|------------------------|-----------|-------------|-----------|-------------|
| `aiohttp` | PyPI | 3.13.5 uploaded 2026-03-31. [VERIFIED: PyPI search pypi.org/project/aiohttp/] | Not checked. [ASSUMED] | `aio-libs/aiohttp` via official docs/Context7. [VERIFIED: Context7 /aio-libs/aiohttp] | Not run. [VERIFIED: shell probe] | Approved existing dependency; no new install decision. [VERIFIED: pyproject.toml] |
| `aiofiles` | PyPI | 25.1.0 uploaded 2025-10-09. [VERIFIED: PyPI search pypi.org/project/aiofiles/] | Not checked. [ASSUMED] | PyPI provenance references `Tinche/aiofiles`. [VERIFIED: PyPI search pypi.org/project/aiofiles/] | Not run. [VERIFIED: shell probe] | Approved existing dependency; no new install decision. [VERIFIED: pyproject.toml] |
| `tldextract` | PyPI | 5.3.1 uploaded 2025-12-28. [VERIFIED: PyPI search pypi.org/project/tldextract/] | Not checked. [ASSUMED] | PyPI project page identifies project metadata and maintainer; source repo URL not independently opened. [VERIFIED: PyPI search pypi.org/project/tldextract/] | Not run. [VERIFIED: shell probe] | Approved existing dependency; no new install decision. [VERIFIED: pyproject.toml] |
| `pytest` | PyPI | 9.0.3 uploaded 2026-04-07. [VERIFIED: PyPI search pypi.org/project/pytest/] | Not checked. [ASSUMED] | PyPI provenance references `pytest-dev/pytest`. [VERIFIED: PyPI search pypi.org/project/pytest/] | Not run. [VERIFIED: shell probe] | Approved existing dev dependency; no new install decision. [VERIFIED: pyproject.toml] |
| `ruff` | PyPI | Current search shows 0.15.13 released 2026-05-14; project declares `>=0.15.10`. [VERIFIED: PyPI search pypi.org/project/ruff/] [VERIFIED: pyproject.toml] | Not checked. [ASSUMED] | `astral-sh/ruff` via official docs/Context7. [VERIFIED: Context7 /astral-sh/ruff] | Not run. [VERIFIED: shell probe] | Approved existing dev dependency; constraints should pin exact release result. [VERIFIED: pyproject.toml] |

**Packages removed due to slopcheck [SLOP] verdict:** none; no new packages recommended. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md]
**Packages flagged as suspicious [SUS]:** none from this research; slopcheck unavailable locally. [VERIFIED: shell probe]

## Architecture Patterns

### System Architecture Diagram

```text
Configured URLs
    |
    v
scripts.downloader.fetch_all()
    |
    +--> fetch_url(url)
          |
          +--> HTTP 304? -----------> bounded copy cache -> raw temp -> raw final
          |
          +--> HTTP error/timeout? --> bounded copy cache -> raw temp -> raw final OR failed
          |
          +--> HTTP 2xx -----------> stream chunks -> cache temp -> cache final
                                      -> bounded copy cache final -> raw temp -> raw final
                                      -> update state after replacements
                                      -> source health bytes/checksum
    |
    v
lists/_raw/*.txt
    |
    v
scripts.pipeline.process_files()
    |
    +--> sorted file order
    +--> bounded process cleaning to ordered spool/chunks
    +--> lazy iterator into scripts.compiler.compile_rules()
             |
             +--> semantic global indexes preserved
             +--> remove unused lookup allocation
             +--> record cardinalities/durations/memory
             +--> atomic output write
    |
    v
reports/pipeline-stats.json + lists/merged.txt
    |
    v
release_validator consumes existing stats + source health + output + canaries
```

This diagram follows the current downloader -> raw files -> pipeline -> compiler -> reports/output architecture and keeps release validation as a consumer rather than a runtime-gate owner for new metrics. [VERIFIED: .planning/codebase/ARCHITECTURE.md] [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md]

### Recommended Project Structure

```text
constraints/
└── release-py314.txt        # generated pip constraints for scheduled release install
scripts/
├── downloader.py            # streamed response and bounded file-copy helpers
├── pipeline.py              # bounded ordered cleaning and runtime_profile JSON writer
├── compiler.py              # allocation cleanup and compiler cardinality metrics
└── release_validator.py     # schema compatibility update; no runtime gates
tests/
├── test_downloader.py       # streaming, temp promotion, fallback copy tests
├── test_pipeline.py         # runtime_profile and bounded ordering tests
├── test_compiler.py         # allocation/metric regression tests
└── test_ci_workflow.py      # constraints install and Python audit matrix assertions
.github/workflows/update.yml # release constraints install, summary fields, compatibility audit
```

The paths above match existing ownership boundaries and add only a constraints file/directory as a new source artifact. [VERIFIED: codebase grep] [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md]

### Pattern 1: Stream Successful Downloads Into Cache-Side Temp Files

**What:** Use `resp.content.iter_chunked(chunk_size)` to write chunks to a temporary cache file while updating byte count and checksum. [VERIFIED: Context7 /aio-libs/aiohttp] [CITED: https://docs.aiohttp.org/en/stable/client_quickstart.html]
**When to use:** Use for HTTP 2xx responses after status handling and before state updates. [VERIFIED: scripts/downloader.py]
**Example:**
```python
# Source: aiohttp client quickstart streaming pattern and existing downloader style.
async def _stream_response_to_file(response, temp_path: Path, chunk_size: int) -> tuple[int, str]:
    digest = hashlib.sha256()
    byte_count = 0

    async with aiofiles.open(temp_path, "wb") as file:
        async for chunk in response.content.iter_chunked(chunk_size):
            if not chunk:
                continue
            byte_count += len(chunk)
            digest.update(chunk)
            await file.write(chunk)

    return byte_count, digest.hexdigest()
```

The planner should add cleanup for abandoned temp files and update state only after cache and raw final files are replaced. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md] [VERIFIED: scripts/downloader.py]

### Pattern 2: Bounded Cache Copy For 304 And Fallback Paths

**What:** Copy from cache to raw output in chunks instead of reading the whole cache file. [VERIFIED: scripts/downloader.py]
**When to use:** Use for 304 Not Modified, HTTP fallback cache, timeout fallback cache, and exception fallback cache paths. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md]
**Example:**
```python
# Source: existing aiofiles usage in scripts/downloader.py.
async def _copy_file_bounded(src_path: Path, dst_temp_path: Path, chunk_size: int) -> tuple[int, str]:
    digest = hashlib.sha256()
    byte_count = 0

    async with aiofiles.open(src_path, "rb") as src, aiofiles.open(dst_temp_path, "wb") as dst:
        while chunk := await src.read(chunk_size):
            byte_count += len(chunk)
            digest.update(chunk)
            await dst.write(chunk)

    return byte_count, digest.hexdigest()
```

This helper should replace the current fallback blocks that call `await src.read()` before writing. [VERIFIED: scripts/downloader.py]

### Pattern 3: Ordered Bounded Cleaning Through Per-File Spools

**What:** Keep `ProcessPoolExecutor` but have workers write cleaned output to per-input temp files or bounded chunk spools, returning a small stats record plus spool path instead of `list[str]`. [VERIFIED: scripts/pipeline.py] [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md]
**When to use:** Use when cleaning must remain parallel but parent memory should not scale with the largest cleaned file payload. [VERIFIED: .planning/codebase/CONCERNS.md]
**Example:**
```python
# Source: existing _clean_single_file/process_files boundary.
class CleanWorkerResult(NamedTuple):
    source_index: int
    spool_path: Path
    stats: dict[str, int]


def _clean_single_file_to_spool(item: tuple[int, Path, Path]) -> CleanWorkerResult:
    source_index, file_path, spool_dir = item
    spool_path = spool_dir / f"{source_index:05d}-{file_path.stem}.cleaned"
    file_stats = _empty_clean_stats()

    with open(file_path, encoding="utf-8-sig", errors="replace") as src, open(
        spool_path, "w", encoding="utf-8", newline="\n"
    ) as dst:
        for line in src:
            result, was_trimmed = clean_line(line)
            _update_clean_stats(file_stats, result, was_trimmed)
            if not result.discarded:
                dst.write(result.line + "\n")

    return CleanWorkerResult(source_index, spool_path, file_stats)
```

The parent should consume results in sorted source order and unlink spools after successful compiler iteration. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md] [VERIFIED: scripts/pipeline.py]

### Pattern 4: Runtime Profile As A Report Extension

**What:** Add a `runtime_profile` object alongside existing top-level `statistics` in `reports/pipeline-stats.json`. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md] [VERIFIED: scripts/pipeline.py]
**When to use:** Use after compile completes so full input/output sizes, durations, worker counts, and compiler cardinalities can be reported together. [VERIFIED: scripts/pipeline.py] [VERIFIED: scripts/compiler.py]
**Example:**
```json
{
  "schema_version": 2,
  "version": "1.5.0",
  "execution_time_seconds": 42.17,
  "statistics": {},
  "runtime_profile": {
    "worker_count": 8,
    "stage_durations_seconds": {
      "clean_compile_total": 41.82
    },
    "byte_sizes": {
      "raw_input_bytes": 145412000,
      "output_bytes": 43198429
    },
    "compiler_cardinalities": {
      "abp_rule_keys": 1234567,
      "abp_wildcard_keys": 123,
      "exception_rules": 456,
      "other_rules": 789
    },
    "memory": {
      "tracemalloc_peak_bytes": 123456789,
      "resource_ru_maxrss": 987654
    }
  }
}
```

`release_validator.py` currently hard-checks pipeline stats schema version `1`, so a schema bump requires validator and test updates. [VERIFIED: scripts/release_validator.py] [VERIFIED: tests/test_release_validator.py]

### Anti-Patterns to Avoid

- **Updating downloader state before final file promotion:** This can record an ETag/Last-Modified for content that did not finish writing. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md]
- **Returning cleaned `list[str]` payloads from workers after adding "streaming":** That keeps the current process-boundary materialization risk. [VERIFIED: scripts/pipeline.py] [VERIFIED: .planning/codebase/CONCERNS.md]
- **Consuming worker results by completion order:** That can break deterministic source ordering and create noisy release diffs. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md]
- **Turning runtime metrics into release gates:** Runtime warnings/hard gates are deferred until baseline history exists. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md]
- **Installing on Python 3.13 exactly like release install while `requires-python = ">=3.14"` remains:** That package install is expected to reject 3.13 unless the audit job deliberately bypasses project metadata or installs dependencies separately. [VERIFIED: pyproject.toml] [CITED: https://pip.pypa.io/en/stable/cli/pip_install/]

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Large HTTP response handling | Custom socket/download loop | `aiohttp` `resp.content.iter_chunked()` | Official aiohttp docs identify response streaming as the large-body pattern. [VERIFIED: Context7 /aio-libs/aiohttp] [CITED: https://docs.aiohttp.org/en/stable/client_quickstart.html] |
| File promotion | Bespoke in-place overwrite | Sibling temp file plus `Path.replace()` | Python docs specify `Path.replace()` unconditionally replaces existing file/empty directory, and the project already uses sibling temp replacement. [CITED: https://docs.python.org/3.14/library/pathlib.html] [VERIFIED: scripts/compiler.py] |
| Dependency resolution | Custom lockfile parser or manual transitive pins | pip-generated constraints consumed by `pip install -c` | Constraints are pip-native and locked by user decision. [CITED: https://pip.pypa.io/en/stable/user_guide/#constraints-files] [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md] |
| Memory measurement | Custom `/proc` parser as primary API | `tracemalloc` and Unix `resource.getrusage()` as best-effort metrics | Both are stdlib APIs with documented behavior; `resource` is Unix-only, matching Ubuntu Actions but requiring fallback. [CITED: https://docs.python.org/3/library/tracemalloc.html] [CITED: https://docs.python.org/3.14/library/resource.html] |
| Compiler storage redesign | Tries, SQLite, external sort, partitioned compilation | Existing semantic dictionaries/sets plus metric instrumentation | Phase context explicitly defers deep storage redesign because global indexes protect semantic pruning and whitelist behavior. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md] |

**Key insight:** This phase should reduce peak memory at I/O and worker-boundary points while preserving the compiler's global semantic view. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md] [VERIFIED: scripts/compiler.py]

## Common Pitfalls

### Pitfall 1: Streaming The HTTP Response But Buffering Fallback Copies
**What goes wrong:** A 2xx path becomes bounded, but 304/error/timeout fallbacks still read the entire cached file into memory. [VERIFIED: scripts/downloader.py]
**Why it happens:** Existing fallback branches duplicate read-then-write logic. [VERIFIED: scripts/downloader.py]
**How to avoid:** Centralize bounded copy/hash helpers and call them from every cache-promotion path. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md]
**Warning signs:** Any remaining `await src.read()` without a size argument in downloader fallback code. [VERIFIED: scripts/downloader.py]

### Pitfall 2: Broken Atomicity From Early State Updates
**What goes wrong:** Cache state can claim a source is fresh after a partially written file. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md]
**Why it happens:** Metadata update code currently sits immediately after successful full-response writes. [VERIFIED: scripts/downloader.py]
**How to avoid:** Keep state mutation after cache temp replacement and raw temp replacement both succeed. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md]
**Warning signs:** `state[url] = new_state` appears before `Path.replace()` for all final destinations. [VERIFIED: scripts/downloader.py]

### Pitfall 3: Losing Deterministic Input Order
**What goes wrong:** Faster workers can feed cleaned rules before earlier files, creating noisy diffs. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md]
**Why it happens:** Bounded queues or `as_completed()` patterns favor completion order. [ASSUMED]
**How to avoid:** Index sorted input files and consume spools/chunks by index. [VERIFIED: scripts/pipeline.py]
**Warning signs:** Parent compiler iterator no longer follows `files = sorted(input_path.glob("*.txt"))`. [VERIFIED: scripts/pipeline.py]

### Pitfall 4: Schema Bump Without Validator Update
**What goes wrong:** `release_validator.py` rejects new pipeline-stats schema versions. [VERIFIED: scripts/release_validator.py]
**Why it happens:** `PIPELINE_STATS_SCHEMA_VERSION` is currently `1` and `_validate_report_schema_versions()` hard-checks equality. [VERIFIED: scripts/release_validator.py]
**How to avoid:** Update validator schema constant/tests when adding `runtime_profile`, or keep schema version 1 only if the schema remains backward-compatible by project policy. [VERIFIED: scripts/release_validator.py] [VERIFIED: tests/test_release_validator.py]
**Warning signs:** `tests/test_release_validator.py` still builds schema `1` only after pipeline stats changes. [VERIFIED: tests/test_release_validator.py]

### Pitfall 5: Treating Python 3.13 Audit As Declared Support
**What goes wrong:** A CI matrix can be misread as project support while `pyproject.toml` still declares `>=3.14`. [VERIFIED: pyproject.toml]
**Why it happens:** Matrix labels and package metadata communicate different things. [ASSUMED]
**How to avoid:** Name the job `python_compatibility_audit`, keep release on 3.14, and document that `requires-python` is unchanged. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md]
**Warning signs:** Any Phase 04 diff changes `requires-python` or Ruff `target-version` as a support declaration. [VERIFIED: pyproject.toml]

## Code Examples

### Release Constraints Install
```yaml
# Source: pip constraints docs and existing update.yml install step.
- name: Install Dependencies
  run: python -m pip install -q -c constraints/release-py314.txt ".[dev]"
```
Pip constraints constrain versions during resolution without installing packages by themselves. [CITED: https://pip.pypa.io/en/stable/user_guide/#constraints-files]

### Compatibility Audit Matrix
```yaml
# Source: GitHub Actions Python matrix docs.
python_compatibility_audit:
  runs-on: ubuntu-latest
  permissions:
    contents: read
  strategy:
    fail-fast: false
    matrix:
      python-version: ["3.13", "3.14"]
  steps:
    - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd
    - uses: actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405
      with:
        python-version: ${{ matrix.python-version }}
        cache: pip
        cache-dependency-path: |
          pyproject.toml
          constraints/*.txt
    - run: python -m pip install -e ".[dev]" --ignore-requires-python -c constraints/release-py314.txt
    - run: python -m ruff check .
    - run: python -m pytest
```
The `--ignore-requires-python` line is the chosen audit-only option because project metadata still requires Python 3.14; it belongs only in `python_compatibility_audit`, not in scheduled release publishing. [VERIFIED: pyproject.toml] [CITED: https://pip.pypa.io/en/stable/cli/pip_install/]

### Memory Probe Helper
```python
# Source: Python tracemalloc and resource docs.
def _memory_profile() -> dict[str, int | None]:
    profile: dict[str, int | None] = {
        "tracemalloc_current_bytes": None,
        "tracemalloc_peak_bytes": None,
        "resource_ru_maxrss": None,
    }
    if tracemalloc.is_tracing():
        current, peak = tracemalloc.get_traced_memory()
        profile["tracemalloc_current_bytes"] = current
        profile["tracemalloc_peak_bytes"] = peak

    try:
        import resource
    except ImportError:
        return profile

    profile["resource_ru_maxrss"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return profile
```
`tracemalloc.get_traced_memory()` returns current and peak traced Python allocation sizes, and `resource.getrusage()` exposes `ru_maxrss` on Unix. [CITED: https://docs.python.org/3/library/tracemalloc.html] [CITED: https://docs.python.org/3.14/library/resource.html]

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Whole-body response reads through `response.read()` | Chunked streaming through `response.content.iter_chunked()` | Current aiohttp 3.13.5 docs. [CITED: https://docs.aiohttp.org/en/stable/client_quickstart.html] | Peak downloader memory scales with chunk size instead of response size. [VERIFIED: Context7 /aio-libs/aiohttp] |
| Lower-bound dependency install in scheduled releases | Constraints-backed install with exact resolved versions | Locked for Phase 04 by context. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md] | Scheduled releases become auditable for dependency resolution drift. [CITED: https://pip.pypa.io/en/stable/user_guide/#constraints-files] |
| Single Python release version in CI | Separate audit matrix for Python 3.13 and 3.14 | GitHub docs show Python matrix workflows. [CITED: https://docs.github.com/en/actions/tutorials/build-and-test-code/python] | Maintainer can see compatibility evidence before changing declared support. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md] |
| Count-only pipeline stats | Versioned stats plus `runtime_profile` | Locked for Phase 04 by context. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md] | Runtime observations become inspectable without adding release gates. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md] |

**Deprecated/outdated:**
- `response.read()` for large blocklist fetches is outdated for Phase 04 because aiohttp docs identify streaming as the large-response pattern. [CITED: https://docs.aiohttp.org/en/stable/client_quickstart.html] [VERIFIED: scripts/downloader.py]
- Whole cleaned-file payload returns across the process boundary are outdated for Phase 04 because the phase locks bounded parallel cleaning as the primary memory strategy. [VERIFIED: scripts/pipeline.py] [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md]
- Lower-bound-only scheduled release installs are outdated for Phase 04 because RUN-04 requires reproducible release dependencies through a lockfile or constraints file. [VERIFIED: .planning/REQUIREMENTS.md] [VERIFIED: pyproject.toml]

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Package download counts were not checked because no new packages are recommended and local Python/pip is unavailable. | Package Legitimacy Audit | Low; planner should not add new packages, but a future package addition would require a fresh legitimacy gate. |
| A2 | Completion-order worker consumption can break deterministic output if not re-ordered by source index. | Common Pitfalls | Medium; the planner must test deterministic ordering for any bounded cleaning design. |
| A3 | Python 3.13 audit uses an editable install with `--ignore-requires-python`; the dependency-only `PYTHONPATH=.` alternative is not chosen for Phase 04. | Code Examples | Low; the audit job is explicitly named and release publishing still uses normal Python 3.14 install. |

## Open Questions (RESOLVED)

1. **Should `runtime_profile` bump `pipeline-stats` schema from 1 to 2?**
   What we know: Reports are versioned and validator currently hard-checks schema 1. [VERIFIED: scripts/pipeline.py] [VERIFIED: scripts/release_validator.py]
   Resolution: Bump `reports/pipeline-stats.json` to `schema_version: 2` and update validator/tests. The new top-level `runtime_profile` is inspect-only and does not add runtime gates. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md]

2. **Which Python 3.13 audit install pattern should be used?**
   What we know: `pyproject.toml` declares `requires-python = ">=3.14"`, so normal package install under 3.13 is expected to fail. [VERIFIED: pyproject.toml]
   Resolution: Use the exact audit-only install command `python -m pip install -e ".[dev]" --ignore-requires-python -c constraints/release-py314.txt` in the separate `python_compatibility_audit` job for both Python 3.13 and 3.14. This bypasses `requires-python` only for the audit signal; scheduled release publishing keeps the normal Python 3.14 command `python -m pip install -q -c constraints/release-py314.txt ".[dev]"`. [VERIFIED: pyproject.toml] [CITED: https://pip.pypa.io/en/stable/cli/pip_install/]

3. **What exact chunk size should the downloader and bounded copy helpers use?**
   What we know: Context delegates chunk-size choice to planner discretion. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md]
   Resolution: Start with a private constant such as `DOWNLOAD_CHUNK_SIZE: Final[int] = 1024 * 1024`, cover it through fixture-scale tests, and expose no public runtime knob in Phase 04. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md]

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|-------------|-----------|---------|----------|
| Local `python` | Local tests, pip registry/slopcheck checks | No | WindowsApps alias failed to launch. [VERIFIED: shell probe] | Use GitHub Actions audit or install a working local CPython before execution. [ASSUMED] |
| Local `py` launcher | Local Python version selection | No | PyManager failed to launch Python 3.11 alias. [VERIFIED: shell probe] | Same as local `python`. [ASSUMED] |
| Local `pip` | Local package checks and constraints generation | No | WindowsApps alias only. [VERIFIED: shell probe] | Generate constraints in CI or after local Python is repaired. [ASSUMED] |
| Git | Commit/status checks | Yes | `git version 2.50.0.windows.1`. [VERIFIED: shell probe] | None needed. [VERIFIED: shell probe] |
| GitHub CLI `gh` | Workflow/release diagnostics if needed | Yes | `gh version 2.92.0`. [VERIFIED: shell probe] | Not required for research. [VERIFIED: .github/workflows/update.yml] |
| GitHub Actions hosted runner | Release build and compatibility audit | Expected in production | `ubuntu-latest` configured. [VERIFIED: .github/workflows/update.yml] | None for scheduled releases. [VERIFIED: AGENTS.md] |
| `actions/setup-python` | Python 3.13/3.14 CI audit | Yes in workflow | v6.2.0 pinned by SHA. [VERIFIED: .github/workflows/update.yml] | None; official docs recommend explicit setup-python for predictable versions. [CITED: https://docs.github.com/en/actions/tutorials/build-and-test-code/python] |

**Missing dependencies with no fallback:**
- Local Python/pip are unavailable in this sandbox, so local pytest/Ruff/slopcheck execution is blocked. [VERIFIED: shell probe]

**Missing dependencies with fallback:**
- Package version checks can be performed through PyPI/official docs during research, and implementation validation can run in GitHub Actions once CI is updated. [VERIFIED: PyPI search pypi.org] [CITED: https://docs.github.com/en/actions/tutorials/build-and-test-code/python]

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | `pytest>=9.0.3` from `pyproject.toml`; PyPI current search confirms 9.0.3 uploaded 2026-04-07. [VERIFIED: pyproject.toml] [VERIFIED: PyPI search pypi.org/project/pytest/] |
| Config file | `pyproject.toml` with `testpaths = ["tests"]`. [VERIFIED: pyproject.toml] |
| Quick run command | `python -m pytest tests/test_downloader.py tests/test_pipeline.py tests/test_compiler.py tests/test_ci_workflow.py -q` [VERIFIED: tests/] |
| Full suite command | `python -m pytest` plus `python -m ruff check .` [VERIFIED: .github/workflows/update.yml] |

### Phase Requirements -> Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|--------------|
| RUN-01 | Successful 2xx downloads stream to cache temp, promote atomically, update state after replacement, and leave old files on partial failure. [VERIFIED: .planning/REQUIREMENTS.md] | unit async downloader | `python -m pytest tests/test_downloader.py -q` | Yes; extend existing file. [VERIFIED: tests/test_downloader.py] |
| RUN-01 | 304/error/timeout/exception fallback copies cache content without full-file reads. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md] | unit async downloader | `python -m pytest tests/test_downloader.py -q` | Yes; add mock aiofiles/fixture coverage. [VERIFIED: tests/test_downloader.py] |
| RUN-02 | Bounded cleaning preserves sorted input-file order and produces same compiler input/output as current pipeline. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md] | integration pipeline | `python -m pytest tests/test_pipeline.py tests/test_integration_pipeline.py -q` | Yes. [VERIFIED: tests/test_pipeline.py] [VERIFIED: tests/test_integration_pipeline.py] |
| RUN-03 | Removing `abp_blocking_domains` does not change compiler output or pruning stats. [VERIFIED: scripts/compiler.py] | unit compiler | `python -m pytest tests/test_compiler.py -q` | Yes. [VERIFIED: tests/test_compiler.py] |
| RUN-03 | `runtime_profile` includes compiler cardinalities, byte sizes, worker count, durations, and memory fields without release gates. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md] | unit report/schema | `python -m pytest tests/test_pipeline.py tests/test_release_validator.py -q` | Yes. [VERIFIED: tests/test_pipeline.py] [VERIFIED: tests/test_release_validator.py] |
| RUN-04 | Workflow installs release dependencies with `-c constraints/...` and setup-python cache dependency path includes constraints. [CITED: https://pip.pypa.io/en/stable/user_guide/#constraints-files] | static workflow | `python -m pytest tests/test_ci_workflow.py -q` | Yes. [VERIFIED: tests/test_ci_workflow.py] |
| RUN-05 | CI has a Python 3.13/3.14 compatibility audit separate from release publishing. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md] | static workflow | `python -m pytest tests/test_ci_workflow.py -q` | Yes. [VERIFIED: tests/test_ci_workflow.py] |

### Sampling Rate

- **Per task commit:** Run the narrow command for the touched module, such as `python -m pytest tests/test_downloader.py -q` for downloader work. [VERIFIED: tests/]
- **Per wave merge:** Run `python -m pytest tests/test_downloader.py tests/test_pipeline.py tests/test_compiler.py tests/test_release_validator.py tests/test_ci_workflow.py -q`. [VERIFIED: tests/]
- **Phase gate:** Run full `python -m pytest` and `python -m ruff check .`, then confirm workflow static tests pass after YAML edits. [VERIFIED: .github/workflows/update.yml] [VERIFIED: tests/test_ci_workflow.py]

### Wave 0 Gaps

- [ ] Add async downloader tests that assert `response.read()` is not used for successful large responses and fallback cache copies are chunked. [VERIFIED: scripts/downloader.py] [VERIFIED: tests/test_downloader.py]
- [ ] Add pipeline tests for deterministic ordered spool/chunk consumption and cleanup after success/failure. [VERIFIED: scripts/pipeline.py] [VERIFIED: tests/test_pipeline.py]
- [ ] Add schema tests for `runtime_profile` and validator compatibility. [VERIFIED: scripts/pipeline.py] [VERIFIED: scripts/release_validator.py]
- [ ] Add workflow static tests for constraints install, cache dependency path, and Python audit matrix. [VERIFIED: tests/test_ci_workflow.py] [VERIFIED: .github/workflows/update.yml]
- [ ] Add a constraints artifact generation/update instruction or script once local/CI Python is available. [CITED: https://pip.pypa.io/en/stable/user_guide/#constraints-files] [ASSUMED]

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|------------------|
| V2 Authentication | No | No user authentication surface in this CLI/release workflow phase. [VERIFIED: .planning/codebase/ARCHITECTURE.md] |
| V3 Session Management | No | No sessions in downloader/pipeline/compiler. [VERIFIED: .planning/codebase/ARCHITECTURE.md] |
| V4 Access Control | Yes, CI permissions only | Preserve least-privilege job permissions from Phase 03. [VERIFIED: .github/workflows/update.yml] [VERIFIED: tests/test_ci_workflow.py] |
| V5 Input Validation | Yes | Keep cleaner/compiler syntax validation and release canaries unchanged while changing runtime flow. [VERIFIED: scripts/cleaner.py] [VERIFIED: scripts/compiler.py] [VERIFIED: scripts/release_validator.py] |
| V6 Cryptography | Yes, content identity only | Use stdlib `hashlib.sha256` for diagnostics/checksums; do not create security claims from non-authenticated upstream checksums. [VERIFIED: scripts/downloader.py] [ASSUMED] |

### Known Threat Patterns for Python/GitHub Actions Pipeline

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Partial or corrupted download promoted as fresh | Tampering | Stream to temp, replace final only after complete write, update state last. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md] |
| Dependency drift in scheduled release | Tampering | Use committed pip constraints in release install and update through reviewed commits. [CITED: https://pip.pypa.io/en/stable/user_guide/#constraints-files] |
| Runtime metrics become release blockers without baseline | Denial of Service | Keep metrics inspect-only in Phase 04. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md] |
| Overbroad CI write token exposure | Elevation of Privilege | Preserve job-level least privilege and avoid moving write permissions back into build/validate. [VERIFIED: .github/workflows/update.yml] [VERIFIED: tests/test_ci_workflow.py] |
| False source rejection from content-type/size gates | Denial of Service | Record diagnostics first; defer default hard gates. [VERIFIED: .planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md] |

## Sources

### Primary (HIGH confidence)
- Context7 `/aio-libs/aiohttp` - Client response streaming with `iter_chunked()` and large-response warning. [VERIFIED: Context7 /aio-libs/aiohttp]
- Context7 `/websites/pip_pypa_io_en_stable` - pip constraints semantics and install options. [VERIFIED: Context7 /websites/pip_pypa_io_en_stable]
- Context7 `/actions/setup-python` - setup-python matrix and pip cache patterns. [VERIFIED: Context7 /actions/setup-python]
- Context7 `/astral-sh/ruff` - Ruff target-version configuration behavior. [VERIFIED: Context7 /astral-sh/ruff]
- `.planning/phases/04-runtime-scaling-reproducibility/04-CONTEXT.md` - Locked decisions and deferred scope. [VERIFIED: codebase grep]
- `scripts/downloader.py`, `scripts/pipeline.py`, `scripts/compiler.py`, `scripts/release_validator.py`, `.github/workflows/update.yml`, and `pyproject.toml` - Implementation touchpoints. [VERIFIED: codebase grep]

### Secondary (MEDIUM confidence)
- https://docs.aiohttp.org/en/stable/client_quickstart.html - aiohttp streaming response content and timeout docs. [CITED: https://docs.aiohttp.org/en/stable/client_quickstart.html]
- https://pip.pypa.io/en/stable/user_guide/#constraints-files - pip constraints file semantics. [CITED: https://pip.pypa.io/en/stable/user_guide/#constraints-files]
- https://pip.pypa.io/en/stable/topics/repeatable-installs/ - pip repeatable install options and hash-checking context. [CITED: https://pip.pypa.io/en/stable/topics/repeatable-installs/]
- https://pip.pypa.io/en/stable/cli/pip_install/ - pip install options including `--ignore-requires-python`. [CITED: https://pip.pypa.io/en/stable/cli/pip_install/]
- https://docs.github.com/en/actions/tutorials/build-and-test-code/python - GitHub Actions Python matrix, setup, caching, and Ruff examples. [CITED: https://docs.github.com/en/actions/tutorials/build-and-test-code/python]
- https://github.com/actions/setup-python - setup-python README for pip cache behavior and recommended permissions. [CITED: https://github.com/actions/setup-python]
- https://docs.python.org/3/library/tracemalloc.html - Python allocation peak metrics. [CITED: https://docs.python.org/3/library/tracemalloc.html]
- https://docs.python.org/3.14/library/resource.html - Unix resource usage metrics and `ru_maxrss`. [CITED: https://docs.python.org/3.14/library/resource.html]
- https://docs.python.org/3.14/library/pathlib.html - `Path.replace()` behavior. [CITED: https://docs.python.org/3.14/library/pathlib.html]

### Tertiary (LOW confidence)
- PyPI search snippets for current package release dates and classifiers. [VERIFIED: PyPI search pypi.org]
- Local environment probes for Python/pip failure mode. [VERIFIED: shell probe]

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - Existing dependencies and workflow are codebase-verified; streaming/constraints/matrix behavior is official-doc verified. [VERIFIED: pyproject.toml] [VERIFIED: Context7 /aio-libs/aiohttp] [CITED: https://pip.pypa.io/en/stable/user_guide/#constraints-files]
- Architecture: HIGH - Phase context and codebase maps align with current downloader/pipeline/compiler boundaries. [VERIFIED: .planning/codebase/ARCHITECTURE.md] [VERIFIED: codebase grep]
- Pitfalls: HIGH for codebase-specific pitfalls, MEDIUM for exact CI audit install method because planner must choose between two viable patterns. [VERIFIED: scripts/downloader.py] [VERIFIED: scripts/pipeline.py] [ASSUMED]

**Research date:** 2026-05-18
**Valid until:** 2026-06-17 for codebase architecture; 2026-05-25 for package version currency and GitHub Actions/PyPI details. [ASSUMED]
