# Phase 04: Runtime Scaling & Reproducibility - Pattern Map

**Mapped:** 2026-05-18
**Files analyzed:** 14 likely new/modified files
**Analogs found:** 13 / 14

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `scripts/downloader.py` | service | streaming, file-I/O, request-response | `scripts/downloader.py` | exact existing target |
| `scripts/pipeline.py` | service/orchestrator | batch, transform, file-I/O | `scripts/pipeline.py` | exact existing target |
| `scripts/compiler.py` | service | batch, transform, file-I/O | `scripts/compiler.py` | exact existing target |
| `scripts/release_validator.py` | service/validator | batch, file-I/O, report validation | `scripts/release_validator.py` | exact existing target |
| `.github/workflows/update.yml` | config | event-driven, batch CI | `.github/workflows/update.yml` | exact existing target |
| `pyproject.toml` | config | dependency declaration | `pyproject.toml` | exact existing target |
| `.github/dependabot.yml` | config | dependency automation | `.github/dependabot.yml` | exact existing target |
| `constraints/release.txt` or `constraints/release-py314.txt` | config | dependency resolution | `pyproject.toml` + `.github/workflows/update.yml` | partial |
| `tests/test_downloader.py` | test | file-I/O, async/service behavior | `tests/test_downloader.py` | exact existing target |
| `tests/test_pipeline.py` | test | batch, transform, report file-I/O | `tests/test_pipeline.py` | exact existing target |
| `tests/test_compiler.py` | test | batch, transform | `tests/test_compiler.py` | exact existing target |
| `tests/test_release_validator.py` | test | report validation, file-I/O | `tests/test_release_validator.py` | exact existing target |
| `tests/test_ci_workflow.py` | test | static config validation | `tests/test_ci_workflow.py` | exact existing target |
| `tests/test_integration_pipeline.py` | test | end-to-end transform fixture | `tests/test_integration_pipeline.py` | role-match |

## Pattern Assignments

### `scripts/downloader.py` (service, streaming/file-I-O/request-response)

**Analog:** `scripts/downloader.py`

**Imports pattern** (lines 25-39):
```python
import argparse
import asyncio
import calendar
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Final, NamedTuple
from urllib.parse import urlparse

import aiofiles
import aiohttp

from scripts import __version__
```

**Result/report data pattern** (lines 76-130):
```python
class FetchResult(NamedTuple):
    url: str
    success: bool
    changed: bool
    error: str | None = None

class SourceHealth(NamedTuple):
    url: str
    filename: str
    status: str
    changed: bool
    byte_size: int
    sha256: str | None
    cache_age_seconds: int | None
    failure_reason: str | None
```

**Atomic write pattern to copy** (lines 225-243, 378-400):
```python
state_path = cache_dir / STATE_FILE
temp_path = state_path.with_suffix(".tmp")
try:
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
    temp_path.replace(state_path)
except OSError as e:
    print(f"Warning: Could not save state.json: {e}", file=sys.stderr)
```

```python
path = Path(output_path)
path.parent.mkdir(parents=True, exist_ok=True)
temp_path = path.with_suffix(".tmp")

with open(temp_path, "w", encoding="utf-8", newline="\n") as f:
    json.dump(_source_health_report_to_dict(report), f, indent=2, sort_keys=True)
    f.write("\n")

temp_path.replace(path)
```

**Current full-buffering pattern to replace** (lines 461-520):
```python
if response.status == 304:
    if cache_path.exists():
        async with aiofiles.open(cache_path, "rb") as src:
            content = await src.read()
        async with aiofiles.open(output_path, "wb") as dst:
            await dst.write(content)
        return FetchResult(url, success=True, changed=False)

content = await response.read()

async with aiofiles.open(output_path, "wb") as f:
    await f.write(content)

async with aiofiles.open(cache_path, "wb") as f:
    await f.write(content)
```

**Fallback error pattern to preserve while changing copy mechanics** (lines 474-497, 522-559):
```python
if response.status >= 400:
    if attempt < retries - 1:
        await asyncio.sleep(2 ** attempt)
        continue

    if cache_path.exists():
        ...
        return FetchResult(
            url,
            success=True,
            changed=False,
            error=f"HTTP {response.status}, using cached version"
        )
    return FetchResult(url, success=False, changed=False, error=f"HTTP {response.status}")
```

**Implementation notes for planner:**
- Add a module constant such as `DOWNLOAD_CHUNK_SIZE: Final[int] = 1024 * 1024`.
- Add bounded helpers beside `_content_identity()`, for example `_copy_file_bounded()`, `_stream_response_to_file()`, and `_content_identity_bounded()`.
- Stream successful `2xx` bodies to a cache-side temp file first, then promote only after the stream completes. Update `state[url]` after successful replacement.
- Use the same bounded copy helper for `304`, HTTP fallback, timeout fallback, and exception fallback.
- `_content_identity()` currently uses `path.read_bytes()` at lines 268-274; runtime-size metrics should replace that with bounded hashing if large source-health files matter.

---

### `scripts/pipeline.py` (service/orchestrator, batch/transform/file-I-O)

**Analog:** `scripts/pipeline.py`

**Imports and dependency pattern** (lines 24-43):
```python
import json
import os
import sys
import time
from collections.abc import Iterator
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Final, TypedDict

from scripts import __version__
from scripts.cleaner import (..., clean_line)
from scripts.compiler import compile_rules
```

**Stats surface pattern** (lines 49-76):
```python
class PipelineStats(TypedDict):
    files_processed: int
    lines_raw: int
    lines_clean: int
    lines_output: int
    comments_removed: int
    ...
    abp_kept: int
    other_kept: int
```

**Current worker materialization pattern to replace** (lines 92-122):
```python
def _clean_single_file(file_path: Path) -> tuple[list[str], dict[str, int]]:
    cleaned: list[str] = []
    file_stats: dict[str, int] = {...}

    with open(file_path, encoding="utf-8-sig", errors="replace") as f:
        for line in f:
            file_stats["lines_raw"] += 1
            result, was_trimmed = clean_line(line)
            ...
            else:
                cleaned.append(result.line)  # type: ignore[arg-type]

    return cleaned, file_stats
```

**Deterministic ordered processing pattern to preserve** (lines 187-209):
```python
files = sorted(input_path.glob("*.txt"))
stats["files_processed"] = len(files)

def _get_cleaned_lines() -> Iterator[str]:
    with ProcessPoolExecutor(max_workers=os.cpu_count()) as executor:
        for cleaned, file_stats in executor.map(_clean_single_file, files):
            ...
            stats["lines_clean"] += len(cleaned)
            yield from cleaned

compile_stats = compile_rules(_get_cleaned_lines(), output_file)
```

**JSON report atomic write pattern** (lines 288-310):
```python
output = {
    "schema_version": 1,
    "version": __version__,
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "execution_time_seconds": round(total_time, 2),
    "statistics": dict(stats),
}

path = Path(output_path)
path.parent.mkdir(parents=True, exist_ok=True)
temp_path = path.with_suffix(".tmp")
with open(temp_path, "w", encoding="utf-8", newline="\n") as f:
    json.dump(output, f, indent=2, sort_keys=True)
temp_path.replace(path)
```

**Implementation notes for planner:**
- Keep `files = sorted(...)` and an ordered consumption contract. `executor.map()` preserves input order; if using `as_completed`, re-order by file/chunk index before yielding.
- Avoid returning full `list[str]` across process boundaries. Prefer per-file/chunk spool files or bounded chunks plus an ordered merge generator.
- Extend `PipelineStats` or add a nested runtime profile shape. Phase context prefers `runtime_profile` under `reports/pipeline-stats.json`, not a separate report family.
- Keep `clean_line()` as the single-line contract; do not reimplement cleaner rules in pipeline.

---

### `scripts/compiler.py` (service, batch/transform/file-I-O)

**Analog:** `scripts/compiler.py`

**Imports pattern** (lines 44-64):
```python
import re
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from sys import intern
from typing import Final, NamedTuple

import tldextract

from scripts.rule_semantics import (...)
from scripts.rule_syntax import (...)
```

**Stats dataclass pattern** (lines 192-235):
```python
@dataclass(slots=True)
class CompileStats:
    total_input: int = 0
    total_output: int = 0
    abp_kept: int = 0
    other_kept: int = 0
    abp_subdomain_pruned: int = 0
    tld_wildcard_pruned: int = 0
    duplicate_pruned: int = 0
    whitelist_conflict_pruned: int = 0
    local_hostname_pruned: int = 0
    formats_compressed: int = 0
    malformed_discarded: int = 0
```

**Parse/compress phase pattern** (lines 582-686):
```python
def _parse_and_compress_lines(
    lines: Iterable[str],
    stats: CompileStats,
    abp_rules: RuleStorage,
    abp_wildcards: WildcardStorage,
    exceptions: ExceptionRules,
    other_rules: set[str],
    duplicate_index: set[RuleDuplicateKey],
) -> None:
    for line in lines:
        stats.total_input += 1
        ...
        if line.startswith(("||", "@@||")):
            record = _parse_abp_rule(line)
            ...
        if line.startswith("@@"):
            continue
        ...
        if PLAIN_DOMAIN_PATTERN.match(line):
            ...
        if line.startswith("/") or "|" in line or "*" in line:
            ...
```

**Unused allocation pattern to remove** (lines 687-698, 926-928):
```python
def _build_coverage_lookups(
    abp_rules: RuleStorage,
    abp_wildcards: WildcardStorage,
) -> tuple[set[str], set[str]]:
    abp_blocking_domains: set[str] = {
        record.domain
        for records in abp_rules.values()
        for record in records
    }
    tld_wildcards: set[str] = set(abp_wildcards.keys())
    return abp_blocking_domains, tld_wildcards
```

```python
abp_blocking_domains, tld_wildcards = _build_coverage_lookups(abp_rules, abp_wildcards)
```

**Atomic output pattern** (lines 848-880):
```python
output_path = Path(output_file)
output_path.parent.mkdir(parents=True, exist_ok=True)
temp_path = output_path.with_suffix(".tmp")

with open(temp_path, "w", encoding="utf-8", newline="\n") as f:
    ...

temp_path.replace(output_path)
stats.total_output = stats.abp_kept + stats.other_kept
```

**Implementation notes for planner:**
- Make `_build_coverage_lookups()` return only `tld_wildcards` or inline `set(abp_wildcards.keys())`.
- Add compiler cardinalities to `CompileStats` only if they are stable, inspect-only counts, for example number of `abp_rules` keys, wildcard keys, exceptions, duplicate index size, and other rules.
- Do not change `compile_rules(lines: Iterable[str], output_file: str) -> CompileStats`; pipeline relies on lazy iteration.

---

### `scripts/release_validator.py` (service/validator, report validation)

**Analog:** `scripts/release_validator.py`

**Schema constants pattern** (lines 35-38):
```python
VALIDATION_SUMMARY_SCHEMA_VERSION: Final[int] = 1
SOURCE_HEALTH_SCHEMA_VERSION: Final[int] = 1
PIPELINE_STATS_SCHEMA_VERSION: Final[int] = 1
```

**Versioned summary pattern** (lines 81-117):
```python
@dataclass(slots=True)
class ValidationSummary:
    errors: list[Finding] = field(default_factory=list)
    warnings: list[Finding] = field(default_factory=list)
    schema_version: int = VALIDATION_SUMMARY_SCHEMA_VERSION
    version: str = __version__
    ...

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "version": self.version,
            ...
        }
```

**Report schema check pattern** (lines 235-251):
```python
def _validate_report_schema_versions(
    source_health: dict[str, object],
    pipeline_stats: dict[str, object],
    canaries: dict[str, object],
) -> list[Finding]:
    errors: list[Finding] = []
    if source_health.get("schema_version") != SOURCE_HEALTH_SCHEMA_VERSION:
        errors.append(_finding("source_health_schema_version", "Unsupported source-health schema"))
    if pipeline_stats.get("schema_version") != PIPELINE_STATS_SCHEMA_VERSION:
        errors.append(_finding(
            "pipeline_stats_schema_version",
            "Unsupported pipeline-stats schema",
        ))
```

**Pipeline stats consumption pattern** (lines 631-688):
```python
source_health = _load_json(source_health_path, "source-health report")
pipeline_stats = _load_json(pipeline_stats_path, "pipeline-stats report")
canaries = _load_json(canaries_path, "canary config")

errors = _validate_report_schema_versions(source_health, pipeline_stats, canaries)
...
stats = pipeline_stats.get("statistics", {})
pipeline_count = 0
if isinstance(stats, dict):
    pipeline_count = int(stats.get("lines_output", 0))
```

**Implementation notes for planner:**
- If `runtime_profile` changes pipeline report schema, bump both `scripts.pipeline` and `PIPELINE_STATS_SCHEMA_VERSION`, then update tests.
- Treat `runtime_profile` as inspect-only. Do not add release errors/warnings for memory, duration, byte size, or cardinality thresholds in Phase 04.
- Keep hard gates focused on existing source health, syntax, canary, output count, and previous-release deltas.

---

### `.github/workflows/update.yml` (config, event-driven/batch CI)

**Analog:** `.github/workflows/update.yml`

**Release Python setup/install pattern** (lines 32-45):
```yaml
- name: Setup Python
  uses: actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405  # v6.2.0
  with:
    python-version: "3.14"
    cache: pip

- name: Install Dependencies
  run: pip install -q ".[dev]"

- name: Ruff
  run: python -m ruff check .

- name: Test
  run: python -m pytest
```

**Build step pattern** (lines 64-84):
```yaml
- name: Fetch Sources
  id: fetch
  run: |
    START=$(date +%s)
    python -m scripts.downloader \
      --sources "$SOURCES" \
      --outdir "$RAW_DIR" \
      --cache .cache \
      --concurrency 10 \
      --timeout 25 \
      --health-report reports/source-health.json
    echo "time=$(($(date +%s) - START))s" >> $GITHUB_OUTPUT

- name: Compile Sources
  id: compile
  run: |
    START=$(date +%s)
    python -m scripts.pipeline "$RAW_DIR" "$OUTPUT" \
      --json-stats reports/pipeline-stats.json
```

**Summary/artifact pattern** (lines 111-134):
```yaml
- name: Append Validation Summary
  if: always()
  run: |
    if [ -f reports/validation-summary.md ]; then
      cat reports/validation-summary.md >> "$GITHUB_STEP_SUMMARY"
    else
      ...
    fi

- name: Upload Release Diagnostics
  if: always()
  uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02  # v4.6.2
  with:
    name: release-candidate
    path: |
      lists/merged.txt
      reports/*.json
      reports/*.md
```

**Permissions pattern to preserve** (lines 13-24, 145-150, 192-199):
```yaml
permissions: {}

jobs:
  build_validate:
    permissions:
      contents: read
  publish:
    permissions:
      contents: write
  cache_cleanup:
    permissions:
      actions: write
```

**Implementation notes for planner:**
- Change release install to use a committed constraints file, for example `pip install -q -c constraints/release.txt ".[dev]"`.
- Add `cache-dependency-path` under `actions/setup-python` when constraints are introduced so cache invalidation sees both `pyproject.toml` and constraints.
- Add a separate compatibility audit job for Python 3.13 and 3.14. Keep the scheduled release/publish path on Python 3.14 and do not lower `requires-python`.
- Mirror only key runtime-size fields to `$GITHUB_STEP_SUMMARY`; leave full data in `reports/pipeline-stats.json`.

---

### `pyproject.toml` (config, dependency declaration)

**Analog:** `pyproject.toml`

**Dependency contract pattern** (lines 1-14):
```toml
[project]
name = "blocklist-merger"
version = "1.5.0"
description = "AdGuard Home blocklist compiler with intelligent deduplication"
requires-python = ">=3.14"

dependencies = [
    "tldextract>=5.3.1",
    "aiohttp>=3.13.5",
    "aiofiles>=25.1.0",
]
```

**Dev tooling pattern** (lines 19-36):
```toml
[project.optional-dependencies]
dev = [
    "pytest>=9.0.3",
    "ruff>=0.15.10",
]

[tool.ruff]
target-version = "py314"
line-length = 100

[tool.pytest.ini_options]
testpaths = ["tests"]
```

**Implementation notes for planner:**
- Keep `requires-python = ">=3.14"` unchanged in Phase 04.
- Keep `pyproject.toml` as the human dependency contract; the constraints file is the reproducible release resolution artifact.

---

### `.github/dependabot.yml` (config, dependency automation)

**Analog:** `.github/dependabot.yml`

**Grouped update pattern** (lines 1-25):
```yaml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
    groups:
      actions:
        patterns:
          - "*"

  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
    groups:
      python-deps:
        patterns:
          - "*"
```

**Implementation notes for planner:**
- If constraints are maintained manually or by CI, Dependabot may update `pyproject.toml` but not regenerate transitive constraints automatically. Planner should decide whether to document the refresh command or add a checked script later.
- Keep grouped weekly updates; do not add a new dependency manager in this phase.

---

### `constraints/release.txt` or `constraints/release-py314.txt` (config, dependency resolution)

**Analog:** partial only - `pyproject.toml` dependencies and `.github/workflows/update.yml` install step.

**Source contract to pin from** (`pyproject.toml` lines 10-23):
```toml
dependencies = [
    "tldextract>=5.3.1",
    "aiohttp>=3.13.5",
    "aiofiles>=25.1.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=9.0.3",
    "ruff>=0.15.10",
]
```

**Workflow install callsite to update** (`.github/workflows/update.yml` lines 38-39):
```yaml
- name: Install Dependencies
  run: pip install -q ".[dev]"
```

**Implementation notes for planner:**
- No constraints or lockfile currently exists; this is the only likely new source file with no exact analog.
- Use standard pip constraints syntax, one pinned distribution per line. Keep generated comments minimal if the generator produces them.
- Do not commit generated runtime artifacts under `lists/`, `.cache/`, or `reports/`.

---

### `tests/test_downloader.py` (test, async/file-I-O/service behavior)

**Analog:** `tests/test_downloader.py`

**Import pattern** (lines 9-29):
```python
import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

import scripts.downloader as downloader
from scripts.downloader import (
    FetchResult,
    SourceHealth,
    SourceHealthReport,
    ...
)
```

**Temp file and atomic-state pattern** (lines 160-183):
```python
class TestSaveState:
    def test_atomic_write(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            save_state(Path(tmpdir), {"test": {"key": "value"}})

            files = os.listdir(tmpdir)
            assert "state.json" in files
            assert "state.tmp" not in files
```

**Source-health fixture pattern** (lines 205-291):
```python
with tempfile.TemporaryDirectory() as tmpdir:
    url = "https://example.com/fallback.txt"
    output_dir = Path(tmpdir) / "out"
    cache_dir = Path(tmpdir) / "cache"
    output_dir.mkdir()
    cache_dir.mkdir()
    filename = url_to_filename(url)
    (output_dir / filename).write_bytes(b"fallback content\n")
    state = {url: {"fetched_at": fetched_at}} if fetched_at else {url: {}}

    health = source_health_from_fetch_result(...)
```

**CLI monkeypatch async pattern** (lines 382-428):
```python
async def fake_fetch_all(urls, output_dir, cache_dir, concurrency, timeout, retries):
    output_dir.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)
    filename = url_to_filename(urls[0])
    (output_dir / filename).write_bytes(b"only successful source\n")
    return [
        FetchResult(urls[0], success=True, changed=True),
        *[
            FetchResult(url, success=False, changed=False, error="HTTP 500")
            for url in urls[1:]
        ],
    ]

monkeypatch.setattr(downloader, "fetch_all", fake_fetch_all)
```

**Implementation notes for planner:**
- Add focused async tests without real network calls. Build fake `session.get()`/response objects that implement async context manager and `content.iter_chunked()`.
- Assert the success path does not call `response.read()`.
- Assert partial stream failure leaves previous cache/output intact and cleans temp files.
- Assert `304`, HTTP error, timeout, and generic exception fallback copy from cache through the shared bounded helper.

---

### `tests/test_pipeline.py` (test, batch/transform/report file-I-O)

**Analog:** `tests/test_pipeline.py`

**Pipeline fixture helper pattern** (lines 20-29):
```python
class TestProcessFiles:
    def _run(self, make_input_dir, file_contents: dict[str, str]):
        input_dir, output_file = make_input_dir(file_contents)
        stats = process_files(input_dir, output_file)
        with open(output_file) as f:
            rules = [line.strip() for line in f if line.strip()]
        return rules, stats
```

**Determinism test pattern** (lines 117-134):
```python
def test_multiple_files_deterministic(self, make_input_dir):
    rules1, _ = self._run(make_input_dir, {
        "aaa.txt": "||a.com^\n",
        "zzz.txt": "||z.com^\n",
    })
    ...
    assert rules1 == rules2
```

**Monkeypatch compile contract pattern** (lines 170-188):
```python
def fake_compile_rules(lines, output_file):
    assert list(lines) == ["||keep.com^"]
    with open(output_file, "w", encoding="utf-8", newline="\n") as f:
        f.write("||keep.com^\n")
    return CompileStats(total_output=1, abp_kept=1, malformed_discarded=3)

monkeypatch.setattr(pipeline_module, "compile_rules", fake_compile_rules)
```

**Stats JSON assertion pattern** (lines 225-271):
```python
save_stats_json(stats, json_path, total_time=5.5)

with open(json_path) as f:
    data = json.load(f)

assert data["schema_version"] == 1
assert data["version"] == "1.5.0"
assert data["execution_time_seconds"] == 5.5
assert data["statistics"]["files_processed"] == 10
assert not os.path.exists(os.path.join(tmp_dir, "stats.tmp"))
```

**Implementation notes for planner:**
- Add tests for bounded worker output: deterministic ordered consumption, same emitted compiler input, and temp spool cleanup on success/failure.
- Add `runtime_profile` report tests here, including durations, byte sizes, worker count, compiler cardinalities, and best-effort memory fields.

---

### `tests/test_compiler.py` (test, batch/transform)

**Analog:** `tests/test_compiler.py`

**Compile helper pattern** (lines 119-126):
```python
def _compile(self, lines):
    with tempfile.TemporaryDirectory() as tmpdir:
        output = os.path.join(tmpdir, "output.txt")
        stats = compile_rules(lines, output)
        with open(output) as f:
            rules = [line.strip() for line in f if line.strip()]
        return rules, stats
```

**Core behavior regression pattern** (lines 128-160):
```python
def test_abp_subdomain_pruning(self):
    lines = ["||example.com^", "||sub.example.com^"]
    rules, stats = self._compile(lines)
    assert "||example.com^" in rules
    assert "||sub.example.com^" not in rules
    assert stats.abp_subdomain_pruned == 1

def test_tld_wildcard_pruning(self):
    lines = ["||*.autos^", "||spam.autos^", "||ads.spam.autos^"]
    rules, stats = self._compile(lines)
    assert "||*.autos^" in rules
    assert stats.tld_wildcard_pruned == 2
```

**Deterministic output pattern** (lines 330-344):
```python
def test_other_rules_written_deterministically(self):
    lines = ["/zeta.*/", "/alpha.*/", "/middle.*/"]

    rules1, stats1 = self._compile(lines)
    rules2, stats2 = self._compile(list(reversed(lines)))

    assert rules1 == sorted(lines)
    assert rules2 == sorted(lines)
    assert stats1.other_kept == 3
    assert stats2.other_kept == 3
```

**Implementation notes for planner:**
- Add a regression proving removing `abp_blocking_domains` does not change rules or pruning stats.
- Add compiler cardinality counter tests if `CompileStats` gains inspect-only fields.
- Keep tests small and synthetic; do not read generated `lists/**`.

---

### `tests/test_release_validator.py` (test, report validation/file-I-O)

**Analog:** `tests/test_release_validator.py`

**Report helper pattern** (lines 16-85):
```python
def _write_json(path: Path, data: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")

def _pipeline_stats(lines_output: int = 3) -> dict[str, object]:
    return {
        "schema_version": 1,
        "version": "1.5.0",
        "timestamp": "2026-05-17T15:01:00Z",
        "execution_time_seconds": 1.25,
        "statistics": {...},
    }
```

**Full validation fixture pattern** (lines 99-140):
```python
def _write_release_inputs(
    tmp_path: Path,
    *,
    output_lines: list[str] | None = None,
    source_health: dict[str, object] | None = None,
    pipeline_stats: dict[str, object] | None = None,
    canaries: dict[str, object] | None = None,
    previous_lines: list[str] | None = None,
) -> dict[str, Path]:
    ...
    return paths

def _validate(tmp_path: Path, **kwargs) -> release_validator.ValidationSummary:
    paths = _write_release_inputs(tmp_path, **kwargs)
    return release_validator.validate_release(...)
```

**Summary output assertion pattern** (lines 272-304):
```python
result = release_validator.run_validation(...)

data = _read_json(paths["summary_json"])
markdown = paths["summary_md"].read_text(encoding="utf-8")
assert result.exit_code == 1
assert data["schema_version"] == 1
assert data["status"] == "failed"
assert data["errors"]
assert data["warnings"]
assert "## Release Validation: Failed" in markdown
```

**Implementation notes for planner:**
- Extend `_pipeline_stats()` with `runtime_profile` when the schema is bumped.
- Add a test proving validator accepts runtime metrics without producing runtime warnings/errors.
- Add a schema-version test if `PIPELINE_STATS_SCHEMA_VERSION` changes from 1 to 2.

---

### `tests/test_ci_workflow.py` (test, static config validation)

**Analog:** `tests/test_ci_workflow.py`

**Static workflow read helpers** (lines 8-32):
```python
ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "update.yml"

def _workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")

def _position(text: str, needle: str) -> int:
    position = text.find(needle)
    assert position != -1, f"Missing workflow text: {needle!r}"
    return position
```

**Ordering assertion pattern** (lines 35-63):
```python
install = _position(text, 'pip install -q ".[dev]"')
ruff = _position(text, "python -m ruff check .")
pytest = _position(text, "python -m pytest")

assert install < ruff < pytest

for step in protected_steps:
    assert pytest < _position(text, step)
```

**Permissions assertion pattern** (lines 81-101):
```python
assert "\npermissions: {}\n" in text
...
build_validate = _job_section(text, "build_validate")
publish = _job_section(text, "publish")
cache_cleanup = _job_section(text, "cache_cleanup")

assert "\n    permissions:\n      contents: read\n" in build_validate
assert "\n    permissions:\n      contents: write\n" in publish
assert "\n    permissions:\n      actions: write\n" in cache_cleanup
```

**Implementation notes for planner:**
- Update install string expectations when constraints are added.
- Add assertions for `cache-dependency-path`, constraints path, and a Python 3.13/3.14 audit matrix/job.
- Preserve existing ordering and least-privilege tests.

---

### `tests/test_integration_pipeline.py` (test, end-to-end transform fixture)

**Analog:** `tests/test_integration_pipeline.py`

**Golden fixture pattern** (lines 13-40):
```python
def _run_case(case_name: str, tmp_path: Path) -> None:
    input_path = FIXTURES_DIR / f"{case_name}_input.txt"
    expected_path = FIXTURES_DIR / f"{case_name}_expected.txt"

    raw_lines = input_path.read_text(encoding="utf-8").splitlines()
    cleaned_lines, _stats = clean_lines(raw_lines)

    clear_caches()
    output_file = tmp_path / f"{case_name}_output.txt"
    compile_rules(cleaned_lines, str(output_file))

    output_lines = output_file.read_text(encoding="utf-8").splitlines()
    expected_lines = expected_path.read_text(encoding="utf-8").splitlines()

    assert output_lines == expected_lines
```

**Implementation notes for planner:**
- Use this only for end-to-end semantic regressions. Bounded cleaning mechanics belong in `tests/test_pipeline.py`.
- Keep fixture cases small and paired with expected output files.

## Shared Patterns

### Atomic Replacement

**Sources:** `scripts/downloader.py` lines 225-243 and 378-400; `scripts/pipeline.py` lines 305-310; `scripts/compiler.py` lines 857-880; `scripts/release_validator.py` lines 181-197.

**Apply to:** Downloader stream promotion, cache fallback copies, pipeline stats, compiler output, validation summaries.

```python
path.parent.mkdir(parents=True, exist_ok=True)
temp_path = path.with_suffix(".tmp")
with open(temp_path, "w", encoding="utf-8", newline="\n") as f:
    json.dump(data, f, indent=2, sort_keys=True)
    f.write("\n")
temp_path.replace(path)
```

### Deterministic Ordering

**Sources:** `scripts/pipeline.py` lines 187-209; `scripts/compiler.py` lines 875-880; `tests/test_pipeline.py` lines 117-134; `tests/test_compiler.py` lines 330-344.

**Apply to:** Bounded cleaning, chunk/spool merge, compiler output, workflow-visible release diffs.

```python
files = sorted(input_path.glob("*.txt"))
...
for cleaned, file_stats in executor.map(_clean_single_file, files):
    ...
    yield from cleaned
```

```python
for rule in sorted(other_rules):
    f.write(rule + "\n")
    stats.other_kept += 1
```

### Versioned Reports

**Sources:** `scripts/pipeline.py` lines 288-303; `scripts/downloader.py` lines 337-375; `scripts/release_validator.py` lines 235-251.

**Apply to:** `runtime_profile` under `reports/pipeline-stats.json`, validator schema compatibility, workflow artifacts.

```python
output = {
    "schema_version": 1,
    "version": __version__,
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "execution_time_seconds": round(total_time, 2),
    "statistics": dict(stats),
}
```

### CLI Boundary Error Handling

**Sources:** `scripts/downloader.py` lines 672-720; `scripts/pipeline.py` lines 342-366; `scripts/release_validator.py` lines 761-788.

**Apply to:** Any new CLI-visible report/metrics behavior.

```python
try:
    ...
    return 0
except Exception as e:
    print(f"\nERROR: {e}", file=sys.stderr)
    import traceback
    traceback.print_exc()
    return 1
```

### Test Style

**Sources:** `tests/conftest.py` lines 14-48; `tests/test_downloader.py` lines 382-428; `tests/test_ci_workflow.py` lines 14-32.

**Apply to:** All Phase 04 tests.

```python
@pytest.fixture
def make_input_dir(tmp_dir):
    def _make(file_contents: dict[str, str]) -> tuple[str, str]:
        input_dir = os.path.join(tmp_dir, "input")
        os.makedirs(input_dir)
        output_file = os.path.join(tmp_dir, "output.txt")
        ...
        return input_dir, output_file
    return _make
```

## No Analog Found

| File/Pattern | Role | Data Flow | Reason |
|---|---|---|---|
| `constraints/release.txt` or `constraints/release-py314.txt` | config | dependency resolution | No constraints or lockfile exists. Use `pyproject.toml` dependency declarations plus pip constraints syntax from research. |
| Downloader `aiohttp` streamed response helper | utility/service helper | streaming, file-I/O | Existing downloader uses `response.read()` and full cache reads. Use atomic write patterns from repo plus `aiohttp` `content.iter_chunked()` from research. |
| Python 3.13/3.14 compatibility audit job | CI config | matrix batch | Existing workflow has one Python 3.14 build/publish path only. Add separate audit job while preserving release job shape. |

## Metadata

**Analog search scope:** `scripts/*.py`, `.github/workflows/update.yml`, `.github/dependabot.yml`, `pyproject.toml`, `tests/*.py`, phase artifacts.

**Files scanned:** 20 source/test/config/planning files, excluding generated `lists/**`, `.cache/**`, and `__pycache__/**`.

**Pattern extraction date:** 2026-05-18

**Planner cautions:**
- Do not add hard runtime gates in Phase 04.
- Do not lower `requires-python` below `>=3.14`.
- Do not redesign compiler storage with tries, SQLite, partitioned compilation, or external sorting.
- Do not place source/test files under generated artifact paths.
