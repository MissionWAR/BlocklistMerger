#!/usr/bin/env python3
"""Corpus benchmark harness for the blocklist compiler (PERF-01/PERF-02, D-01/D-02).

A standalone stdlib-only CLI that makes this phase's performance claims
measurable. It pins ``lists/_raw/`` with a hash-in-place SHA-256 manifest so a
before/after comparison can never silently use different inputs (D-02), times
the real production compiler entry point ``compile_rules()`` median-of-N runs,
and writes identity-stamped JSON reports under the gitignored
``reports/benchmarks/runs/`` tree. Compare modes enforce the locked D-01 floor
(``>=15%`` wall-clock improvement) via exit codes for manual local evidence
workflows only — there is deliberately no CI integration (D-02).

Usage:
    py -3.14 -m scripts.benchmark --corpus lists/_raw --runs 3 \
        --json reports/benchmarks/runs/pre.json
    py -3.14 -m scripts.benchmark --compare pre.json post.json \
        --min-improve-percent 15.0
    py -3.14 -m scripts.benchmark --corpus lists/_raw --runs 3 \
        --json reports/benchmarks/runs/post.json --compare-baseline
    py -3.14 -m scripts.benchmark --corpus lists/_raw \
        --track-memory --json reports/benchmarks/runs/pre-memory.json

Exit codes:
    0  success; compare modes: improvement meets the floor
    1  operational failure: missing/empty corpus, mid-leg corpus drift,
       unparseable or missing report documents, drifted-corpus comparison,
       below-floor compare verdict, or missing baseline document (Plan 14-03
       pins tests/fixtures/benchmarks/corpus-baseline.json)
    2  argparse usage error

Compare verdict line (single machine-readable JSON object on stdout):
    {"pre_seconds": <float>, "post_seconds": <float>,
     "improvement_percent": <float>, "floor_percent": <float>,
     "passes": <bool>}

JSON schema (mode == "timing"):
    {
      "schema_version": 1,
      "report_type": "corpus_benchmark",
      "mode": "timing",
      "created_at": "<UTC ISO-8601 Zulu timestamp>",
      "identity": {
        "python_version": "<platform.python_version()>",
        "platform": "<platform.platform()>",
        "package_version": "<scripts.__version__>",
        "git_revision": "<short sha or 'unknown'>"
      },
      "corpus": {
        "dir": "lists/_raw",
        "file_count": <int>,
        "total_bytes": <int>,
        "manifest_sha256": "<64 hex chars>"
      },
      "entries": [{"filename", "byte_size", "sha256"}, ...],
      "runs": <int>,
      "durations_seconds": [<float>, ...],
      "summary": {"min_seconds": <float>, "median_seconds": <float>,
                  "max_seconds": <float>},
      "output_sha256_stable": <bool>,
      "per_run": [{"index": <int>, "elapsed_seconds": <float>,
                   "output_byte_size": <int>, "output_sha256": "<64 hex>"}]
    }

JSON schema (mode == "memory", from --track-memory):
    Common report_type/created_at/identity/corpus fields as timing mode, plus:
    {
      "mode": "memory",
      "tracemalloc_current_bytes": <int >= 0>,
      "tracemalloc_peak_bytes": <int > 0>
    }
    With --memory-top N the document additionally carries:
      "top_allocations": [{"location": "<file>:<line>", "size_bytes": <int > 0>,
                           "count": <int > 0>}, ...]   (at most N entries)
    Memory numbers come from memory-leg invocations only: --track-memory
    ignores --runs and never emits runs/durations_seconds/summary/per_run
    keys, so profiler overhead can never contaminate wall-clock medians.

JSON schema (mode == "profile", from --profile):
    Common report_type/created_at/identity/corpus fields as timing mode, plus:
    {
      "mode": "profile",
      "elapsed_seconds": <float > 0>,
      "output_byte_size": <int>,
      "output_sha256": "<64 hex chars>",
      "top_functions": [{"function": "<name>", "location": "<file>:<line>",
                          "primitive_calls": <int>, "total_calls": <int>,
                          "cumulative_seconds": <float>}, ...],   (top 15)
      "stats_file": "<path under reports/benchmarks/runs/ ending in .pstats>"
    }
    The profile leg wraps exactly one compile in profiler.runcall() (mirroring
    scripts/profile_pipeline.py), dumps the raw .pstats artifact beside the
    JSON target, renders the cumulative top-25 to stdout, and never emits
    timing-summary or tracemalloc keys — measurement kinds never mix.
"""

import argparse
import cProfile
import gc
import hashlib
import io
import json
import platform
import pstats
import statistics
import subprocess
import sys
import tempfile
import time
import tracemalloc
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Final, NamedTuple

from scripts import __version__
from scripts.compiler import clear_caches, compile_rules

# =========================================================================
# CONSTANTS
# =========================================================================

BENCHMARK_ROOT: Final[Path] = Path("reports/benchmarks")
DEFAULT_CORPUS: Final[Path] = Path("lists/_raw")
DEFAULT_RUNS: Final[int] = 3
DEFAULT_MIN_IMPROVE_PERCENT: Final[float] = 15.0
DEFAULT_BASELINE_PATH: Final[Path] = Path("tests/fixtures/benchmarks/corpus-baseline.json")
DEFAULT_MEMORY_TOP: Final[int] = 10
CHUNK_BYTES: Final[int] = 1024 * 1024

#: Rows rendered to stdout from the cProfile ranking (evidence leg).
PROFILE_STDOUT_ROWS: Final[int] = 25
#: Ranking rows embedded into a mode == "profile" report document.
PROFILE_EMBEDDED_ROWS: Final[int] = 15


class BenchmarkError(Exception):
    """Operational benchmark failure reported cleanly on stderr."""


class ManifestEntry(NamedTuple):
    """One pinned corpus file: name, byte size, and in-place content digest."""

    filename: str
    byte_size: int
    sha256: str


# =========================================================================
# HELPER FUNCTIONS
# =========================================================================


def _rooted(path: Path) -> Path:
    """Return an absolute path rooted at the current working directory."""
    return path if path.is_absolute() else Path.cwd() / path


def _reject_root_symlink_segments(path: Path, label: str) -> None:
    """Reject existing symlink components below the workspace root."""
    candidate = _rooted(path)
    try:
        relative = candidate.relative_to(Path.cwd().resolve(strict=False))
    except ValueError:
        return

    probe = Path.cwd().resolve(strict=False)
    for part in relative.parts:
        probe = probe / part
        if probe.is_symlink():
            raise BenchmarkError(f"{label} must not contain symlink path segments")


def _resolved_root(path: Path) -> Path:
    """Return the resolved absolute path for a configured benchmark root."""
    _reject_root_symlink_segments(path, "benchmark root")
    return _rooted(path).resolve(strict=False)


def _reject_artifact_symlink_segments(path: Path, root: Path, label: str) -> None:
    """Reject existing symlink components in an artifact path below root."""
    candidate = _rooted(path)
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        msg = f"{label} must be under {root.as_posix()}"
        raise BenchmarkError(msg) from exc

    probe = root
    for part in relative.parts:
        probe = probe / part
        if probe.is_symlink():
            raise BenchmarkError(f"{label} must not contain symlink path segments")


def _safe_artifact_dir(path: Path, root: Path, label: str) -> Path:
    """Create and return a non-symlink artifact directory below root."""
    candidate = _rooted(path)
    _reject_artifact_symlink_segments(candidate, root, label)
    try:
        candidate.resolve(strict=False).relative_to(root)
    except ValueError as exc:
        msg = f"{label} must be under {root.as_posix()}"
        raise BenchmarkError(msg) from exc

    candidate.mkdir(parents=True, exist_ok=True)
    _reject_artifact_symlink_segments(candidate, root, label)

    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        msg = f"{label} must stay under {root.as_posix()}"
        raise BenchmarkError(msg) from exc
    if not resolved.is_dir():
        raise BenchmarkError(f"{label} must be a directory")
    return resolved


def _safe_artifact_file(path: Path, root: Path, label: str) -> Path:
    """Return a non-symlink artifact file path below root, creating its parent."""
    candidate = _rooted(path)
    parent = _safe_artifact_dir(candidate.parent, root, f"{label} parent")
    target = parent / candidate.name

    _reject_artifact_symlink_segments(target, root, label)
    if target.exists() and not target.is_file():
        raise BenchmarkError(f"{label} must be a file")
    try:
        target.resolve(strict=False).relative_to(root)
    except ValueError as exc:
        msg = f"{label} must stay under {root.as_posix()}"
        raise BenchmarkError(msg) from exc
    return target


def _write_json_report(path: Path, data: dict[str, object]) -> None:
    """Write a JSON report atomically, confined under the benchmark root.

    Only WRITER paths are root-confined and suffix-checked; readers of
    evidence documents (compare modes) intentionally accept paths anywhere.
    """
    root = _resolved_root(BENCHMARK_ROOT)
    if path.suffix != ".json":
        raise BenchmarkError("JSON report path must end in .json")
    target = _safe_artifact_file(path, root, "JSON report")
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            newline="\n",
            dir=target.parent,
            prefix=f".{target.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
        _safe_artifact_file(temp_path, root, "temporary JSON report").replace(target)
    except Exception:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
        raise


def _dump_pstats_artifact(path: Path, profiler: cProfile.Profile) -> Path:
    """Dump cProfile stats atomically to a hardened ``.pstats`` artifact path.

    Mirrors the JSON writer's hardening trio (root confinement, symlink-segment
    rejection, suffix allowlist extended to admit .pstats alongside .json).
    cProfile opens its own output handle, so atomicity comes from dumping to a
    hidden sibling and replacing the target only on success.
    """
    root = _resolved_root(BENCHMARK_ROOT)
    if path.suffix != ".pstats":
        raise BenchmarkError("pstats artifact path must end in .pstats")
    target = _safe_artifact_file(path, root, "pstats artifact")
    temp_path: Path | None = None
    try:
        # Reserve-and-close a unique temp name: cProfile opens its own output
        # handle in dump_stats, so the reservation must not stay locked
        # (Windows raises a sharing violation otherwise).
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            newline="\n",
            dir=target.parent,
            prefix=f".{target.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
        profiler.dump_stats(str(temp_path))
        _safe_artifact_file(temp_path, root, "temporary pstats artifact").replace(target)
    except Exception:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
        raise
    return target


def _render_pstats_top(profile_path: Path, limit: int) -> None:
    """Render the cumulative-time pstats ranking for one artifact to stdout."""
    stream = io.StringIO()
    stats_view = pstats.Stats(str(profile_path), stream=stream)
    stats_view.strip_dirs().sort_stats("cumulative").print_stats(limit)
    print(stream.getvalue(), end="")


def _top_functions_from_pstats(profile_path: Path, limit: int) -> list[dict[str, object]]:
    """Extract the top cumulative-time functions from a dumped .pstats artifact."""
    stats_view = pstats.Stats(str(profile_path))
    ranked = sorted(stats_view.stats.items(), key=lambda item: item[1][3], reverse=True)
    top: list[dict[str, object]] = []
    for entry_key, entry_stats in ranked[:limit]:
        filename, lineno, funcname = entry_key
        primitive, total, _self_time, cumulative, _callers = entry_stats
        top.append(
            {
                "function": funcname,
                "location": f"{filename}:{lineno}",
                "primitive_calls": primitive,
                "total_calls": total,
                "cumulative_seconds": round(cumulative, 6),
            }
        )
    return top


def _display_path(path: Path) -> str:
    """Return a path relative to the cwd when possible for readable reports."""
    try:
        return path.relative_to(Path.cwd()).as_posix()
    except ValueError:
        return path.as_posix()


def _utc_timestamp() -> str:
    """Return a UTC ISO-8601 timestamp for report identity."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _git_revision() -> str:
    """Return a best-effort short git revision for report identity."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return "unknown"
    return result.stdout.strip() or "unknown"


def _sha256_file(path: Path) -> str:
    """Return a SHA-256 hex digest for one file, read in fixed-size chunks."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def build_corpus_manifest(corpus_dir: Path) -> list[ManifestEntry]:
    """Pin every ``*.txt`` file in place; never duplicate corpus bytes.

    Args:
        corpus_dir: Directory holding raw upstream blocklist files.

    Returns:
        Manifest entries sorted by filename, each hashed where it lies.
    """
    entries: list[ManifestEntry] = []
    for corpus_file in sorted(corpus_dir.glob("*.txt")):
        entries.append(
            ManifestEntry(
                filename=corpus_file.name,
                byte_size=corpus_file.stat().st_size,
                sha256=_sha256_file(corpus_file),
            )
        )
    return entries


def manifest_digest(entries: list[ManifestEntry]) -> str:
    """Return the stable corpus identity digest over canonical manifest lines."""
    lines = [f"{entry.filename}:{entry.byte_size}:{entry.sha256}" for entry in entries]
    payload = "\n".join(lines).encode(encoding="utf-8")
    return hashlib.sha256(payload).hexdigest()


def iter_corpus_lines(corpus_dir: Path) -> Iterator[str]:
    """Stream corpus rows lazily, mirroring the audit-suite reader discipline."""
    for corpus_file in sorted(corpus_dir.glob("*.txt")):
        with open(corpus_file, encoding="utf-8-sig", errors="replace") as handle:
            yield from handle


def _drifted_filenames(baseline: list[ManifestEntry], current: list[ManifestEntry]) -> list[str]:
    """List filenames whose content digest changed between two manifests."""
    baseline_by_name = {entry.filename: entry.sha256 for entry in baseline}
    current_by_name = {entry.filename: entry.sha256 for entry in current}
    drifted = [
        filename
        for filename, content_sha in current_by_name.items()
        if baseline_by_name.get(filename) != content_sha
    ]
    drifted.extend(filename for filename in baseline_by_name if filename not in current_by_name)
    return sorted(drifted)


def _python_identity() -> dict[str, object]:
    """Return tool-identity fields stamped into every report."""
    return {
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "package_version": __version__,
        "git_revision": _git_revision(),
    }


def improvement_percent(pre_median: float, post_median: float) -> float:
    """Return wall-clock improvement percent; positive means post is faster.

    Raises:
        ValueError: When ``pre_median`` is not strictly positive, because no
            improvement percentage is definable over a zero baseline.
    """
    if pre_median <= 0:
        raise ValueError(
            f"pre_median must be > 0 to compute an improvement percent (got {pre_median!r})"
        )
    return (pre_median - post_median) / pre_median * 100


def meets_floor(improvement_pct: float, floor_pct: float = DEFAULT_MIN_IMPROVE_PERCENT) -> bool:
    """Return True when the improvement meets the D-01 floor (inclusive >=)."""
    return improvement_pct >= floor_pct


def extract_perf_fields(document: Mapping[str, object]) -> tuple[float, str]:
    """Return ``(median_seconds, manifest_sha256)`` from a report document.

    Tolerates both the full timing-report shape (``summary.median_seconds`` +
    ``corpus.manifest_sha256``) and the slim pinned-baseline shape
    (top-level ``median_seconds`` + ``manifest_sha256``).

    Raises:
        ValueError: With an actionable message naming the expected keys when
            neither median shape nor digest location is present/usable.
    """
    summary = document.get("summary")
    corpus = document.get("corpus")

    median_candidates: list[object] = []
    if isinstance(summary, Mapping):
        median_candidates.append(summary.get("median_seconds"))
    median_candidates.append(document.get("median_seconds"))

    digest_candidates: list[object] = []
    if isinstance(corpus, Mapping):
        digest_candidates.append(corpus.get("manifest_sha256"))
    digest_candidates.append(document.get("manifest_sha256"))

    median_value = next(
        (
            candidate
            for candidate in median_candidates
            if isinstance(candidate, (int, float)) and not isinstance(candidate, bool)
        ),
        None,
    )
    digest_value = next(
        (
            candidate
            for candidate in digest_candidates
            if isinstance(candidate, str) and bool(candidate)
        ),
        None,
    )

    problems: list[str] = []
    if median_value is None:
        problems.append("median_seconds (expected summary.median_seconds or top-level)")
    if digest_value is None:
        problems.append("manifest_sha256 (expected corpus.manifest_sha256 or top-level)")
    if problems:
        raise ValueError(f"document is missing usable perf fields: {'; '.join(problems)}")
    return float(median_value), str(digest_value)


def _load_timing_report(path: Path) -> dict[str, object]:
    """Load one timing-mode benchmark document, failing loudly when foreign.

    Compare READ paths intentionally accept evidence files anywhere on disk;
    only WRITER paths are root-confined under reports/benchmarks/.
    """
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except OSError as error:
        raise BenchmarkError(f"{path}: cannot read compare document ({error})") from error
    except json.JSONDecodeError as error:
        raise BenchmarkError(f"{path}: not parseable JSON ({error})") from error

    if not isinstance(data, dict):
        raise BenchmarkError(f"{path}: compare document must be a JSON object")
    if data.get("report_type") != "corpus_benchmark":
        raise BenchmarkError(
            f"{path}: field 'report_type' must be 'corpus_benchmark' "
            f"(got {data.get('report_type')!r})"
        )
    if data.get("mode") != "timing":
        raise BenchmarkError(f"{path}: field 'mode' must be 'timing' (got {data.get('mode')!r})")
    return data


def run_compare(pre_path: Path, post_path: Path, min_improve_percent: float) -> int:
    """Compare two timing reports and enforce the D-01 floor via exit code."""
    pre_median, pre_digest = extract_perf_fields(_load_timing_report(pre_path))
    post_median, post_digest = extract_perf_fields(_load_timing_report(post_path))

    # Dishonest-comparison guard (D-02): never compute an improvement number
    # over different corpus inputs — refuse with both digests named.
    if pre_digest != post_digest:
        print("ERROR: refusing dishonest comparison across drifted corpora:", file=sys.stderr)
        print(f"  pre  ({pre_path}): manifest_sha256={pre_digest}", file=sys.stderr)
        print(f"  post ({post_path}): manifest_sha256={post_digest}", file=sys.stderr)
        print("Re-capture both sides against the same pinned corpus snapshot.", file=sys.stderr)
        return 1

    improvement = improvement_percent(pre_median, post_median)
    passes = meets_floor(improvement, min_improve_percent)

    print("=== benchmark compare ===")
    print(f"pre  median : {pre_median:.6f}s  ({pre_path})")
    print(f"post median : {post_median:.6f}s  ({post_path})")
    print(f"delta       : {pre_median - post_median:+.6f}s")
    print(f"improvement : {improvement:.2f}%")
    print(f"floor       : >= {min_improve_percent:.2f}%")
    print("verdict     : PASS" if passes else "verdict     : FAIL")
    print(json.dumps({
        "pre_seconds": pre_median,
        "post_seconds": post_median,
        "improvement_percent": round(improvement, 6),
        "floor_percent": min_improve_percent,
        "passes": passes,
    }))
    return 0 if passes else 1


# =========================================================================
# MEASUREMENT LEGS
# =========================================================================


def run_timing_leg(corpus_dir: Path, runs: int, json_path: Path) -> dict[str, object]:
    """Time ``compile_rules()`` over the pinned corpus and persist the report."""
    baseline_entries = build_corpus_manifest(corpus_dir)
    baseline_digest = manifest_digest(baseline_entries)

    durations: list[float] = []
    per_run: list[dict[str, object]] = []
    output_shas: list[str] = []

    with tempfile.TemporaryDirectory(prefix="blocklist-benchmark-") as temp_dir_name:
        output_path = Path(temp_dir_name) / "compiled-output.txt"
        for index in range(1, runs + 1):
            current_entries = build_corpus_manifest(corpus_dir)
            current_digest = manifest_digest(current_entries)
            if current_digest != baseline_digest:
                drifted = _drifted_filenames(baseline_entries, current_entries)
                raise BenchmarkError(
                    f"corpus drifted mid-leg; aborted before run {index}; "
                    f"changed files: {', '.join(drifted)}"
                )

            gc.collect()
            clear_caches()
            start_ns = time.perf_counter_ns()
            compile_rules(iter_corpus_lines(corpus_dir), str(output_path))
            elapsed_seconds = round((time.perf_counter_ns() - start_ns) / 1_000_000_000, 6)

            output_sha = _sha256_file(output_path) if output_path.exists() else ""
            output_shas.append(output_sha)
            durations.append(elapsed_seconds)
            per_run.append(
                {
                    "index": index,
                    "elapsed_seconds": elapsed_seconds,
                    "output_byte_size": output_path.stat().st_size if output_path.exists() else 0,
                    "output_sha256": output_sha,
                }
            )

    sha_stable = len(set(output_shas)) == 1
    if not sha_stable:
        print(
            "WARNING: compiled output differed across runs "
            f"({len(set(output_shas))} distinct fingerprints); timing medians may be meaningless",
            file=sys.stderr,
        )

    report: dict[str, object] = {
        "schema_version": 1,
        "report_type": "corpus_benchmark",
        "mode": "timing",
        "created_at": _utc_timestamp(),
        "identity": _python_identity(),
        "corpus": {
            "dir": str(corpus_dir),
            "file_count": len(baseline_entries),
            "total_bytes": sum(entry.byte_size for entry in baseline_entries),
            "manifest_sha256": baseline_digest,
        },
        "entries": [entry._asdict() for entry in baseline_entries],
        "runs": runs,
        "durations_seconds": durations,
        "summary": {
            "min_seconds": min(durations),
            "median_seconds": round(statistics.median(durations), 6),
            "max_seconds": max(durations),
        },
        "output_sha256_stable": sha_stable,
        "per_run": per_run,
    }
    _write_json_report(json_path, report)
    print(
        f"timing leg complete: median={report['summary']['median_seconds']}s "
        f"over {runs} run(s); report written to {json_path}"
    )
    return report


def run_memory_leg(
    corpus_dir: Path,
    json_path: Path,
    memory_top: int | None = None,
) -> dict[str, object]:
    """Measure one compile's traced peak memory as its own invocation.

    Tracemalloc adds real CPU overhead, so this leg is architecturally
    separated from timing (research Pitfall 6): memory numbers come from
    memory-leg invocations only, and this function deliberately records no
    durations — combining the legs would corrupt the D-01 wall-clock floor.

    When ``memory_top`` is provided, one allocation snapshot is taken inside
    the traced window right after the compile and the top ``memory_top``
    allocation sites (by cumulative size) are embedded as ``top_allocations``.
    Absent flag means absent key: the report schema stays backward compatible.
    """
    entries = build_corpus_manifest(corpus_dir)
    digest = manifest_digest(entries)

    # Guard-railed start/get/stop idiom mirroring scripts/pipeline.py: only
    # stop tracing when this leg started it.
    stop_tracemalloc = not tracemalloc.is_tracing()
    if stop_tracemalloc:
        tracemalloc.start()
    top_allocations: list[dict[str, object]] | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="blocklist-benchmark-") as temp_dir_name:
            output_path = Path(temp_dir_name) / "compiled-output.txt"
            compile_rules(iter_corpus_lines(corpus_dir), str(output_path))
            if memory_top is not None:
                snapshot = tracemalloc.take_snapshot()
                top_allocations = [
                    {
                        "location": f"{frame.filename}:{frame.lineno}",
                        "size_bytes": statistic.size,
                        "count": statistic.count,
                    }
                    for statistic in snapshot.statistics("lineno")[:memory_top]
                    for frame in statistic.traceback[:1]
                ]
    finally:
        current_bytes, peak_bytes = tracemalloc.get_traced_memory()
        if stop_tracemalloc:
            tracemalloc.stop()

    report: dict[str, object] = {
        "schema_version": 1,
        "report_type": "corpus_benchmark",
        "mode": "memory",
        "created_at": _utc_timestamp(),
        "identity": _python_identity(),
        "corpus": {
            "dir": str(corpus_dir),
            "file_count": len(entries),
            "total_bytes": sum(entry.byte_size for entry in entries),
            "manifest_sha256": digest,
        },
        # Field names mirror scripts/pipeline.py MemoryProfile for parity.
        "tracemalloc_current_bytes": current_bytes,
        "tracemalloc_peak_bytes": peak_bytes,
    }
    if top_allocations is not None:
        report["top_allocations"] = top_allocations
    _write_json_report(json_path, report)
    print(f"memory leg complete: peak={peak_bytes} bytes; report written to {json_path}")
    return report


def run_profile_leg(corpus_dir: Path, json_path: Path) -> dict[str, object]:
    """Profile exactly ONE compile under cProfile and persist report + artifact.

    Mirrors scripts/profile_pipeline.py's ``profiler.runcall`` idiom. The raw
    .pstats artifact lands beside the JSON target under reports/benchmarks/runs/
    so hotspot evidence stays reproducible after the run. This leg never emits
    timing-summary or tracemalloc keys — measurement kinds never mix (Pitfall 6).
    """
    entries = build_corpus_manifest(corpus_dir)
    digest = manifest_digest(entries)

    stats_path = json_path.with_suffix(".pstats")
    profiler = cProfile.Profile()

    gc.collect()
    clear_caches()
    start_ns = time.perf_counter_ns()
    output_sha256 = ""
    output_byte_size = 0
    try:
        with tempfile.TemporaryDirectory(prefix="blocklist-benchmark-") as temp_dir_name:
            output_path = Path(temp_dir_name) / "compiled-output.txt"
            profiler.runcall(compile_rules, iter_corpus_lines(corpus_dir), str(output_path))
            elapsed_seconds = round((time.perf_counter_ns() - start_ns) / 1_000_000_000, 6)
            if output_path.exists():
                output_byte_size = output_path.stat().st_size
                output_sha256 = _sha256_file(output_path)
    finally:
        stats_target = _dump_pstats_artifact(stats_path, profiler)

    _render_pstats_top(stats_target, PROFILE_STDOUT_ROWS)
    top_functions = _top_functions_from_pstats(stats_target, PROFILE_EMBEDDED_ROWS)

    report: dict[str, object] = {
        "schema_version": 1,
        "report_type": "corpus_benchmark",
        "mode": "profile",
        "created_at": _utc_timestamp(),
        "identity": _python_identity(),
        "corpus": {
            "dir": str(corpus_dir),
            "file_count": len(entries),
            "total_bytes": sum(entry.byte_size for entry in entries),
            "manifest_sha256": digest,
        },
        "elapsed_seconds": elapsed_seconds,
        "output_byte_size": output_byte_size,
        "output_sha256": output_sha256,
        "top_functions": top_functions,
        "stats_file": _display_path(stats_target),
    }
    _write_json_report(json_path, report)
    print(
        f"profile leg complete: elapsed={elapsed_seconds}s over 1 instrumented "
        f"run; ranking artifact {stats_target.name}; report written to {json_path}"
    )
    return report


# =========================================================================
# CLI INTERFACE
# =========================================================================


def main(argv: list[str] | None = None) -> int:
    """Run one benchmark invocation and return the process exit code."""
    parser = argparse.ArgumentParser(
        prog="scripts.benchmark",
        description=(
            "Median-of-N wall-clock benchmark of compile_rules() over a pinned "
            "hash-in-place corpus manifest (local-only measurement tooling)."
        ),
    )
    parser.add_argument(
        "--corpus",
        type=Path,
        default=DEFAULT_CORPUS,
        help=f"directory of *.txt blocklist sources to pin and time (default: {DEFAULT_CORPUS})",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=DEFAULT_RUNS,
        help=f"number of timed compile iterations (default: {DEFAULT_RUNS})",
    )
    parser.add_argument(
        "--json",
        type=Path,
        default=None,
        help=(
            "report destination under reports/benchmarks/; required for timing "
            "runs and for --compare-baseline (the fresh report becomes the post side)"
        ),
    )
    parser.add_argument(
        "--track-memory",
        action="store_true",
        help=(
            "run the tracemalloc peak-memory leg instead of timing; ignores "
            "--runs (memory numbers come from memory-leg invocations only)"
        ),
    )
    parser.add_argument(
        "--profile",
        action="store_true",
        help=(
            "run exactly ONE compile under cProfile (hotspot evidence leg); "
            "ignores --runs, writes a .pstats artifact beside the JSON target, "
            "and never combines with timing summaries or memory numbers"
        ),
    )
    parser.add_argument(
        "--memory-top",
        nargs="?",
        const=DEFAULT_MEMORY_TOP,
        type=int,
        default=None,
        metavar="N",
        help=(
            "with --track-memory: embed the top N allocation sites "
            f"(location/size/count) as top_allocations (default {DEFAULT_MEMORY_TOP})"
        ),
    )
    parser.add_argument(
        "--compare",
        nargs=2,
        metavar=("PRE", "POST"),
        default=None,
        help=(
            "document-only comparison of two existing timing reports; ignores "
            "--corpus/--runs and writes nothing"
        ),
    )
    parser.add_argument(
        "--compare-baseline",
        nargs="?",
        const=DEFAULT_BASELINE_PATH,
        default=None,
        metavar="BASELINE",
        help=(
            "run a fresh timing leg (--json target becomes the post side), then "
            f"compare against a pinned baseline (default: {DEFAULT_BASELINE_PATH})"
        ),
    )
    parser.add_argument(
        "--min-improve-percent",
        type=float,
        default=DEFAULT_MIN_IMPROVE_PERCENT,
        help=(
            f"inclusive improvement floor for compare exit codes "
            f"(default: {DEFAULT_MIN_IMPROVE_PERCENT})"
        ),
    )
    args = parser.parse_args(argv)

    try:
        # Document-only mode: never touches the corpus directory.
        if args.compare is not None:
            pre_path = Path(args.compare[0])
            post_path = Path(args.compare[1])
            return run_compare(pre_path, post_path, args.min_improve_percent)

        baseline_path: Path | None = (
            Path(args.compare_baseline) if args.compare_baseline is not None else None
        )
        if baseline_path is not None and not baseline_path.is_file():
            raise BenchmarkError(
                f"baseline document not found: {baseline_path}; Plan 14-03 pins "
                "tests/fixtures/benchmarks/corpus-baseline.json (any timing report "
                "can seed it by writing a report to that path)"
            )

        corpus_dir = args.corpus
        # --track-memory and --profile ignore --runs: leg separation keeps
        # profiler overhead out of wall-clock medians (Pitfall 6), so the runs
        # count is meaningless for those legs and never validated.
        if not (args.track_memory or args.profile) and args.runs < 1:
            parser.error("--runs must be >= 1")
        if args.profile and (args.track_memory or args.memory_top is not None):
            parser.error("--profile cannot be combined with --track-memory/--memory-top")
        if args.memory_top is not None:
            if not args.track_memory:
                parser.error("--memory-top requires --track-memory")
            if args.memory_top < 1:
                parser.error("--memory-top must be >= 1")
        if not corpus_dir.is_dir():
            raise BenchmarkError(
                f"corpus directory not found: {corpus_dir}; run `python run.py fetch` first"
            )
        if not any(corpus_dir.glob("*.txt")):
            raise BenchmarkError(
                f"corpus directory contains no *.txt files: {corpus_dir}; "
                "run `python run.py fetch` first"
            )
        if args.json is None:
            parser.error("--json is required for benchmark runs")

        if args.profile:
            run_profile_leg(corpus_dir, args.json)
        elif args.track_memory:
            run_memory_leg(corpus_dir, args.json, args.memory_top)
        else:
            run_timing_leg(corpus_dir, args.runs, args.json)

        if baseline_path is not None:
            if not args.json.is_file():
                raise BenchmarkError(
                    "--compare-baseline requires a freshly written report: supply "
                    "--json PATH under reports/benchmarks/ so the new timing leg "
                    "becomes the comparison's post side"
                )
            return run_compare(baseline_path, args.json, args.min_improve_percent)
    except BenchmarkError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    except Exception as error:
        # Deliberately no `traceback` import: this tool keeps its stdlib
        # surface minimal, so unexpected failures report type + message.
        print(f"UNEXPECTED {type(error).__name__}: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
