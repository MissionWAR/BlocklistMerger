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

Exit codes:
    0  success (compare mode: improvement meets the floor)
    1  operational failure: missing/empty corpus, mid-leg corpus drift,
       unparseable report documents, drifted-corpus comparison, below-floor
       compare verdict, or missing baseline document
    2  argparse usage error

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
"""

import argparse
import gc
import hashlib
import json
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
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
CHUNK_BYTES: Final[int] = 1024 * 1024


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
        required=True,
        help="report destination under reports/benchmarks/ (required)",
    )
    args = parser.parse_args(argv)

    try:
        corpus_dir = args.corpus
        if not corpus_dir.is_dir():
            raise BenchmarkError(
                f"corpus directory not found: {corpus_dir}; run `python run.py fetch` first"
            )
        if not any(corpus_dir.glob("*.txt")):
            raise BenchmarkError(
                f"corpus directory contains no *.txt files: {corpus_dir}; "
                "run `python run.py fetch` first"
            )
        if args.runs < 1:
            parser.error("--runs must be >= 1")

        run_timing_leg(corpus_dir, args.runs, args.json)
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
