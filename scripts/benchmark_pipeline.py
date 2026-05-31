#!/usr/bin/env python3
"""Frozen-input benchmark helpers for the blocklist pipeline."""

import argparse
import hashlib
import json
import platform
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Final, NamedTuple, TypedDict

from scripts import __version__


BENCHMARK_SCHEMA_VERSION: Final[int] = 1
BENCHMARK_ROOT: Final[Path] = Path("reports/benchmarks")
FROZEN_ROOT: Final[Path] = BENCHMARK_ROOT / "frozen"
RUNS_ROOT: Final[Path] = BENCHMARK_ROOT / "runs"

_REQUIRED_MANIFEST_FIELDS: Final[tuple[str, ...]] = (
    "schema_version",
    "dataset_id",
    "created_at",
    "python_version",
    "package_version",
    "git_revision",
    "runner",
    "sources",
)
_REQUIRED_SOURCE_FIELDS: Final[tuple[str, ...]] = (
    "url",
    "filename",
    "byte_size",
    "sha256",
    "source_health_status",
    "cache_status",
)
_DATASET_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class ManifestSource(TypedDict):
    """One source entry in a frozen benchmark manifest."""

    url: str
    filename: str
    byte_size: int
    sha256: str
    source_health_status: str
    cache_status: str


class ManifestValidationResult(NamedTuple):
    """Normalized frozen manifest identity returned after validation."""

    manifest_path: Path
    manifest_sha256: str
    dataset_id: str
    raw_dir: Path
    sources: list[ManifestSource]
    python_version: str
    package_version: str
    git_revision: str
    runner: dict[str, object]

    @property
    def source_count(self) -> int:
        """Return the number of manifest sources."""
        return len(self.sources)


class BenchmarkIteration(TypedDict):
    """One measured pipeline iteration in a benchmark report."""

    index: int
    elapsed_seconds: float
    merged_output: str
    output_byte_size: int
    output_sha256: str
    stats: dict[str, object]
    runtime_profile: dict[str, object]


def _rooted(path: Path) -> Path:
    """Return an absolute path rooted at the current working directory."""
    return path if path.is_absolute() else Path.cwd() / path


def _resolved_root(path: Path) -> Path:
    """Return the resolved absolute path for a configured benchmark root."""
    return _rooted(path).resolve(strict=False)


def _relative_to_root(path: Path, root: Path, label: str) -> Path:
    """Resolve a path and require it to stay below a configured root."""
    candidate = _rooted(path).resolve(strict=True)
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        msg = f"{label} must be under {root.as_posix()}"
        raise ValueError(msg) from exc
    return candidate


def _relative_to_root_existing_or_parent(path: Path, root: Path, label: str) -> Path:
    """Resolve a path whose parent exists and require it below a configured root."""
    candidate = _rooted(path).resolve(strict=False)
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        msg = f"{label} must be under {root.as_posix()}"
        raise ValueError(msg) from exc
    return candidate


def _manifest_path(path: str | Path) -> Path:
    """Return a resolved manifest path under the frozen benchmark root."""
    return _relative_to_root(Path(path), _resolved_root(FROZEN_ROOT), "manifest path")


def _run_report_path(path: str | Path) -> Path:
    """Return a resolved benchmark report path under the runs root."""
    report_path = _relative_to_root_existing_or_parent(
        Path(path),
        _resolved_root(RUNS_ROOT),
        "report path",
    )
    if report_path.suffix != ".json":
        raise ValueError("report path must point to a .json file")
    return report_path


def _validate_relative_child_path(value: object, *, label: str) -> Path:
    """Return a safe relative path without absolute or traversal segments."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty relative path")

    path = Path(value)
    if path.is_absolute():
        raise ValueError(f"{label} must not be absolute")
    if ".." in path.parts:
        raise ValueError(f"{label} must not contain traversal segments")
    return path


def _resolve_manifest_raw_dir(manifest_path: Path, raw_dir_value: object) -> Path:
    """Resolve and validate the manifest raw input directory."""
    relative_raw_dir = _validate_relative_child_path(raw_dir_value, label="raw_dir")
    raw_dir = (manifest_path.parent / relative_raw_dir).resolve(strict=True)
    try:
        raw_dir.relative_to(manifest_path.parent.resolve(strict=True))
    except ValueError as exc:
        msg = "raw_dir must resolve inside the frozen dataset directory"
        raise ValueError(msg) from exc
    if not raw_dir.is_dir():
        raise ValueError("raw_dir must exist and be a directory")
    return raw_dir


def _validate_optional_report_path(value: object) -> None:
    """Validate an optional manifest report path when present."""
    if value is None:
        return
    relative_report = _validate_relative_child_path(value, label="report_path")
    report_path = _rooted(relative_report).resolve(strict=False)
    try:
        report_path.relative_to(_resolved_root(BENCHMARK_ROOT))
    except ValueError as exc:
        msg = "report_path must be under reports/benchmarks"
        raise ValueError(msg) from exc


def _sha256(path: Path) -> str:
    """Return a SHA-256 hex digest for a file."""
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_write_json(path: Path, data: dict[str, object]) -> None:
    """Write JSON atomically with deterministic formatting."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(".tmp")
    with open(temp_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")
    temp_path.replace(path)


def _utc_timestamp() -> str:
    """Return a UTC timestamp for benchmark artifacts."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _compact_path(path: Path) -> str:
    """Return a non-absolute path reference suitable for reports."""
    resolved = path.resolve(strict=False)
    try:
        return resolved.relative_to(Path.cwd().resolve(strict=False)).as_posix()
    except ValueError:
        for marker in ("reports", "lists"):
            if marker in resolved.parts:
                return Path(*resolved.parts[resolved.parts.index(marker) :]).as_posix()
        return resolved.name


def _load_json_object(path: Path) -> dict[str, object]:
    """Load a JSON object from disk."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("manifest must be a JSON object")
    return data


def _load_source_health_sources(path: Path) -> dict[str, dict[str, object]]:
    """Load source-health records keyed by deterministic raw filename."""
    data = _load_json_object(path)
    sources = data.get("sources")
    if not isinstance(sources, list):
        raise ValueError("source-health report must contain a sources list")

    by_filename: dict[str, dict[str, object]] = {}
    for source in sources:
        if not isinstance(source, dict):
            continue
        filename = source.get("filename")
        if isinstance(filename, str) and filename:
            by_filename[filename] = dict(source)
    return by_filename


def _require_string(data: dict[str, object], field: str) -> str:
    """Return a required non-empty string field."""
    value = data.get(field)
    if not isinstance(value, str) or not value:
        raise ValueError(f"manifest field {field!r} is required")
    return value


def _require_source_string(source: dict[str, object], field: str) -> str:
    """Return a required non-empty source string field."""
    value = source.get(field)
    if not isinstance(value, str) or not value:
        raise ValueError(f"manifest source field {field!r} is required")
    return value


def _require_source_size(source: dict[str, object]) -> int:
    """Return a required non-negative source byte size."""
    value = source.get("byte_size")
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("manifest source field 'byte_size' is required")
    return value


def _validate_filename(filename: str) -> None:
    """Reject path-like or non-text source filenames."""
    path = Path(filename)
    if path.is_absolute() or ".." in path.parts or filename != path.name:
        raise ValueError(f"manifest source filename is unsafe: {filename!r}")
    if path.suffix != ".txt":
        raise ValueError(f"manifest source filename must be a .txt file: {filename!r}")


def _validate_dataset_id(dataset_id: str) -> str:
    """Return a safe dataset id for a benchmark artifact path."""
    if not _DATASET_ID_PATTERN.fullmatch(dataset_id):
        raise ValueError("dataset_id must contain only letters, numbers, dots, dashes, or underscores")
    return dataset_id


def _dataset_dir(dataset_id: str) -> Path:
    """Return a safe frozen dataset directory."""
    safe_dataset_id = _validate_dataset_id(dataset_id)
    dataset_dir = _resolved_root(FROZEN_ROOT) / safe_dataset_id
    try:
        dataset_dir.resolve(strict=False).relative_to(_resolved_root(FROZEN_ROOT))
    except ValueError as exc:
        raise ValueError("dataset directory must stay under reports/benchmarks/frozen") from exc
    return dataset_dir


def _git_revision() -> str:
    """Return a best-effort git revision for benchmark identity."""
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


def _manifest_sources(data: dict[str, object]) -> list[ManifestSource]:
    """Validate and normalize source entries from manifest data."""
    sources = data.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ValueError("manifest field 'sources' must be a non-empty list")

    normalized: list[ManifestSource] = []
    seen_filenames: set[str] = set()
    for index, raw_source in enumerate(sources):
        if not isinstance(raw_source, dict):
            raise ValueError(f"manifest source #{index} must be an object")
        source = dict(raw_source)
        for field in _REQUIRED_SOURCE_FIELDS:
            if field not in source:
                raise ValueError(f"manifest source field {field!r} is required")
        filename = _require_source_string(source, "filename")
        _validate_filename(filename)
        if filename in seen_filenames:
            raise ValueError(f"duplicate manifest source filename: {filename}")
        seen_filenames.add(filename)
        normalized.append(
            {
                "url": _require_source_string(source, "url"),
                "filename": filename,
                "byte_size": _require_source_size(source),
                "sha256": _require_source_string(source, "sha256"),
                "source_health_status": _require_source_string(
                    source,
                    "source_health_status",
                ),
                "cache_status": _require_source_string(source, "cache_status"),
            }
        )
    return normalized


def _validate_manifest_raw_files(raw_dir: Path, sources: list[ManifestSource]) -> None:
    """Require raw files to match the manifest exactly."""
    expected = {source["filename"] for source in sources}
    actual = {path.name for path in raw_dir.glob("*.txt")}
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    if missing:
        raise ValueError(f"manifest raw file missing: {missing[0]}")
    if unexpected:
        raise ValueError(f"unexpected raw file in frozen dataset: {unexpected[0]}")

    for source in sources:
        raw_file = raw_dir / source["filename"]
        actual_size = raw_file.stat().st_size
        if actual_size != source["byte_size"]:
            raise ValueError(
                f"raw file byte size mismatch for {source['filename']}: "
                f"expected {source['byte_size']}, got {actual_size}"
            )
        actual_sha256 = _sha256(raw_file)
        if actual_sha256 != source["sha256"]:
            raise ValueError(f"raw file SHA-256 mismatch for {source['filename']}")


def _manifest_document(
    *,
    dataset_id: str,
    sources: list[ManifestSource],
    source_health_report: str | None = None,
    synthetic_parameters: dict[str, object] | None = None,
) -> dict[str, object]:
    """Return a versioned frozen benchmark manifest object."""
    manifest: dict[str, object] = {
        "schema_version": BENCHMARK_SCHEMA_VERSION,
        "dataset_id": dataset_id,
        "raw_dir": "raw",
        "created_at": _utc_timestamp(),
        "python_version": platform.python_version(),
        "package_version": __version__,
        "git_revision": _git_revision(),
        "runner": {
            "name": "scripts.benchmark_pipeline",
            "schema_version": BENCHMARK_SCHEMA_VERSION,
        },
        "sources": sources,
    }
    if source_health_report is not None:
        manifest["source_health_report"] = source_health_report
    if synthetic_parameters is not None:
        manifest["synthetic_parameters"] = synthetic_parameters
    return manifest


def _copy_raw_file(source: Path, destination: Path) -> None:
    """Copy one raw file through a sibling temp path."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_path = destination.with_suffix(".tmp")
    try:
        shutil.copyfile(source, temp_path)
        temp_path.replace(destination)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise


def _source_health_manifest_entry(raw_file: Path, source: dict[str, object]) -> ManifestSource:
    """Build a manifest source entry from a raw file and source-health metadata."""
    missing = [
        field
        for field in ("url", "status", "sha256", "byte_size")
        if field not in source or source[field] in {None, ""}
    ]
    if missing:
        raise ValueError(f"source-health metadata incomplete for {raw_file.name}: {missing[0]}")

    url = source["url"]
    status = source["status"]
    sha256 = source["sha256"]
    byte_size = source["byte_size"]
    if (
        not isinstance(url, str)
        or not isinstance(status, str)
        or not isinstance(sha256, str)
        or isinstance(byte_size, bool)
        or not isinstance(byte_size, int)
    ):
        raise ValueError(f"source-health metadata invalid for {raw_file.name}")

    actual_size = raw_file.stat().st_size
    actual_sha256 = _sha256(raw_file)
    if byte_size != actual_size or sha256 != actual_sha256:
        raise ValueError(f"source-health metadata does not match local raw file {raw_file.name}")

    return {
        "url": url,
        "filename": raw_file.name,
        "byte_size": actual_size,
        "sha256": actual_sha256,
        "source_health_status": status,
        "cache_status": status,
    }


def freeze_dataset(
    input_dir: str | Path,
    source_health_report: str | Path,
    dataset_id: str,
) -> Path:
    """Freeze local raw ``.txt`` inputs and write a validated manifest."""
    input_path = Path(input_dir).resolve(strict=True)
    if not input_path.is_dir():
        raise ValueError("input_dir must be an existing directory")

    raw_files = sorted(path for path in input_path.glob("*.txt") if path.is_file())
    if not raw_files:
        raise ValueError("input_dir must contain at least one .txt raw file")

    health_path = Path(source_health_report).resolve(strict=True)
    health_sources = _load_source_health_sources(health_path)
    dataset_path = _dataset_dir(dataset_id)
    raw_dir = dataset_path / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    manifest_sources: list[ManifestSource] = []
    for raw_file in raw_files:
        source = health_sources.get(raw_file.name)
        if source is None:
            raise ValueError(f"source-health metadata unavailable for {raw_file.name}")
        destination = raw_dir / raw_file.name
        _copy_raw_file(raw_file, destination)
        manifest_sources.append(_source_health_manifest_entry(destination, source))

    existing_raw = {path.name for path in raw_dir.glob("*.txt")}
    expected_raw = {source["filename"] for source in manifest_sources}
    unexpected = sorted(existing_raw - expected_raw)
    if unexpected:
        raise ValueError(f"unexpected existing raw file in frozen dataset: {unexpected[0]}")

    try:
        source_health_ref = _compact_path(health_path)
    except OSError:
        source_health_ref = None
    manifest_path = dataset_path / "manifest.json"
    _atomic_write_json(
        manifest_path,
        _manifest_document(
            dataset_id=dataset_id,
            sources=manifest_sources,
            source_health_report=source_health_ref,
        ),
    )
    validate_manifest(manifest_path)
    return manifest_path.resolve(strict=True)


def process_files_with_profile(*args, **kwargs):
    """Lazily call the production pipeline path used by benchmark runs."""
    from scripts.pipeline import process_files_with_profile as _process_files_with_profile

    return _process_files_with_profile(*args, **kwargs)


def _percentile(values: list[float], percentile: float) -> float:
    """Return a simple nearest-rank percentile from observed durations."""
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int((percentile / 100) * len(ordered) + 0.999999) - 1))
    return ordered[index]


def _benchmark_summary(durations: list[float]) -> dict[str, float]:
    """Return compact duration summary fields."""
    if not durations:
        return {"min_seconds": 0.0, "max_seconds": 0.0, "p50_seconds": 0.0, "p95_seconds": 0.0}
    ordered = sorted(durations)
    midpoint = len(ordered) // 2
    if len(ordered) % 2:
        p50 = ordered[midpoint]
    else:
        p50 = (ordered[midpoint - 1] + ordered[midpoint]) / 2
    return {
        "min_seconds": round(min(durations), 6),
        "max_seconds": round(max(durations), 6),
        "p50_seconds": round(p50, 6),
        "p95_seconds": round(_percentile(durations, 95), 6),
    }


def _run_pipeline_iterations(
    validation: ManifestValidationResult,
    *,
    iterations: int,
    report_path: Path,
) -> list[BenchmarkIteration]:
    """Run the production pipeline path repeatedly for one validated manifest."""
    observed: list[BenchmarkIteration] = []
    for index in range(1, iterations + 1):
        validate_manifest(validation.manifest_path)
        iteration_dir = report_path.parent / f"iteration-{index:04d}"
        iteration_dir.mkdir(parents=True, exist_ok=True)
        output_file = iteration_dir / "merged.txt"

        start = time.perf_counter()
        result = process_files_with_profile(validation.raw_dir, output_file)
        elapsed = time.perf_counter() - start

        observed.append(
            {
                "index": index,
                "elapsed_seconds": round(elapsed, 6),
                "merged_output": _compact_path(output_file),
                "output_byte_size": output_file.stat().st_size if output_file.exists() else 0,
                "output_sha256": _sha256(output_file) if output_file.exists() else "",
                "stats": dict(result.stats),
                "runtime_profile": dict(result.runtime_profile),
            }
        )
    return observed


def _benchmark_report(
    validation: ManifestValidationResult,
    *,
    report_type: str,
    iterations: list[BenchmarkIteration],
    iterations_requested: int,
    synthetic_parameters: dict[str, object] | None = None,
) -> dict[str, object]:
    """Return the JSON benchmark report object."""
    durations = [iteration["elapsed_seconds"] for iteration in iterations]
    report: dict[str, object] = {
        "schema_version": BENCHMARK_SCHEMA_VERSION,
        "report_type": report_type,
        "generated_at": _utc_timestamp(),
        "command": "run-synthetic" if report_type == "synthetic" else "run-frozen",
        "python_version": platform.python_version(),
        "package_version": __version__,
        "git_revision": _git_revision(),
        "iterations_requested": iterations_requested,
        "manifest": {
            "path": _compact_path(validation.manifest_path),
            "sha256": validation.manifest_sha256,
            "dataset_id": validation.dataset_id,
            "source_count": validation.source_count,
            "python_version": validation.python_version,
            "package_version": validation.package_version,
            "git_revision": validation.git_revision,
            "runner": validation.runner,
        },
        "iterations": iterations,
        "summary": _benchmark_summary(durations),
    }
    if synthetic_parameters is not None:
        report["synthetic_parameters"] = synthetic_parameters
    return report


def run_frozen_benchmark(
    manifest_path: str | Path,
    iterations: int,
    report_path: str | Path,
) -> Path:
    """Run benchmark iterations from a validated frozen manifest."""
    if iterations < 1:
        raise ValueError("iterations must be at least 1")
    report = _run_report_path(report_path)
    validation = validate_manifest(manifest_path)
    iterations_data = _run_pipeline_iterations(validation, iterations=iterations, report_path=report)
    _atomic_write_json(
        report,
        _benchmark_report(
            validation,
            report_type="frozen",
            iterations=iterations_data,
            iterations_requested=iterations,
        ),
    )
    return report


def synthetic_rule(file_index: int, rule_index: int) -> str:
    """Return one deterministic synthetic block rule."""
    first = (file_index * 37 + rule_index * 17) % 997
    second = (file_index * 53 + rule_index * 29) % 991
    return f"||synthetic-{file_index:03d}-{rule_index:05d}-{first:03d}-{second:03d}.example^"


def write_synthetic_raw_inputs(
    raw_dir: str | Path,
    *,
    file_count: int,
    rules_per_file: int,
) -> list[Path]:
    """Write deterministic synthetic raw inputs and return created files."""
    if file_count < 1:
        raise ValueError("file_count must be at least 1")
    if rules_per_file < 1:
        raise ValueError("rules_per_file must be at least 1")

    output_dir = Path(raw_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for file_index in range(file_count):
        path = output_dir / f"synthetic-{file_index:03d}.txt"
        lines = [synthetic_rule(file_index, rule_index) for rule_index in range(rules_per_file)]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        paths.append(path)
    return paths


def _synthetic_sources(paths: list[Path], dataset_id: str) -> list[ManifestSource]:
    """Return manifest source entries for deterministic synthetic files."""
    return [
        {
            "url": f"synthetic://{dataset_id}/{path.name}",
            "filename": path.name,
            "byte_size": path.stat().st_size,
            "sha256": _sha256(path),
            "source_health_status": "synthetic",
            "cache_status": "synthetic",
        }
        for path in paths
    ]


def run_synthetic_benchmark(
    *,
    dataset_id: str,
    file_count: int,
    rules_per_file: int,
    iterations: int,
    report_path: str | Path,
) -> Path:
    """Create deterministic synthetic data and run the same benchmark path."""
    if iterations < 1:
        raise ValueError("iterations must be at least 1")
    report = _run_report_path(report_path)
    dataset_path = _dataset_dir(dataset_id)
    raw_dir = dataset_path / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    for old_raw in raw_dir.glob("*.txt"):
        old_raw.unlink()

    paths = write_synthetic_raw_inputs(
        raw_dir,
        file_count=file_count,
        rules_per_file=rules_per_file,
    )
    parameters = {
        "file_count": file_count,
        "rules_per_file": rules_per_file,
        "generator": "fixed arithmetic",
    }
    manifest_path = dataset_path / "manifest.json"
    _atomic_write_json(
        manifest_path,
        _manifest_document(
            dataset_id=dataset_id,
            sources=_synthetic_sources(paths, dataset_id),
            synthetic_parameters=parameters,
        ),
    )
    validation = validate_manifest(manifest_path)
    iterations_data = _run_pipeline_iterations(validation, iterations=iterations, report_path=report)
    _atomic_write_json(
        report,
        _benchmark_report(
            validation,
            report_type="synthetic",
            iterations=iterations_data,
            iterations_requested=iterations,
            synthetic_parameters=parameters,
        ),
    )
    return report


def validate_manifest(manifest_path: str | Path) -> ManifestValidationResult:
    """
    Validate a frozen benchmark manifest and return normalized identity data.

    Validation fails closed for path traversal, absolute manifest-controlled
    paths, symlink escapes, missing D-07 identity fields, changed raw content,
    missing raw files, and unexpected raw ``.txt`` files.
    """
    path = _manifest_path(manifest_path)
    data = _load_json_object(path)

    for field in _REQUIRED_MANIFEST_FIELDS:
        if field not in data:
            raise ValueError(f"manifest field {field!r} is required")
    if data["schema_version"] != BENCHMARK_SCHEMA_VERSION:
        raise ValueError(f"manifest schema_version must be {BENCHMARK_SCHEMA_VERSION}")

    raw_dir = _resolve_manifest_raw_dir(path, data.get("raw_dir", "raw"))
    _validate_optional_report_path(data.get("report_path"))
    sources = _manifest_sources(data)
    _validate_manifest_raw_files(raw_dir, sources)

    runner = data["runner"]
    if not isinstance(runner, dict) or not runner.get("name"):
        raise ValueError("manifest field 'runner' is required")

    return ManifestValidationResult(
        manifest_path=path,
        manifest_sha256=_sha256(path),
        dataset_id=_require_string(data, "dataset_id"),
        raw_dir=raw_dir,
        sources=sources,
        python_version=_require_string(data, "python_version"),
        package_version=_require_string(data, "package_version"),
        git_revision=_require_string(data, "git_revision"),
        runner=dict(runner),
    )


def _build_parser() -> argparse.ArgumentParser:
    """Build the benchmark CLI parser."""
    parser = argparse.ArgumentParser(
        prog="scripts.benchmark_pipeline",
        description="Freeze and benchmark local blocklist inputs without network fetches.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    freeze = subparsers.add_parser("freeze", help="Freeze local raw inputs into reports/benchmarks")
    freeze.add_argument("--input-dir", required=True, help="Directory containing local raw .txt files")
    freeze.add_argument(
        "--source-health-report",
        required=True,
        help="Existing source-health JSON report with URL/status/SHA metadata",
    )
    freeze.add_argument("--dataset-id", required=True, help="Safe frozen dataset identifier")

    run_frozen = subparsers.add_parser(
        "run-frozen",
        help="Benchmark a validated frozen manifest",
    )
    run_frozen.add_argument("--manifest", required=True, help="Frozen manifest path")
    run_frozen.add_argument("--iterations", type=int, default=1, help="Benchmark iterations")
    run_frozen.add_argument("--report", required=True, help="Benchmark report JSON path")

    run_synthetic = subparsers.add_parser(
        "run-synthetic",
        help="Benchmark deterministic synthetic raw inputs",
    )
    run_synthetic.add_argument("--dataset-id", default="synthetic-smoke")
    run_synthetic.add_argument("--files", type=int, default=2)
    run_synthetic.add_argument("--rules-per-file", type=int, default=100)
    run_synthetic.add_argument("--iterations", type=int, default=1)
    run_synthetic.add_argument("--report", required=True, help="Benchmark report JSON path")
    return parser


def main() -> int:
    """CLI entry point."""
    parser = _build_parser()
    args = parser.parse_args()
    try:
        if args.command == "freeze":
            manifest = freeze_dataset(
                input_dir=args.input_dir,
                source_health_report=args.source_health_report,
                dataset_id=args.dataset_id,
            )
            print(f"Frozen manifest: {_compact_path(manifest)}")
            return 0
        if args.command == "run-frozen":
            report = run_frozen_benchmark(
                manifest_path=args.manifest,
                iterations=args.iterations,
                report_path=args.report,
            )
            print(f"Benchmark report: {_compact_path(report)}")
            return 0
        if args.command == "run-synthetic":
            report = run_synthetic_benchmark(
                dataset_id=args.dataset_id,
                file_count=args.files,
                rules_per_file=args.rules_per_file,
                iterations=args.iterations,
                report_path=args.report,
            )
            print(f"Synthetic benchmark report: {_compact_path(report)}")
            return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
