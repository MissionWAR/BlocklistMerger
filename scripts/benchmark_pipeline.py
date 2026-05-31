#!/usr/bin/env python3
"""Frozen-input benchmark helpers for the blocklist pipeline."""

import hashlib
import json
from pathlib import Path
from typing import Final, NamedTuple, TypedDict


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


def _manifest_path(path: str | Path) -> Path:
    """Return a resolved manifest path under the frozen benchmark root."""
    return _relative_to_root(Path(path), _resolved_root(FROZEN_ROOT), "manifest path")


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


def _load_json_object(path: Path) -> dict[str, object]:
    """Load a JSON object from disk."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("manifest must be a JSON object")
    return data


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
