"""Tests for frozen-input benchmark manifest and runner behavior."""

import hashlib
import json
from pathlib import Path

import pytest

from scripts import benchmark_pipeline


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, data: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _source_entry(raw_file: Path, *, url: str = "https://example.com/list.txt") -> dict[str, object]:
    return {
        "url": url,
        "filename": raw_file.name,
        "byte_size": raw_file.stat().st_size,
        "sha256": _sha256(raw_file),
        "source_health_status": "fresh_fetch",
        "cache_status": "fresh_fetch",
    }


def _valid_manifest(tmp_path: Path, dataset_id: str = "tiny") -> Path:
    dataset_dir = tmp_path / "reports" / "benchmarks" / "frozen" / dataset_id
    raw_dir = dataset_dir / "raw"
    raw_dir.mkdir(parents=True)
    raw_file = raw_dir / "example.txt"
    raw_file.write_text("||example.com^\n", encoding="utf-8")
    manifest_path = dataset_dir / "manifest.json"
    _write_json(
        manifest_path,
        {
            "schema_version": 1,
            "dataset_id": dataset_id,
            "raw_dir": "raw",
            "created_at": "2026-05-31T00:00:00Z",
            "python_version": "3.14.0",
            "package_version": "1.5.0",
            "git_revision": "abc1234",
            "runner": {
                "name": "scripts.benchmark_pipeline",
                "schema_version": 1,
            },
            "sources": [_source_entry(raw_file)],
        },
    )
    return manifest_path


def test_validate_manifest_accepts_exact_frozen_raw_set(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    manifest_path = _valid_manifest(tmp_path)

    result = benchmark_pipeline.validate_manifest(manifest_path)

    assert result.dataset_id == "tiny"
    assert result.raw_dir == Path("reports/benchmarks/frozen/tiny/raw").resolve()
    assert result.manifest_path == manifest_path.resolve()
    assert result.source_count == 1
    assert result.manifest_sha256 == _sha256(manifest_path)


def test_validate_manifest_rejects_missing_changed_and_unexpected_raw_files(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    manifest_path = _valid_manifest(tmp_path)
    raw_dir = manifest_path.parent / "raw"

    (raw_dir / "extra.txt").write_text("||extra.example^\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unexpected"):
        benchmark_pipeline.validate_manifest(manifest_path)

    (raw_dir / "extra.txt").unlink()
    raw_file = raw_dir / "example.txt"
    raw_file.write_bytes(b"x" * raw_file.stat().st_size)
    with pytest.raises(ValueError, match="SHA-256"):
        benchmark_pipeline.validate_manifest(manifest_path)

    (raw_dir / "example.txt").unlink()
    with pytest.raises(ValueError, match="missing"):
        benchmark_pipeline.validate_manifest(manifest_path)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("raw_dir", "../raw", "traversal"),
        ("raw_dir", str(Path.cwd() / "raw"), "absolute"),
        ("report_path", "outside/report.json", "reports/benchmarks"),
    ],
)
def test_validate_manifest_rejects_unsafe_manifest_paths(
    tmp_path: Path,
    monkeypatch,
    field: str,
    value: str,
    message: str,
) -> None:
    monkeypatch.chdir(tmp_path)
    manifest_path = _valid_manifest(tmp_path)
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    data[field] = value
    manifest_path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        benchmark_pipeline.validate_manifest(manifest_path)


def test_validate_manifest_rejects_symlink_escape(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    manifest_path = _valid_manifest(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    raw_dir = manifest_path.parent / "raw"
    for path in raw_dir.glob("*.txt"):
        path.unlink()
    raw_dir.rmdir()
    try:
        raw_dir.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable in this environment: {exc}")

    with pytest.raises(ValueError, match="outside"):
        benchmark_pipeline.validate_manifest(manifest_path)


@pytest.mark.parametrize(
    "remove_key",
    [
        "created_at",
        "python_version",
        "package_version",
        "git_revision",
        "runner",
    ],
)
def test_validate_manifest_requires_top_level_d07_identity_fields(
    tmp_path: Path,
    monkeypatch,
    remove_key: str,
) -> None:
    monkeypatch.chdir(tmp_path)
    manifest_path = _valid_manifest(tmp_path)
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    del data[remove_key]
    manifest_path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ValueError, match=remove_key):
        benchmark_pipeline.validate_manifest(manifest_path)


@pytest.mark.parametrize(
    "remove_key",
    [
        "url",
        "filename",
        "byte_size",
        "sha256",
        "source_health_status",
        "cache_status",
    ],
)
def test_validate_manifest_requires_source_d07_identity_fields(
    tmp_path: Path,
    monkeypatch,
    remove_key: str,
) -> None:
    monkeypatch.chdir(tmp_path)
    manifest_path = _valid_manifest(tmp_path)
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    sources = data["sources"]
    assert isinstance(sources, list)
    source = sources[0]
    assert isinstance(source, dict)
    del source[remove_key]
    manifest_path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ValueError, match=remove_key):
        benchmark_pipeline.validate_manifest(manifest_path)
