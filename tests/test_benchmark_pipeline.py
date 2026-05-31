"""Tests for frozen-input benchmark manifest and runner behavior."""

import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

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


def _source_health_report(path: Path, raw_files: list[Path]) -> Path:
    _write_json(
        path,
        {
            "schema_version": 1,
            "source_count": len(raw_files),
            "totals_by_status": {
                "fresh_fetch": len(raw_files),
                "validated_cache": 0,
                "fallback_cache": 0,
                "stale_cache": 0,
                "failed": 0,
            },
            "sources": [
                {
                    "url": f"https://example.com/{raw_file.name}",
                    "filename": raw_file.name,
                    "status": "fresh_fetch",
                    "changed": True,
                    "byte_size": raw_file.stat().st_size,
                    "sha256": _sha256(raw_file),
                    "cache_age_seconds": None,
                    "failure_reason": None,
                }
                for raw_file in raw_files
            ],
        },
    )
    return path


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


def test_freeze_copies_local_raw_files_and_writes_manifest_under_frozen_root(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    input_dir = tmp_path / "lists" / "_raw"
    input_dir.mkdir(parents=True)
    raw_a = input_dir / "a.txt"
    raw_b = input_dir / "b.txt"
    raw_a.write_text("||a.example^\n", encoding="utf-8")
    raw_b.write_text("||b.example^\n", encoding="utf-8")
    (input_dir / "ignored.md").write_text("not copied\n", encoding="utf-8")
    health_report = _source_health_report(
        tmp_path / "reports" / "source-health.json",
        [raw_a, raw_b],
    )

    manifest_path = benchmark_pipeline.freeze_dataset(
        input_dir=input_dir,
        source_health_report=health_report,
        dataset_id="local-smoke",
    )

    assert manifest_path == (
        tmp_path / "reports" / "benchmarks" / "frozen" / "local-smoke" / "manifest.json"
    )
    frozen_raw = manifest_path.parent / "raw"
    assert sorted(path.name for path in frozen_raw.iterdir()) == ["a.txt", "b.txt"]
    assert (frozen_raw / "a.txt").read_text(encoding="utf-8") == "||a.example^\n"
    result = benchmark_pipeline.validate_manifest(manifest_path)
    assert result.dataset_id == "local-smoke"
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert [source["url"] for source in data["sources"]] == [
        "https://example.com/a.txt",
        "https://example.com/b.txt",
    ]
    assert {source["source_health_status"] for source in data["sources"]} == {"fresh_fetch"}
    assert not (tmp_path / "reports" / "benchmarks" / "a.txt").exists()


def test_freeze_fails_when_source_health_metadata_is_missing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    input_dir = tmp_path / "lists" / "_raw"
    input_dir.mkdir(parents=True)
    raw_file = input_dir / "a.txt"
    raw_file.write_text("||a.example^\n", encoding="utf-8")
    health_report = tmp_path / "reports" / "source-health.json"
    _write_json(
        health_report,
        {
            "schema_version": 1,
            "source_count": 1,
            "totals_by_status": {},
            "sources": [{"filename": "a.txt", "status": "fresh_fetch"}],
        },
    )

    with pytest.raises(ValueError, match="metadata"):
        benchmark_pipeline.freeze_dataset(input_dir, health_report, "missing-meta")


def test_run_frozen_validates_manifest_calls_pipeline_and_writes_report(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    manifest_path = _valid_manifest(tmp_path)
    report_path = tmp_path / "reports" / "benchmarks" / "runs" / "tiny-run" / "benchmark.json"
    calls: list[tuple[Path, Path]] = []

    def fake_process_files_with_profile(input_dir, output_file, **kwargs):
        calls.append((Path(input_dir), Path(output_file)))
        Path(output_file).write_text("||example.com^\n", encoding="utf-8")
        return SimpleNamespace(
            stats={
                "files_processed": 1,
                "lines_raw": 1,
                "lines_clean": 1,
                "lines_output": 1,
            },
            runtime_profile={
                "stage_durations_seconds": {"clean_seconds": 0.01, "compile_seconds": 0.02},
                "compiler_cardinalities": {"abp_rule_keys": 1},
            },
        )

    monkeypatch.setattr(
        benchmark_pipeline,
        "process_files_with_profile",
        fake_process_files_with_profile,
    )

    written_report = benchmark_pipeline.run_frozen_benchmark(
        manifest_path=manifest_path,
        iterations=2,
        report_path=report_path,
    )

    assert written_report == report_path.resolve()
    assert len(calls) == 2
    assert calls[0][0] == (tmp_path / "reports" / "benchmarks" / "frozen" / "tiny" / "raw")
    assert all(output.parent.parent == report_path.parent for _, output in calls)
    data = json.loads(report_path.read_text(encoding="utf-8"))
    assert data["schema_version"] == 1
    assert data["report_type"] == "frozen"
    assert data["manifest"]["dataset_id"] == "tiny"
    assert data["manifest"]["sha256"] == _sha256(manifest_path)
    assert data["iterations_requested"] == 2
    assert len(data["iterations"]) == 2
    assert data["summary"]["p50_seconds"] >= 0
    assert data["summary"]["p95_seconds"] >= 0
    serialized = json.dumps(data, sort_keys=True)
    assert str(tmp_path) not in serialized


def test_run_frozen_rejects_mutable_raw_inputs_without_manifest(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    mutable_raw = tmp_path / "lists" / "_raw"
    mutable_raw.mkdir(parents=True)
    mutable_raw.joinpath("a.txt").write_text("||a.example^\n", encoding="utf-8")

    with pytest.raises(ValueError, match="frozen"):
        benchmark_pipeline.run_frozen_benchmark(
            manifest_path=mutable_raw,
            iterations=1,
            report_path=tmp_path / "reports" / "benchmarks" / "runs" / "bad.json",
        )


def test_benchmark_cli_freeze_and_run_frozen(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    input_dir = tmp_path / "lists" / "_raw"
    input_dir.mkdir(parents=True)
    raw_file = input_dir / "a.txt"
    raw_file.write_text("||a.example^\n", encoding="utf-8")
    health_report = _source_health_report(tmp_path / "reports" / "source-health.json", [raw_file])

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "scripts.benchmark_pipeline",
            "freeze",
            "--input-dir",
            str(input_dir),
            "--source-health-report",
            str(health_report),
            "--dataset-id",
            "cli-smoke",
        ],
    )

    assert benchmark_pipeline.main() == 0
    manifest_path = (
        tmp_path / "reports" / "benchmarks" / "frozen" / "cli-smoke" / "manifest.json"
    )
    assert manifest_path.exists()

    def fake_process_files_with_profile(input_dir, output_file, **kwargs):
        Path(output_file).write_text("||a.example^\n", encoding="utf-8")
        return SimpleNamespace(
            stats={"lines_output": 1},
            runtime_profile={"stage_durations_seconds": {"clean_seconds": 0.0}},
        )

    monkeypatch.setattr(
        benchmark_pipeline,
        "process_files_with_profile",
        fake_process_files_with_profile,
    )
    report_path = tmp_path / "reports" / "benchmarks" / "runs" / "cli" / "benchmark.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "scripts.benchmark_pipeline",
            "run-frozen",
            "--manifest",
            str(manifest_path),
            "--iterations",
            "1",
            "--report",
            str(report_path),
        ],
    )

    assert benchmark_pipeline.main() == 0
    assert json.loads(report_path.read_text(encoding="utf-8"))["report_type"] == "frozen"
