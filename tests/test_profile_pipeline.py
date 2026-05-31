"""Tests for the dedicated stdlib profiling wrapper."""

import builtins
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import profile_pipeline

ROOT = Path(__file__).resolve().parents[1]
PROFILING_DOC = ROOT / "docs" / "PROFILING.md"


def _write_tiny_input(root: Path) -> Path:
    input_dir = root / "input"
    input_dir.mkdir()
    input_dir.joinpath("one.txt").write_text(
        "\n".join(
            [
                "! comment",
                "||example.com^",
                "||ads.example.com^",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return input_dir


def _run_cli(monkeypatch: pytest.MonkeyPatch, args: list[str]) -> int:
    monkeypatch.setattr(sys, "argv", ["scripts.profile_pipeline", *args])
    return profile_pipeline.main()


def test_profile_cli_writes_stdlib_artifacts_under_run_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    input_dir = _write_tiny_input(tmp_path)

    assert _run_cli(monkeypatch, [str(input_dir), "--run-id", "test-run"]) == 0

    run_dir = tmp_path / "reports" / "profiles" / "test-run"
    cprofile_path = run_dir / "pipeline.cprofile"
    cumulative_path = run_dir / "pstats-cumulative.txt"
    total_time_path = run_dir / "pstats-total-time.txt"
    stats_path = run_dir / "pipeline-stats.json"
    merged_path = run_dir / "merged.txt"

    for artifact in (
        cprofile_path,
        cumulative_path,
        total_time_path,
        stats_path,
        merged_path,
    ):
        assert artifact.exists(), artifact
        assert artifact.stat().st_size > 0, artifact

    assert "function calls" in cumulative_path.read_text(encoding="utf-8")
    assert "function calls" in total_time_path.read_text(encoding="utf-8")
    assert "||example.com^" in merged_path.read_text(encoding="utf-8")

    stats = json.loads(stats_path.read_text(encoding="utf-8"))
    assert stats["schema_version"] == 4
    assert stats["statistics"]["lines_output"] >= 1
    assert "runtime_profile" in stats
    serialized_stats = json.dumps(stats, sort_keys=True)
    assert "pipeline.cprofile" not in serialized_stats
    assert "pstats-cumulative" not in serialized_stats


def test_profile_cli_stdlib_path_does_not_require_optional_profiler_tools(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    input_dir = _write_tiny_input(tmp_path)
    real_import = builtins.__import__

    def reject_optional_profilers(name, *args, **kwargs):
        if name in {"pyperf", "dns"} or name.startswith("dns."):
            raise ModuleNotFoundError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", reject_optional_profilers)
    monkeypatch.setenv("PATH", "")

    assert _run_cli(monkeypatch, [str(input_dir), "--run-id", "stdlib-only"]) == 0
    assert (tmp_path / "reports" / "profiles" / "stdlib-only" / "pipeline.cprofile").exists()


@pytest.mark.parametrize(
    ("flag", "tool", "artifact"),
    [
        ("--py-spy-speedscope", "py-spy", "speedscope"),
        ("--py-spy-flamegraph", "py-spy", "flamegraph"),
        ("--pyperf-json", "pyperf", "pyperf JSON"),
        ("--dns-diagnostics", "dnspython", "DNS diagnostics"),
    ],
)
def test_requested_optional_tools_fail_loudly_when_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    flag: str,
    tool: str,
    artifact: str,
) -> None:
    monkeypatch.chdir(tmp_path)
    input_dir = _write_tiny_input(tmp_path)
    monkeypatch.setattr(profile_pipeline.shutil, "which", lambda _name: None)
    monkeypatch.setattr(profile_pipeline, "_module_available", lambda _name: False)

    assert _run_cli(monkeypatch, [str(input_dir), "--run-id", "missing-tool", flag]) != 0

    captured = capsys.readouterr()
    diagnostic = captured.err
    assert tool in diagnostic
    assert artifact in diagnostic
    assert "manual/profiling-only" in diagnostic
    assert "scheduled publish dependencies" in diagnostic
    assert not (tmp_path / "reports" / "profiles" / "missing-tool" / "pipeline.cprofile").exists()


@pytest.mark.parametrize(
    "args",
    [
        ["--run-id", "bad/run"],
        ["--run-id", "bad\\run"],
        ["--run-id", "outside", "--report-dir", "../profiles"],
        ["--run-id", "source", "--report-dir", "scripts/profiles"],
        ["--run-id", "absolute", "--report-dir", "{outside}"],
    ],
)
def test_profile_cli_rejects_unsafe_report_destinations_before_writing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    args: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    input_dir = _write_tiny_input(tmp_path)
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    resolved_args = [
        str(outside) if value == "{outside}" else value
        for value in args
    ]

    assert _run_cli(monkeypatch, [str(input_dir), *resolved_args]) != 0

    captured = capsys.readouterr()
    assert "ERROR:" in captured.err
    assert not any((tmp_path / "reports" / "profiles").glob("**/pipeline.cprofile"))
    assert not (outside / "pipeline.cprofile").exists()


def test_profile_cli_uses_pipeline_writer_for_stats_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    input_dir = _write_tiny_input(tmp_path)
    calls: dict[str, object] = {}

    def fake_process_files_with_profile(input_dir_arg, output_file_arg):
        calls["input_dir"] = Path(input_dir_arg)
        calls["output_file"] = Path(output_file_arg)
        Path(output_file_arg).write_text("||example.com^\n", encoding="utf-8")
        return SimpleNamespace(
            stats={"lines_output": 1},
            runtime_profile={"stage_durations_seconds": {"clean_seconds": 0.0}},
        )

    def fake_save_stats_json(stats, output_path, total_time, runtime_profile=None):
        calls["stats"] = stats
        calls["stats_path"] = Path(output_path)
        calls["total_time"] = total_time
        calls["runtime_profile"] = runtime_profile
        Path(output_path).write_text(
            json.dumps({"writer": "save_stats_json", "runtime_profile": runtime_profile}),
            encoding="utf-8",
        )

    monkeypatch.setattr(
        profile_pipeline,
        "process_files_with_profile",
        fake_process_files_with_profile,
    )
    monkeypatch.setattr(profile_pipeline, "save_stats_json", fake_save_stats_json)

    assert _run_cli(monkeypatch, [str(input_dir), "--run-id", "writer-check"]) == 0

    run_dir = tmp_path / "reports" / "profiles" / "writer-check"
    assert calls["input_dir"] == input_dir
    assert calls["output_file"] == run_dir / "merged.txt"
    assert calls["stats_path"] == run_dir / "pipeline-stats.json"
    assert calls["stats"] == {"lines_output": 1}
    assert calls["runtime_profile"] == {"stage_durations_seconds": {"clean_seconds": 0.0}}
    assert json.loads((run_dir / "pipeline-stats.json").read_text(encoding="utf-8")) == {
        "writer": "save_stats_json",
        "runtime_profile": {"stage_durations_seconds": {"clean_seconds": 0.0}},
    }


def test_profiling_docs_capture_artifacts_boundaries_and_checkpoint() -> None:
    text = PROFILING_DOC.read_text(encoding="utf-8")

    for snippet in (
        "pipeline.cprofile",
        "pstats-cumulative.txt",
        "pstats-total-time.txt",
        "pipeline-stats.json",
        "merged.txt",
        "reports/profiles/<run-id>/",
        "manual/profiling-only",
        "does not invoke `scripts.profile_pipeline`",
        "local source paths",
        "function names",
        "pyperf",
        "not approved for tracked dependency metadata or install documentation",
    ):
        assert snippet in text

    assert "pip install pyperf" not in text
    assert "pyperf>=" not in text
