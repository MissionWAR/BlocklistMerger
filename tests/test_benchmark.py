"""Self-tests for scripts/benchmark.py — the D-01/D-02 measurement instrument.

Isolation contract: every test here builds its own tiny synthetic corpus under
``tmp_path`` and runs with ``monkeypatch.chdir(tmp_path)``. The production
corpus (``lists/_raw/``, ~132 MB) is never read by this file, and by extension
never read anywhere in the default pytest suite. Heavy benchmark invocations
against the real corpus are manual CLI work outside pytest paths.
"""

import json
import time
from pathlib import Path

import pytest

from scripts.benchmark import (
    build_corpus_manifest,
    extract_perf_fields,
    improvement_percent,
    main,
    manifest_digest,
    meets_floor,
    run_compare,
)


def _make_tiny_corpus(raw_dir: Path) -> None:
    """Create a minimal two-file synthetic corpus."""
    raw_dir.mkdir(parents=True)
    (raw_dir / "alpha.txt").write_text(
        "||example.com^\n||blocked.example.org^\n",
        encoding="utf-8",
    )
    (raw_dir / "beta.txt").write_text("0.0.0.0 ads.example.net\n", encoding="utf-8")


class TestTimingLegSmoke:
    """End-to-end timing-leg smoke tests over a tiny synthetic corpus."""

    def test_end_to_end_report_shape(self, tmp_path: Path, monkeypatch) -> None:
        """One timing run writes an identity-stamped timing report atomically."""
        raw_dir = tmp_path / "raw"
        _make_tiny_corpus(raw_dir)
        report_path = Path("reports/benchmarks/runs/smoke.json")

        monkeypatch.chdir(tmp_path)
        start = time.perf_counter()
        return_code = main(["--corpus", str(raw_dir), "--runs", "1", "--json", str(report_path)])
        duration = time.perf_counter() - start

        assert return_code == 0
        assert duration < 10

        data = json.loads(report_path.read_text(encoding="utf-8"))
        assert data["report_type"] == "corpus_benchmark"
        assert data["mode"] == "timing"
        assert data["corpus"]["file_count"] == 2
        assert len(data["corpus"]["manifest_sha256"]) == 64
        assert data["runs"] == 1
        assert len(data["per_run"]) == 1
        assert len(data["per_run"][0]["output_sha256"]) == 64
        assert isinstance(data["identity"]["git_revision"], str)
        assert data["identity"]["git_revision"]
        assert data["summary"]["median_seconds"] > 0

    def test_manifest_deterministic_and_change_sensitive(self, tmp_path: Path) -> None:
        """Manifest digests are stable across rebuilds and flip when bytes change."""
        raw_dir = tmp_path / "raw"
        _make_tiny_corpus(raw_dir)
        # Non-.txt files must be ignored by the manifest builder entirely.
        (raw_dir / "notes.md").write_text("not a blocklist\n", encoding="utf-8")
        (raw_dir / "subdir").mkdir()
        (raw_dir / "subdir" / "nested.txt").write_text("||ignored.example^\n", encoding="utf-8")

        first = manifest_digest(build_corpus_manifest(raw_dir))
        second = manifest_digest(build_corpus_manifest(raw_dir))
        assert first == second
        assert len(first) == 64

        with open(raw_dir / "alpha.txt", "ab") as handle:
            handle.write(b"||appended.example^\n")

        third = manifest_digest(build_corpus_manifest(raw_dir))
        assert third != first


def _full_timing_document(median: float, digest: str) -> dict[str, object]:
    """Build a synthetic timing report shaped like a real run artifact."""
    return {
        "report_type": "corpus_benchmark",
        "mode": "timing",
        "summary": {"min_seconds": median, "median_seconds": median, "max_seconds": median},
        "corpus": {
            "dir": "lists/_raw",
            "file_count": 2,
            "total_bytes": 64,
            "manifest_sha256": digest,
        },
    }


class TestMemoryLeg:
    """Memory-leg smoke tests over a tiny synthetic corpus."""

    def test_track_memory_reports_positive_peak(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """--track-memory writes a memory-mode report and never mixes in timing."""
        raw_dir = tmp_path / "raw"
        _make_tiny_corpus(raw_dir)
        report_path = Path("reports/benchmarks/runs/memory-smoke.json")

        monkeypatch.chdir(tmp_path)
        return_code = main(
            [
                "--corpus",
                str(raw_dir),
                "--track-memory",
                "--json",
                str(report_path),
            ]
        )

        assert return_code == 0
        data = json.loads(report_path.read_text(encoding="utf-8"))

        assert data["report_type"] == "corpus_benchmark"
        assert data["mode"] == "memory"
        assert isinstance(data["tracemalloc_peak_bytes"], int)
        assert data["tracemalloc_peak_bytes"] > 0
        assert isinstance(data["tracemalloc_current_bytes"], int)
        assert data["tracemalloc_current_bytes"] >= 0

        # Pitfall 6: legs never combine — one invocation, one measurement kind.
        assert "runs" not in data
        assert "durations_seconds" not in data
        assert "summary" not in data
        assert "per_run" not in data


class TestProfileLeg:
    """Profile-leg smoke tests over a tiny synthetic corpus."""

    def test_profile_mode_report_shape(self, tmp_path: Path, monkeypatch) -> None:
        """--profile writes a mode='profile' report with ranking + pstats artifact."""
        raw_dir = tmp_path / "raw"
        _make_tiny_corpus(raw_dir)
        report_path = Path("reports/benchmarks/runs/profile-smoke.json")

        monkeypatch.chdir(tmp_path)
        return_code = main(
            [
                "--corpus",
                str(raw_dir),
                "--profile",
                "--json",
                str(report_path),
            ]
        )

        assert return_code == 0
        data = json.loads(report_path.read_text(encoding="utf-8"))

        assert data["report_type"] == "corpus_benchmark"
        assert data["mode"] == "profile"
        assert isinstance(data["elapsed_seconds"], (int, float))
        assert data["elapsed_seconds"] > 0

        # Ranking entries carry identification + cumulative-time fields.
        top_functions = data["top_functions"]
        assert isinstance(top_functions, list) and top_functions
        for entry in top_functions:
            assert isinstance(entry["function"], str) and entry["function"]
            assert isinstance(entry["location"], str)
            assert isinstance(entry["primitive_calls"], int)
            assert isinstance(entry["total_calls"], int)
            assert isinstance(entry["cumulative_seconds"], (int, float))

        # The raw cProfile artifact exists beside the report under runs/.
        stats_file = Path(data["stats_file"])
        if not stats_file.is_absolute():
            stats_file = Path.cwd() / stats_file
        assert stats_file.is_file()
        assert stats_file.suffix == ".pstats"
        assert Path("reports") / "benchmarks" / "runs" in stats_file.parents

        # Legs never mix: no timing-summary keys leak into a profile document.
        assert "runs" not in data
        assert "durations_seconds" not in data
        assert "summary" not in data
        assert "per_run" not in data
        assert "tracemalloc_peak_bytes" not in data


class TestMemoryTop:
    """--memory-top allocation snapshot tests over a tiny synthetic corpus."""

    def test_memory_top_allocations(self, tmp_path: Path, monkeypatch) -> None:
        """--memory-top N embeds at most N allocation rows into the memory report."""
        raw_dir = tmp_path / "raw"
        _make_tiny_corpus(raw_dir)
        report_path = Path("reports/benchmarks/runs/memory-top-smoke.json")

        monkeypatch.chdir(tmp_path)
        return_code = main(
            [
                "--corpus",
                str(raw_dir),
                "--track-memory",
                "--memory-top",
                "2",
                "--json",
                str(report_path),
            ]
        )

        assert return_code == 0
        data = json.loads(report_path.read_text(encoding="utf-8"))

        top_allocations = data["top_allocations"]
        assert isinstance(top_allocations, list)
        assert len(top_allocations) <= 2
        assert top_allocations  # a real compile allocates something
        for entry in top_allocations:
            assert isinstance(entry["location"], str) and entry["location"]
            assert isinstance(entry["size_bytes"], int) and entry["size_bytes"] > 0
            assert isinstance(entry["count"], int) and entry["count"] > 0

        # Memory-mode leg separation still holds with the extra key present.
        assert "runs" not in data
        assert "summary" not in data
        assert "per_run" not in data

    def test_memory_top_absent_without_flag(self, tmp_path: Path, monkeypatch) -> None:
        """Without --memory-top the memory report carries no top_allocations key."""
        raw_dir = tmp_path / "raw"
        _make_tiny_corpus(raw_dir)
        report_path = Path("reports/benchmarks/runs/memory-notop-smoke.json")

        monkeypatch.chdir(tmp_path)
        return_code = main(
            ["--corpus", str(raw_dir), "--track-memory", "--json", str(report_path)]
        )

        assert return_code == 0
        data = json.loads(report_path.read_text(encoding="utf-8"))
        assert "top_allocations" not in data


class TestCompareMath:
    """Pure delta math and document-shape tolerance on synthetic numbers only."""

    @pytest.mark.parametrize(
        ("pre_median", "post_median", "expected"),
        [
            pytest.param(100.0, 85.0, 15.0, id="fifteen-percent-improvement"),
            pytest.param(100.0, 100.0, 0.0, id="no-change"),
            pytest.param(100.0, 120.0, -20.0, id="regression-is-negative"),
        ],
    )
    def test_improvement_percent_synthetic_math(
        self, pre_median: float, post_median: float, expected: float
    ) -> None:
        result = improvement_percent(pre_median, post_median)
        assert abs(result - expected) < 1e-9

    def test_improvement_percent_rejects_nonpositive_pre_median(self) -> None:
        with pytest.raises(ValueError):
            improvement_percent(0.0, 50.0)

    def test_meets_floor_inclusive_at_exact_boundary(self) -> None:
        # D-01's >=15% floor is inclusive: exactly-at-floor passes.
        assert meets_floor(15.0, 15.0) is True
        assert meets_floor(14.999, 15.0) is False
        assert meets_floor(20.0, 15.0) is True

    def test_meets_floor_honors_custom_floor(self) -> None:
        assert meets_floor(5.0, 5.0) is True
        assert meets_floor(4.999999, 5.0) is False
        assert meets_floor(10.0, 30.0) is False

    def test_extract_perf_fields_full_timing_report(self) -> None:
        document = _full_timing_document(median=1.25, digest="a" * 64)
        assert extract_perf_fields(document) == (1.25, "a" * 64)

    def test_extract_perf_fields_slim_pinned_baseline(self) -> None:
        slim = {"median_seconds": 2.5, "manifest_sha256": "b" * 64}
        assert extract_perf_fields(slim) == (2.5, "b" * 64)

    def test_extract_perf_fields_missing_shapes_raise_actionable_error(self) -> None:
        empty: dict[str, object] = {"report_type": "corpus_benchmark", "mode": "timing"}
        with pytest.raises(ValueError) as exc_info:
            extract_perf_fields(empty)
        message = str(exc_info.value)
        assert "median_seconds" in message
        assert "manifest_sha256" in message

    def test_digest_mismatch_rejected_without_percentage(
        self, tmp_path: Path, capsys
    ) -> None:
        pre_path = tmp_path / "pre.json"
        post_path = tmp_path / "post.json"
        pre_path.write_text(
            json.dumps(_full_timing_document(100.0, "c" * 64)), encoding="utf-8"
        )
        post_path.write_text(
            json.dumps(_full_timing_document(50.0, "d" * 64)), encoding="utf-8"
        )

        exit_code = run_compare(pre_path, post_path, 15.0)
        captured = capsys.readouterr()

        assert exit_code == 1
        # Mismatch details go to stderr (error-stream convention); stdout
        # stays completely verdict-free — no percentage, no PASS/FAIL.
        assert "c" * 64 in captured.err
        assert "d" * 64 in captured.err
        assert "improvement_percent" not in captured.out
        assert "PASS" not in captured.out and "FAIL" not in captured.out
        assert "PASS" not in captured.err and "FAIL" not in captured.err
