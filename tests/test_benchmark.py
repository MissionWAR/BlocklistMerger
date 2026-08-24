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
        runs_root = Path.cwd() / "reports" / "benchmarks" / "runs"
        assert stats_file.parent == runs_root

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


def _make_autos_pair_corpus(raw_dir: Path) -> None:
    """Create a tiny corpus holding a real-gTLD apex/wildcard pair.

    Synthetic TLD names never reach ``abp_wildcards`` (PSL parse bucketing),
    so the same-key pair uses ``autos`` — a genuine gTLD per the 16-02
    recipe — to exercise Direction-A pruning end-to-end.
    """
    raw_dir.mkdir(parents=True)
    (raw_dir / "autos.txt").write_text(
        "||autos^\n||*.autos^\n||example.com^\n",
        encoding="utf-8",
    )


class TestApexTimingFlag:
    """--wildcard-apex-pruning turns one timing leg into the Direction-A ON config."""

    def test_off_report_has_no_compile_flags_key(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """Default OFF leg: absent-key backward compatibility (never emits false)."""
        raw_dir = tmp_path / "raw"
        _make_tiny_corpus(raw_dir)
        report_path = Path("reports/benchmarks/runs/apex-off-smoke.json")

        monkeypatch.chdir(tmp_path)
        return_code = main(
            ["--corpus", str(raw_dir), "--runs", "1", "--json", str(report_path)]
        )

        assert return_code == 0
        data = json.loads(report_path.read_text(encoding="utf-8"))
        assert data["mode"] == "timing"
        assert "compile_flags" not in data
        assert data["output_sha256_stable"] is True
        assert len(data["durations_seconds"]) == 1
        assert data["summary"]["median_seconds"] > 0

    def test_on_report_records_compile_flags(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """ON leg stamps compile_flags == {"wildcard_apex_pruning": True}."""
        raw_dir = tmp_path / "raw"
        _make_tiny_corpus(raw_dir)
        report_path = Path("reports/benchmarks/runs/apex-on-smoke.json")

        monkeypatch.chdir(tmp_path)
        return_code = main(
            [
                "--corpus",
                str(raw_dir),
                "--runs",
                "1",
                "--wildcard-apex-pruning",
                "--json",
                str(report_path),
            ]
        )

        assert return_code == 0
        data = json.loads(report_path.read_text(encoding="utf-8"))
        assert data["compile_flags"] == {"wildcard_apex_pruning": True}
        assert data["output_sha256_stable"] is True

    def test_flag_observably_reaches_compile_rules(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """ON leg output is strictly smaller than OFF on the same-key pair fixture."""
        raw_dir = tmp_path / "raw"
        _make_autos_pair_corpus(raw_dir)
        off_report = Path("reports/benchmarks/runs/apex-behavior-off.json")
        on_report = Path("reports/benchmarks/runs/apex-behavior-on.json")

        monkeypatch.chdir(tmp_path)
        assert main(["--corpus", str(raw_dir), "--runs", "1", "--json", str(off_report)]) == 0
        assert (
            main(
                [
                    "--corpus",
                    str(raw_dir),
                    "--runs",
                    "1",
                    "--wildcard-apex-pruning",
                    "--json",
                    str(on_report),
                ]
            )
            == 0
        )

        off_data = json.loads(off_report.read_text(encoding="utf-8"))
        on_data = json.loads(on_report.read_text(encoding="utf-8"))
        off_bytes = off_data["per_run"][0]["output_byte_size"]
        on_bytes = on_data["per_run"][0]["output_byte_size"]

        # ||*.autos^ vanishes only under the flag: the wildcard line is gone.
        assert on_bytes < off_bytes

    def test_flag_with_track_memory_rejected_upfront(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """flag + --track-memory dies at argparse with exit 2 and no artifacts."""
        raw_dir = tmp_path / "raw"
        _make_tiny_corpus(raw_dir)
        report_path = Path("reports/benchmarks/runs/apex-reject-memory.json")

        monkeypatch.chdir(tmp_path)
        with pytest.raises(SystemExit) as exc_info:
            main(
                [
                    "--corpus",
                    str(raw_dir),
                    "--wildcard-apex-pruning",
                    "--track-memory",
                    "--json",
                    str(report_path),
                ]
            )

        assert exc_info.value.code == 2
        assert not report_path.exists()

    def test_flag_with_profile_rejected_upfront(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """flag + --profile dies at argparse with exit 2 and no artifacts."""
        raw_dir = tmp_path / "raw"
        _make_tiny_corpus(raw_dir)
        report_path = Path("reports/benchmarks/runs/apex-reject-profile.json")
        stats_path = report_path.with_suffix(".pstats")

        monkeypatch.chdir(tmp_path)
        with pytest.raises(SystemExit) as exc_info:
            main(
                [
                    "--corpus",
                    str(raw_dir),
                    "--wildcard-apex-pruning",
                    "--profile",
                    "--json",
                    str(report_path),
                ]
            )

        assert exc_info.value.code == 2
        assert not report_path.exists()
        assert not stats_path.exists()

    def test_flag_with_compare_rejected_upfront(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """flag + --compare dies at argparse: document-only mode compiles nothing."""
        raw_dir = tmp_path / "raw"
        _make_tiny_corpus(raw_dir)
        pre_doc = tmp_path / "unused-pre.json"
        post_doc = tmp_path / "unused-post.json"

        monkeypatch.chdir(tmp_path)
        with pytest.raises(SystemExit) as exc_info:
            main(
                [
                    "--corpus",
                    str(raw_dir),
                    "--wildcard-apex-pruning",
                    "--compare",
                    str(pre_doc),
                    str(post_doc),
                ]
            )

        assert exc_info.value.code == 2


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
