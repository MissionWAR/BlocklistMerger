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

from scripts.benchmark import build_corpus_manifest, main, manifest_digest


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
