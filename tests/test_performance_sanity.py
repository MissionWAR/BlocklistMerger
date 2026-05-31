"""Loose deterministic performance sanity checks for benchmark inputs."""

import json
import time
from pathlib import Path

from scripts import benchmark_pipeline


def test_deterministic_synthetic_benchmark_sanity(tmp_path: Path, monkeypatch) -> None:
    """Synthetic benchmark data should exercise the wrapper path without jitter."""
    monkeypatch.chdir(tmp_path)
    report_path = Path("reports/benchmarks/runs/performance-sanity/benchmark.json")

    start = time.perf_counter()
    benchmark_pipeline.run_synthetic_benchmark(
        dataset_id="performance-sanity",
        file_count=2,
        rules_per_file=100,
        iterations=1,
        report_path=report_path,
    )
    duration = time.perf_counter() - start

    data = json.loads(report_path.read_text(encoding="utf-8"))
    assert duration < 60
    assert data["report_type"] == "synthetic"
    assert data["iterations_requested"] == 1
    assert data["synthetic_parameters"] == {
        "file_count": 2,
        "generator": "fixed arithmetic",
        "rules_per_file": 100,
    }
    assert data["iterations"][0]["stats"]["lines_raw"] == 200
