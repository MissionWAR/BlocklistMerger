"""Focused tests for compact runtime evidence helpers."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import scripts.pipeline as pipeline_module
from scripts.downloader import (
    SourceHealth,
    build_source_health_report,
    source_health_runtime_summary,
)


def _source_health_report():
    return build_source_health_report(
        [
            SourceHealth(
                url="https://example.com/fresh.txt",
                filename="fresh.txt",
                status="fresh_fetch",
                changed=True,
                byte_size=100,
                sha256="fresh-hash",
                cache_age_seconds=None,
                failure_reason=None,
            ),
            SourceHealth(
                url="https://example.com/validated.txt",
                filename="validated.txt",
                status="validated_cache",
                changed=False,
                byte_size=200,
                sha256="validated-hash",
                cache_age_seconds=30,
                failure_reason=None,
            ),
            SourceHealth(
                url="https://example.com/fallback.txt",
                filename="fallback.txt",
                status="fallback_cache",
                changed=False,
                byte_size=300,
                sha256="fallback-hash",
                cache_age_seconds=60,
                failure_reason="HTTP 500",
            ),
            SourceHealth(
                url="https://example.com/stale.txt",
                filename="stale.txt",
                status="stale_cache",
                changed=False,
                byte_size=400,
                sha256="stale-hash",
                cache_age_seconds=200_000,
                failure_reason="Timeout",
            ),
            SourceHealth(
                url="https://example.com/failed.txt",
                filename="failed.txt",
                status="failed",
                changed=False,
                byte_size=0,
                sha256=None,
                cache_age_seconds=None,
                failure_reason="DNS failure",
            ),
        ],
        generated_at="2026-05-31T15:00:00Z",
    )


def test_source_health_runtime_summary_is_compact_and_aggregate_only() -> None:
    report = _source_health_report()

    summary = source_health_runtime_summary(report, "reports/source-health.json")

    assert summary == {
        "available": True,
        "report_path": "reports/source-health.json",
        "schema_version": 1,
        "source_count": 5,
        "totals_by_status": {
            "fresh_fetch": 1,
            "validated_cache": 1,
            "fallback_cache": 1,
            "stale_cache": 1,
            "failed": 1,
        },
        "cache_backed_sources": 3,
        "failed_sources": 1,
        "total_byte_size": 1000,
    }

    serialized = json.dumps(summary, sort_keys=True)
    for forbidden_key in ("url", "filename", "sha256", "failure_reason", "sources"):
        assert f'"{forbidden_key}"' not in serialized


def test_source_health_runtime_summary_consumes_saved_report_dict(tmp_path: Path) -> None:
    report = _source_health_report()
    report_dict = {
        "schema_version": report.schema_version,
        "source_count": report.source_count,
        "totals_by_status": report.totals_by_status,
        "sources": [source._asdict() for source in report.sources],
    }
    report_path = tmp_path / "reports" / "source-health.json"

    summary = source_health_runtime_summary(
        report_dict,
        report_path,
        base_dir=tmp_path,
    )

    assert summary["available"] is True
    assert summary["report_path"] == "reports/source-health.json"
    assert summary["source_count"] == 5
    assert summary["cache_backed_sources"] == 3
    assert summary["failed_sources"] == 1
    assert summary["total_byte_size"] == 1000


@pytest.mark.parametrize(
    "report_path",
    [
        Path("..") / "source-health.json",
        Path("reports") / ".." / "source-health.json",
    ],
)
def test_source_health_runtime_summary_rejects_parent_path_references(
    report_path: Path,
) -> None:
    with pytest.raises(ValueError, match="must not contain '..'"):
        source_health_runtime_summary(_source_health_report(), report_path)


def test_source_health_runtime_summary_unavailable_shape_is_stable() -> None:
    summary = source_health_runtime_summary(None)

    assert summary == {
        "available": False,
        "report_path": None,
        "schema_version": None,
        "source_count": 0,
        "totals_by_status": {
            "fresh_fetch": 0,
            "validated_cache": 0,
            "fallback_cache": 0,
            "stale_cache": 0,
            "failed": 0,
        },
        "cache_backed_sources": 0,
        "failed_sources": 0,
        "total_byte_size": 0,
    }


def test_pipeline_source_health_report_loader_returns_compact_runtime_summary(
    tmp_path: Path,
) -> None:
    report = _source_health_report()
    report_path = tmp_path / "reports" / "source-health.json"
    report_path.parent.mkdir()
    report_path.write_text(
        json.dumps(
            {
                "schema_version": report.schema_version,
                "source_count": report.source_count,
                "totals_by_status": report.totals_by_status,
                "sources": [source._asdict() for source in report.sources],
            }
        ),
        encoding="utf-8",
    )

    summary = pipeline_module._source_health_summary_from_report(report_path)

    assert summary["available"] is True
    assert summary["report_path"] == "reports/source-health.json"
    assert summary["source_count"] == 5
    assert summary["cache_backed_sources"] == 3
    assert summary["failed_sources"] == 1
    serialized = json.dumps(summary, sort_keys=True)
    for forbidden_key in ("url", "filename", "sha256", "failure_reason", "sources"):
        assert f'"{forbidden_key}"' not in serialized


def test_pipeline_source_health_report_loader_missing_report_is_unavailable(
    tmp_path: Path,
) -> None:
    summary = pipeline_module._source_health_summary_from_report(
        tmp_path / "reports" / "source-health.json"
    )

    assert summary["available"] is False
    assert summary["report_path"] == "reports/source-health.json"
    assert summary["source_count"] == 0


def test_child_resource_usage_delta_unavailable_shape_is_stable() -> None:
    usage = pipeline_module._child_resource_usage_delta(None, None)

    assert usage == {
        "available": False,
        "platform": pipeline_module.sys.platform,
        "user_cpu_seconds": None,
        "system_cpu_seconds": None,
        "resource_ru_maxrss": None,
        "minor_page_faults": None,
        "major_page_faults": None,
        "voluntary_context_switches": None,
        "involuntary_context_switches": None,
    }


def test_child_resource_usage_delta_reports_aggregate_child_fields() -> None:
    before = SimpleNamespace(
        ru_utime=1.0,
        ru_stime=2.0,
        ru_maxrss=100,
        ru_minflt=10,
        ru_majflt=1,
        ru_nvcsw=3,
        ru_nivcsw=4,
    )
    after = SimpleNamespace(
        ru_utime=2.25,
        ru_stime=2.5,
        ru_maxrss=175,
        ru_minflt=15,
        ru_majflt=2,
        ru_nvcsw=8,
        ru_nivcsw=6,
    )

    usage = pipeline_module._child_resource_usage_delta(before, after)

    assert usage["available"] is True
    assert usage["platform"] == pipeline_module.sys.platform
    assert usage["user_cpu_seconds"] == 1.25
    assert usage["system_cpu_seconds"] == 0.5
    assert usage["resource_ru_maxrss"] == 75
    assert usage["minor_page_faults"] == 5
    assert usage["major_page_faults"] == 1
    assert usage["voluntary_context_switches"] == 5
    assert usage["involuntary_context_switches"] == 2
