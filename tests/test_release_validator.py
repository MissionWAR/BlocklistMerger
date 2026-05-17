#!/usr/bin/env python3
"""
test_release_validator.py

Focused tests for release validation policy.
"""
import json
import sys
from pathlib import Path

import pytest

import scripts.release_validator as release_validator


def _write_json(path: Path, data: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _read_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _source_health(statuses: list[str]) -> dict[str, object]:
    return {
        "schema_version": 1,
        "version": "1.5.0",
        "generated_at": "2026-05-17T15:00:00Z",
        "source_count": len(statuses),
        "totals_by_status": {
            status: statuses.count(status)
            for status in [
                "failed",
                "fallback_cache",
                "fresh_fetch",
                "stale_cache",
                "validated_cache",
            ]
        },
        "sources": [
            {
                "url": f"https://example.com/list-{index}.txt",
                "filename": f"list-{index}.txt",
                "status": status,
                "changed": status == "fresh_fetch",
                "byte_size": 128 if status != "failed" else 0,
                "sha256": "abc" if status != "failed" else None,
                "cache_age_seconds": 60 if status in {"fallback_cache", "stale_cache"} else None,
                "failure_reason": "HTTP 500" if status in {"failed", "fallback_cache"} else None,
            }
            for index, status in enumerate(statuses)
        ],
    }


def _pipeline_stats(lines_output: int = 3) -> dict[str, object]:
    return {
        "schema_version": 1,
        "version": "1.5.0",
        "timestamp": "2026-05-17T15:01:00Z",
        "execution_time_seconds": 1.25,
        "statistics": {
            "files_processed": 1,
            "lines_raw": lines_output,
            "lines_clean": lines_output,
            "lines_output": lines_output,
            "comments_removed": 0,
            "cosmetic_removed": 0,
            "unsupported_removed": 0,
            "empty_removed": 0,
            "url_path_removed": 0,
            "invalid_removed": 0,
            "trimmed": 0,
            "abp_subdomain_pruned": 0,
            "tld_wildcard_pruned": 0,
            "duplicate_pruned": 0,
            "whitelist_conflict_pruned": 0,
            "local_hostname_pruned": 0,
            "formats_compressed": 0,
            "malformed_discarded": 0,
            "abp_kept": lines_output,
            "other_kept": 0,
        },
    }


def _canaries(
    must_block: list[str] | None = None,
    must_allow: list[str] | None = None,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "must_block": must_block or ["ads.example.com"],
        "must_allow": must_allow or ["github.com"],
    }


def _write_release_inputs(
    tmp_path: Path,
    *,
    output_lines: list[str] | None = None,
    source_health: dict[str, object] | None = None,
    pipeline_stats: dict[str, object] | None = None,
    canaries: dict[str, object] | None = None,
    previous_lines: list[str] | None = None,
) -> dict[str, Path]:
    output_lines = output_lines or ["||ads.example.com^", "||tracker.example.com^"]
    paths = {
        "source_health": tmp_path / "reports" / "source-health.json",
        "pipeline_stats": tmp_path / "reports" / "pipeline-stats.json",
        "output": tmp_path / "lists" / "merged.txt",
        "canaries": tmp_path / "config" / "release_canaries.json",
        "summary_json": tmp_path / "reports" / "validation-summary.json",
        "summary_md": tmp_path / "reports" / "validation-summary.md",
        "previous_output": tmp_path / "previous" / "merged.txt",
    }
    _write_json(paths["source_health"], source_health or _source_health(["fresh_fetch"] * 10))
    _write_json(paths["pipeline_stats"], pipeline_stats or _pipeline_stats(len(output_lines)))
    _write_json(paths["canaries"], canaries or _canaries())
    paths["output"].parent.mkdir(parents=True, exist_ok=True)
    paths["output"].write_text("\n".join(output_lines) + "\n", encoding="utf-8")
    if previous_lines is not None:
        paths["previous_output"].parent.mkdir(parents=True, exist_ok=True)
        paths["previous_output"].write_text("\n".join(previous_lines) + "\n", encoding="utf-8")
    return paths


def _validate(tmp_path: Path, **kwargs) -> release_validator.ValidationSummary:
    paths = _write_release_inputs(tmp_path, **kwargs)
    return release_validator.validate_release(
        source_health_path=paths["source_health"],
        pipeline_stats_path=paths["pipeline_stats"],
        output_path=paths["output"],
        canaries_path=paths["canaries"],
        previous_output_path=paths["previous_output"],
        summary_json_path=paths["summary_json"],
        summary_md_path=paths["summary_md"],
        thresholds=release_validator.ReleaseThresholds(minimum_output_rules=1),
    )


def test_repo_canary_config_is_versioned() -> None:
    canaries = _read_json(Path("config/release_canaries.json"))

    assert canaries["schema_version"] == 1
    assert canaries["must_block"] == ["doubleclick.net", "googlesyndication.com"]
    assert canaries["must_allow"] == ["github.com", "adguard.com"]


def test_source_health_hard_fails_catastrophic_and_warns_bounded_fallback(
    tmp_path: Path,
) -> None:
    catastrophic = _validate(
        tmp_path / "catastrophic",
        source_health=_source_health(["fresh_fetch"] * 6 + ["failed"] * 4),
    )
    bounded = _validate(
        tmp_path / "bounded",
        source_health=_source_health(["fresh_fetch"] * 9 + ["fallback_cache"]),
    )

    assert any(
        error["code"] == "source_health_catastrophic_failed_stale"
        for error in catastrophic.errors
    )
    assert not bounded.errors
    assert any(warning["code"] == "source_health_degraded" for warning in bounded.warnings)


@pytest.mark.parametrize(
    "bad_rule, expected_code",
    [
        ("||^", "output_invalid_syntax"),
        ("||example.com/path.js", "output_url_path"),
        ("||example.com^$script", "output_unsupported_modifier"),
    ],
    ids=["invalid", "url-path", "unsupported-modifier"],
)
def test_output_syntax_hard_fails_unsafe_emitted_rules(
    tmp_path: Path,
    bad_rule: str,
    expected_code: str,
) -> None:
    summary = _validate(
        tmp_path,
        output_lines=["||ads.example.com^", bad_rule],
        pipeline_stats=_pipeline_stats(2),
    )

    assert any(error["code"] == expected_code for error in summary.errors)


def test_canaries_hard_fail_missing_must_block_and_blocked_must_allow(tmp_path: Path) -> None:
    summary = _validate(
        tmp_path,
        output_lines=["||not-canary.example.com^", "||github.com^"],
        pipeline_stats=_pipeline_stats(2),
    )

    assert any(error["code"] == "canary_must_block_missing" for error in summary.errors)
    assert any(error["code"] == "canary_must_allow_blocked" for error in summary.errors)


@pytest.mark.parametrize(
    "current_count, previous_count, expected_code",
    [
        (74, 100, "previous_output_extreme_drop"),
        (201, 100, "previous_output_extreme_increase"),
        (2_100_001, 1_000_000, "previous_output_extreme_absolute_delta"),
        (100_000, 2_100_001, "previous_output_extreme_absolute_delta"),
    ],
    ids=["drop", "increase", "absolute-up", "absolute-down"],
)
def test_previous_release_extreme_deltas_hard_fail(
    tmp_path: Path,
    current_count: int,
    previous_count: int,
    expected_code: str,
) -> None:
    summary = release_validator.validate_previous_output_delta(
        current_count=current_count,
        previous_count=previous_count,
        thresholds=release_validator.ReleaseThresholds(minimum_output_rules=1),
    )

    assert any(error["code"] == expected_code for error in summary.errors)
    assert not summary.warnings


def test_previous_release_moderate_delta_and_missing_previous_warn_without_failure(
    tmp_path: Path,
) -> None:
    moderate = release_validator.validate_previous_output_delta(
        current_count=112,
        previous_count=100,
        thresholds=release_validator.ReleaseThresholds(minimum_output_rules=1),
    )
    missing = _validate(tmp_path)

    assert not moderate.errors
    assert any(warning["code"] == "previous_output_moderate_delta" for warning in moderate.warnings)
    assert not missing.errors
    assert any(warning["code"] == "previous_output_unavailable" for warning in missing.warnings)


def test_summaries_are_written_with_schema_thresholds_and_triage_text(tmp_path: Path) -> None:
    paths = _write_release_inputs(
        tmp_path,
        output_lines=["||missing-required.example.com^"],
        pipeline_stats=_pipeline_stats(1),
    )

    result = release_validator.run_validation(
        source_health_path=paths["source_health"],
        pipeline_stats_path=paths["pipeline_stats"],
        output_path=paths["output"],
        canaries_path=paths["canaries"],
        previous_output_path=paths["previous_output"],
        summary_json_path=paths["summary_json"],
        summary_md_path=paths["summary_md"],
        thresholds=release_validator.ReleaseThresholds(minimum_output_rules=1),
    )

    data = _read_json(paths["summary_json"])
    markdown = paths["summary_md"].read_text(encoding="utf-8")
    assert result.exit_code == 1
    assert data["schema_version"] == 1
    assert data["status"] == "failed"
    assert data["errors"]
    assert data["warnings"]
    assert data["thresholds"]["minimum_output_rules"] == 1
    assert data["counts"]["current_output_rules"] == 1
    assert data["previous_release"]["available"] is False
    assert "## Release Validation: Failed" in markdown
    assert "Errors" in markdown
    assert "Warnings" in markdown
    assert "Thresholds" in markdown


def test_cli_returns_nonzero_for_errors_and_writes_summaries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _write_release_inputs(
        tmp_path,
        output_lines=["||not-canary.example.com^"],
        pipeline_stats=_pipeline_stats(1),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "scripts.release_validator",
            "--source-health",
            str(paths["source_health"]),
            "--pipeline-stats",
            str(paths["pipeline_stats"]),
            "--output",
            str(paths["output"]),
            "--canaries",
            str(paths["canaries"]),
            "--previous-output",
            str(paths["previous_output"]),
            "--summary-json",
            str(paths["summary_json"]),
            "--summary-md",
            str(paths["summary_md"]),
            "--minimum-output-rules",
            "1",
        ],
    )

    assert release_validator.main() == 1
    assert paths["summary_json"].exists()
    assert paths["summary_md"].exists()
