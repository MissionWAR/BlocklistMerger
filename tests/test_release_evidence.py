from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.pruning_proof import fingerprint_payload
from scripts.release_evidence import (
    DEFAULT_SAMPLE_CAP,
    RELEASE_EVIDENCE_SCHEMA_VERSION,
    MembershipChurn,
    compact_source_health_context,
    compare_membership,
    fingerprint_membership,
    membership_churn_to_dict,
    normalize_membership,
    render_diagnostic_sidecar,
    write_report_json,
)


def test_normalize_membership_strips_deduplicates_and_sorts_rules() -> None:
    lines = [
        "  ||tracker.example^  ",
        "",
        "||ads.example^",
        "||tracker.example^",
        "   ",
    ]

    assert normalize_membership(lines) == ("||ads.example^", "||tracker.example^")


def test_fingerprint_membership_uses_pruning_proof_payload_semantics() -> None:
    lines = ["||tracker.example^", "||ads.example^", "||ads.example^"]

    assert fingerprint_membership(lines) == fingerprint_payload(
        ("||ads.example^", "||tracker.example^")
    )


def test_compare_membership_counts_fingerprints_and_capped_samples() -> None:
    churn = compare_membership(
        ["||new-b.example^", "||kept.example^", "||new-a.example^"],
        ["||removed.example^", "||kept.example^"],
        sample_cap=1,
    )

    assert churn == MembershipChurn(
        current_count=3,
        previous_count=2,
        added_count=2,
        removed_count=1,
        current_fingerprint=fingerprint_membership(
            ["||kept.example^", "||new-a.example^", "||new-b.example^"]
        ),
        previous_fingerprint=fingerprint_membership(["||kept.example^", "||removed.example^"]),
        added_fingerprint=fingerprint_membership(["||new-a.example^", "||new-b.example^"]),
        removed_fingerprint=fingerprint_membership(["||removed.example^"]),
        added_samples=("||new-a.example^",),
        removed_samples=("||removed.example^",),
    )


def test_compare_membership_rejects_invalid_sample_cap() -> None:
    with pytest.raises(ValueError, match="sample_cap must be at least 1"):
        compare_membership(["||current.example^"], [], sample_cap=0)


def test_membership_churn_to_dict_is_json_compatible() -> None:
    churn = compare_membership(["||current.example^"], ["||previous.example^"])

    assert membership_churn_to_dict(churn) == {
        "current_count": 1,
        "previous_count": 1,
        "added_count": 1,
        "removed_count": 1,
        "current_fingerprint": fingerprint_membership(["||current.example^"]),
        "previous_fingerprint": fingerprint_membership(["||previous.example^"]),
        "added_fingerprint": fingerprint_membership(["||current.example^"]),
        "removed_fingerprint": fingerprint_membership(["||previous.example^"]),
        "added_samples": ["||current.example^"],
        "removed_samples": ["||previous.example^"],
    }


def test_compact_source_health_context_prefers_sorted_totals_without_rich_sources() -> None:
    report = {
        "schema_version": 1,
        "source_count": 4,
        "totals_by_status": {
            "validated_cache": 1,
            "failed": 1,
            "fresh_fetch": 1,
            "fallback_cache": 1,
            "stale_cache": 0,
        },
        "sources": [
            {"url": "https://example.com/private-source.txt", "status": "failed"},
        ],
    }

    assert compact_source_health_context(report) == {
        "available": True,
        "source_count": 4,
        "totals_by_status": {
            "failed": 1,
            "fallback_cache": 1,
            "fresh_fetch": 1,
            "stale_cache": 0,
            "validated_cache": 1,
        },
        "degraded_sources": 2,
    }


def test_compact_source_health_context_derives_counts_from_sources_when_needed() -> None:
    context = compact_source_health_context({
        "sources": [
            {"status": "fresh_fetch"},
            {"status": "fresh_fetch"},
            {"status": "stale_cache"},
            {"status": "unknown"},
        ]
    })

    assert context["available"] is True
    assert context["source_count"] == 4
    assert context["totals_by_status"] == {
        "fresh_fetch": 2,
        "stale_cache": 1,
        "unknown": 1,
    }
    assert context["degraded_sources"] == 1


def test_render_diagnostic_sidecar_is_bounded_versioned_and_diagnostic_only() -> None:
    churn = compare_membership(
        ["||added-b.example^", "||added-a.example^", "||kept.example^"],
        ["||kept.example^"],
        sample_cap=1,
    )
    sidecar = render_diagnostic_sidecar(
        membership_churn=churn,
        source_health_context={"available": False},
        coverage_records=[
            {"raw_rule": "||b.example^", "effect": "block", "scope": "apex_and_subdomains"},
            {"raw_rule": "||a.example^", "effect": "block", "scope": "apex_and_subdomains"},
        ],
        sample_cap=1,
    )

    assert sidecar == {
        "schema_version": RELEASE_EVIDENCE_SCHEMA_VERSION,
        "report_type": "release_evidence",
        "sample_cap": 1,
        "membership_churn": membership_churn_to_dict(churn),
        "source_health_context": {"available": False},
        "coverage_summary": {
            "total_records": 2,
            "sampled_records": 1,
            "by_effect": {"block": 2},
            "by_scope": {"apex_and_subdomains": 2},
        },
        "coverage_records": [
            {
                "effect": "block",
                "raw_rule": "||a.example^",
                "scope": "apex_and_subdomains",
            }
        ],
    }
    for forbidden_key in ("errors", "warnings", "findings", "exit_code", "thresholds"):
        assert forbidden_key not in sidecar


def test_render_diagnostic_sidecar_rejects_invalid_sample_cap() -> None:
    with pytest.raises(ValueError, match="sample_cap must be at least 1"):
        render_diagnostic_sidecar(sample_cap=0)


def test_write_report_json_uses_atomic_sorted_utf8_json(tmp_path: Path) -> None:
    report_path = tmp_path / "reports" / "release-evidence.json"
    temp_path = report_path.with_suffix(".tmp")

    write_report_json(report_path, {"z": 1, "a": {"marker": "check"}})

    text = report_path.read_text(encoding="utf-8")
    assert json.loads(text) == {"z": 1, "a": {"marker": "check"}}
    assert text.index('"a"') < text.index('"z"')
    assert "check" in text
    assert not temp_path.exists()


def test_default_sample_cap_is_intentionally_small_for_sidecars() -> None:
    assert DEFAULT_SAMPLE_CAP == 25
