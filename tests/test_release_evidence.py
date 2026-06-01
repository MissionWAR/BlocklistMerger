from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.pruning_proof import fingerprint_payload
from scripts.release_evidence import (
    COVERAGE_EFFECT_ALLOW,
    COVERAGE_EFFECT_BLOCK,
    COVERAGE_EFFECT_DIAGNOSTIC,
    DEFAULT_SAMPLE_CAP,
    RELEASE_EVIDENCE_SCHEMA_VERSION,
    SCOPE_APEX,
    SCOPE_APEX_AND_SUBDOMAINS,
    SCOPE_EXACT_HOST,
    SCOPE_SUBDOMAIN,
    SCOPE_UNSCOPED_GLOBAL,
    SCOPE_WILDCARD_APEX_ALLOWED,
    SCOPE_WILDCARD_CHILD,
    CoverageRecord,
    MembershipChurn,
    compact_source_health_context,
    compare_membership,
    coverage_record_to_dict,
    coverage_records_for_rule,
    coverage_records_from_rules,
    fingerprint_membership,
    membership_churn_to_dict,
    normalize_membership,
    record_covers_canary_scope,
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


def test_abp_rule_records_global_apex_and_subdomain_coverage() -> None:
    records = coverage_records_for_rule("  ||Example.COM^  ")

    assert records == (
        CoverageRecord(
            raw_rule="||Example.COM^",
            domain="example.com",
            syntax_kind="abp",
            effect=COVERAGE_EFFECT_BLOCK,
            scope=SCOPE_APEX_AND_SUBDOMAINS,
            is_global=True,
            is_exception=False,
            is_wildcard=False,
            modifier_names=(),
            modifier_signature=(),
            notes=("abp_basic_apex_and_subdomains",),
        ),
    )
    record = records[0]
    assert record_covers_canary_scope(record, "example.com", SCOPE_APEX)
    assert record_covers_canary_scope(record, "sub.example.com", SCOPE_SUBDOMAIN)
    assert record_covers_canary_scope(record, "sub.example.com", SCOPE_UNSCOPED_GLOBAL)


def test_wildcard_rule_records_child_coverage_without_apex_coverage() -> None:
    record = coverage_records_for_rule("||*.example.com^")[0]

    assert record.scope == SCOPE_WILDCARD_CHILD
    assert record.is_global is False
    assert record.is_wildcard is True
    assert record_covers_canary_scope(record, "ads.example.com", SCOPE_WILDCARD_CHILD)
    assert not record_covers_canary_scope(record, "example.com", SCOPE_WILDCARD_CHILD)
    assert record_covers_canary_scope(record, "example.com", SCOPE_WILDCARD_APEX_ALLOWED)
    assert not record_covers_canary_scope(record, "ads.example.com", SCOPE_UNSCOPED_GLOBAL)


def test_hosts_and_plain_domain_records_are_exact_host_only() -> None:
    hosts_records = coverage_records_for_rule("0.0.0.0 Example.COM ads.example.com")
    plain_record = coverage_records_for_rule("Tracker.EXAMPLE.com")[0]

    assert [record.domain for record in hosts_records] == ["example.com", "ads.example.com"]
    assert all(record.scope == SCOPE_EXACT_HOST for record in hosts_records)
    assert plain_record.domain == "tracker.example.com"
    assert plain_record.scope == SCOPE_EXACT_HOST
    assert record_covers_canary_scope(hosts_records[0], "example.com", SCOPE_EXACT_HOST)
    assert not record_covers_canary_scope(hosts_records[0], "sub.example.com", SCOPE_SUBDOMAIN)
    assert not record_covers_canary_scope(
        plain_record,
        "child.tracker.example.com",
        SCOPE_UNSCOPED_GLOBAL,
    )


def test_exception_records_are_allow_evidence_and_never_global() -> None:
    record = coverage_records_for_rule("@@||example.com^")[0]

    assert record.effect == COVERAGE_EFFECT_ALLOW
    assert record.is_exception is True
    assert record.is_global is False
    assert not record_covers_canary_scope(record, "example.com", SCOPE_UNSCOPED_GLOBAL)


def test_modifier_limited_records_preserve_signature_and_do_not_cover_global() -> None:
    record = coverage_records_for_rule("||example.com^$client=10.0.0.1,dnstype=a")[0]
    data = coverage_record_to_dict(record)

    assert record.effect == COVERAGE_EFFECT_BLOCK
    assert record.is_global is False
    assert record.modifier_names == ("client", "dnstype")
    assert record.modifier_signature
    assert data["modifier_names"] == ["client", "dnstype"]
    assert data["modifier_signature"]
    assert not record_covers_canary_scope(record, "example.com", SCOPE_UNSCOPED_GLOBAL)
    assert not record_covers_canary_scope(record, "example.com", SCOPE_APEX)


@pytest.mark.parametrize(
    "rule",
    [
        "||example.com^$script",
        "||example.com^$badfilter",
        "||example.com^$dnsrewrite=1.2.3.4",
        "||example.com^$denyallow=allowed.example",
    ],
)
def test_unsupported_or_special_modifier_records_cannot_satisfy_global_scope(rule: str) -> None:
    record = coverage_records_for_rule(rule)[0]

    assert record.is_global is False
    assert not record_covers_canary_scope(record, "example.com", SCOPE_UNSCOPED_GLOBAL)


def test_unsupported_modifier_record_is_diagnostic_evidence() -> None:
    record = coverage_records_for_rule("||example.com^$script")[0]

    assert record.effect == COVERAGE_EFFECT_DIAGNOSTIC
    assert record.scope == "unsupported_modifier"
    assert record.notes == ("unsupported_or_uncertain_modifier",)


def test_coverage_records_from_rules_flattens_and_sorts_deterministically() -> None:
    records = coverage_records_from_rules([
        "||b.example^",
        "",
        "0.0.0.0 a.example c.example",
    ])

    assert [record.domain for record in records] == ["a.example", "b.example", "c.example"]


def test_coverage_record_to_dict_is_json_compatible_and_stable() -> None:
    record = coverage_records_for_rule("||example.com^$client=10.0.0.1")[0]
    data = coverage_record_to_dict(record)

    assert data["raw_rule"] == "||example.com^$client=10.0.0.1"
    assert data["domain"] == "example.com"
    assert data["modifier_names"] == ["client"]
    assert isinstance(data["modifier_signature"], list)
    assert json.loads(json.dumps(data, sort_keys=True)) == data


def test_sidecar_accepts_coverage_records_without_release_policy_fields() -> None:
    sidecar = render_diagnostic_sidecar(
        coverage_records=[
            coverage_records_for_rule("||example.com^")[0],
            coverage_records_for_rule("@@||allowed.example^")[0],
            coverage_records_for_rule("||bad.example^$script")[0],
        ],
        sample_cap=3,
    )

    assert sidecar["coverage_summary"] == {
        "total_records": 3,
        "sampled_records": 3,
        "by_effect": {
            COVERAGE_EFFECT_ALLOW: 1,
            COVERAGE_EFFECT_BLOCK: 1,
            COVERAGE_EFFECT_DIAGNOSTIC: 1,
        },
        "by_scope": {
            "unsupported_modifier": 1,
            SCOPE_APEX_AND_SUBDOMAINS: 2,
        },
    }
    for forbidden_key in ("errors", "warnings", "findings", "exit_code", "thresholds"):
        assert forbidden_key not in sidecar
