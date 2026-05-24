from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts.pruning_proof import (
    ALL_DELTAS,
    DELTA_CHANGED,
    DELTA_GAINED,
    DELTA_LOST,
    DELTA_NOT_APPLICABLE,
    DELTA_PRESERVED,
    DELTA_UNCERTAIN,
    OUTCOME_KEPT,
    OUTCOME_PRUNED,
    OUTCOME_REMOVED,
    ProofLedger,
    PROOF_STATUS_PROVEN,
    PROOF_STATUS_NOT_APPLICABLE,
    PROOF_STATUS_UNCERTAIN,
    REASON_BADFILTER_DISABLED,
    REASON_DUPLICATE_RULE,
    REASON_KEPT_BECAUSE_UNCERTAIN,
    RuleFacet,
    make_proof_record,
    record_to_dict,
    render_capped_report,
    render_full_report,
    write_report_json,
)


def _candidate_facet() -> RuleFacet:
    return RuleFacet(
        raw_rule="||ads.example.com^",
        normalized_rule="||ads.example.com^",
        source_kind="abp",
        rule_kind="abp",
        domain="ads.example.com",
        domain_shape="subdomain",
        effect="block",
        scope="apex_and_subdomains",
        modifier_signature=(),
        priority="normal",
        agh_behavior_basis="adguard_dns_filtering_syntax",
    )


def _covering_facet() -> RuleFacet:
    return RuleFacet(
        raw_rule="||example.com^",
        normalized_rule="||example.com^",
        source_kind="abp",
        rule_kind="abp",
        domain="example.com",
        domain_shape="registered_domain",
        effect="block",
        scope="apex_and_subdomains",
        modifier_signature=(),
        priority="normal",
        agh_behavior_basis="adguard_dns_filtering_syntax",
    )


def _expected_fingerprint(payload: dict[str, object]) -> str:
    normalized = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def test_delta_constants_cover_required_proof_vocabulary() -> None:
    assert ALL_DELTAS == (
        DELTA_PRESERVED,
        DELTA_LOST,
        DELTA_GAINED,
        DELTA_CHANGED,
        DELTA_UNCERTAIN,
        DELTA_NOT_APPLICABLE,
    )
    assert ALL_DELTAS == (
        "preserved",
        "lost",
        "gained",
        "changed",
        "uncertain",
        "not_applicable",
    )


@pytest.mark.parametrize(
    ("strict_delta", "project_delta"),
    [
        (DELTA_PRESERVED, DELTA_PRESERVED),
        (DELTA_LOST, DELTA_LOST),
        (DELTA_GAINED, DELTA_PRESERVED),
        (DELTA_CHANGED, DELTA_CHANGED),
        (DELTA_UNCERTAIN, DELTA_UNCERTAIN),
        (DELTA_NOT_APPLICABLE, DELTA_NOT_APPLICABLE),
    ],
)
def test_proof_record_dict_contains_all_decision_facets(
    strict_delta: str,
    project_delta: str,
) -> None:
    sample = {"domains": ["ads.example.com"], "metadata": {"source": "fixture"}}
    record = make_proof_record(
        decision_id=f"decision:{strict_delta}",
        decision_type="parent_domain",
        outcome=OUTCOME_PRUNED,
        proof_status=PROOF_STATUS_PROVEN,
        reason=REASON_DUPLICATE_RULE,
        candidate=_candidate_facet(),
        covering=_covering_facet(),
        strict_agh_delta=strict_delta,
        project_policy_delta=project_delta,
        sample=sample,
    )
    payload_without_fingerprint = {
        "candidate": _candidate_facet()._asdict(),
        "covering": _covering_facet()._asdict(),
        "decision_id": f"decision:{strict_delta}",
        "decision_type": "parent_domain",
        "outcome": OUTCOME_PRUNED,
        "project_policy_delta": project_delta,
        "proof_status": PROOF_STATUS_PROVEN,
        "reason": REASON_DUPLICATE_RULE,
        "sample": sample,
        "strict_agh_delta": strict_delta,
    }

    assert record_to_dict(record) == {
        **payload_without_fingerprint,
        "fingerprint": _expected_fingerprint(payload_without_fingerprint),
    }


def test_fingerprint_is_independent_of_sample_dictionary_order() -> None:
    first = make_proof_record(
        decision_id="decision:uncertain",
        decision_type="regex",
        outcome=OUTCOME_KEPT,
        proof_status=PROOF_STATUS_UNCERTAIN,
        reason=REASON_KEPT_BECAUSE_UNCERTAIN,
        candidate=_candidate_facet(),
        covering=None,
        strict_agh_delta=DELTA_UNCERTAIN,
        project_policy_delta=DELTA_UNCERTAIN,
        sample={"b": {"y": 2, "x": 1}, "a": ["one", "two"]},
    )
    second = make_proof_record(
        decision_id="decision:uncertain",
        decision_type="regex",
        outcome=OUTCOME_KEPT,
        proof_status=PROOF_STATUS_UNCERTAIN,
        reason=REASON_KEPT_BECAUSE_UNCERTAIN,
        candidate=_candidate_facet(),
        covering=None,
        strict_agh_delta=DELTA_UNCERTAIN,
        project_policy_delta=DELTA_UNCERTAIN,
        sample={"a": ["one", "two"], "b": {"x": 1, "y": 2}},
    )

    assert first.fingerprint == second.fingerprint
    assert record_to_dict(first) == record_to_dict(second)


def _record(
    decision_id: str,
    *,
    decision_type: str = "duplicate",
    outcome: str = OUTCOME_PRUNED,
    proof_status: str = PROOF_STATUS_PROVEN,
    reason: str = REASON_DUPLICATE_RULE,
    strict_delta: str = DELTA_PRESERVED,
    project_delta: str = DELTA_PRESERVED,
    sample: dict[str, object] | None = None,
) -> object:
    return make_proof_record(
        decision_id=decision_id,
        decision_type=decision_type,
        outcome=outcome,
        proof_status=proof_status,
        reason=reason,
        candidate=_candidate_facet(),
        covering=_covering_facet(),
        strict_agh_delta=strict_delta,
        project_policy_delta=project_delta,
        sample=sample or {"decision": decision_id},
    )


def test_ledger_summary_counts_all_decision_dimensions() -> None:
    ledger = ProofLedger()
    ledger.append(_record("decision:duplicate"))
    ledger.append(
        _record(
            "decision:uncertain",
            decision_type="regex",
            outcome=OUTCOME_KEPT,
            proof_status=PROOF_STATUS_UNCERTAIN,
            reason=REASON_KEPT_BECAUSE_UNCERTAIN,
            strict_delta=DELTA_UNCERTAIN,
            project_delta=DELTA_UNCERTAIN,
        )
    )
    ledger.append(
        _record(
            "decision:badfilter",
            decision_type="nonblocking",
            outcome=OUTCOME_REMOVED,
            proof_status=PROOF_STATUS_NOT_APPLICABLE,
            reason=REASON_BADFILTER_DISABLED,
            strict_delta=DELTA_NOT_APPLICABLE,
            project_delta=DELTA_NOT_APPLICABLE,
        )
    )

    assert ledger.summary() == {
        "total_records": 3,
        "by_decision_type": {
            "duplicate": 1,
            "nonblocking": 1,
            "regex": 1,
        },
        "by_outcome": {
            "kept": 1,
            "pruned": 1,
            "removed": 1,
        },
        "by_proof_status": {
            "not_applicable": 1,
            "proven": 1,
            "uncertain": 1,
        },
        "by_reason": {
            "badfilter_disabled": 1,
            "duplicate_rule": 1,
            "kept_because_uncertain": 1,
        },
        "by_strict_agh_delta": {
            "preserved": 1,
            "lost": 0,
            "gained": 0,
            "changed": 0,
            "uncertain": 1,
            "not_applicable": 1,
        },
        "by_project_policy_delta": {
            "preserved": 1,
            "lost": 0,
            "gained": 0,
            "changed": 0,
            "uncertain": 1,
            "not_applicable": 1,
        },
    }


def test_full_report_includes_every_record_with_deterministic_sorting() -> None:
    later = _record("decision:002")
    earlier = _record(
        "decision:001",
        strict_delta=DELTA_GAINED,
        project_delta=DELTA_PRESERVED,
    )
    ledger = ProofLedger([later, earlier])

    assert render_full_report(ledger) == {
        "schema_version": 1,
        "report_type": "full",
        "summary": ledger.summary(),
        "records": [record_to_dict(earlier), record_to_dict(later)],
    }


def test_capped_report_limits_samples_per_delta_reason_outcome_bucket() -> None:
    bucket_records = [
        _record(
            f"decision:uncertain:{index}",
            decision_type="regex",
            outcome=OUTCOME_KEPT,
            proof_status=PROOF_STATUS_UNCERTAIN,
            reason=REASON_KEPT_BECAUSE_UNCERTAIN,
            strict_delta=DELTA_UNCERTAIN,
            project_delta=DELTA_UNCERTAIN,
            sample={"index": index},
        )
        for index in range(3)
    ]
    other_bucket = _record(
        "decision:duplicate",
        sample={"index": "other"},
    )
    ledger = ProofLedger([bucket_records[2], bucket_records[0], other_bucket, bucket_records[1]])

    assert render_capped_report(ledger, sample_cap=2) == {
        "schema_version": 1,
        "report_type": "capped",
        "sample_cap": 2,
        "summary": ledger.summary(),
        "sample_buckets": [
            {
                "bucket": {
                    "strict_agh_delta": DELTA_PRESERVED,
                    "project_policy_delta": DELTA_PRESERVED,
                    "reason": REASON_DUPLICATE_RULE,
                    "outcome": OUTCOME_PRUNED,
                },
                "total_records": 1,
                "sampled_records": 1,
                "records": [
                    {
                        "decision_id": other_bucket.decision_id,
                        "decision_type": other_bucket.decision_type,
                        "fingerprint": other_bucket.fingerprint,
                        "candidate_rule": other_bucket.candidate.normalized_rule,
                        "candidate_domain": other_bucket.candidate.domain,
                        "covering_rule": other_bucket.covering.normalized_rule,
                        "sample": {"index": "other"},
                    }
                ],
            },
            {
                "bucket": {
                    "strict_agh_delta": DELTA_UNCERTAIN,
                    "project_policy_delta": DELTA_UNCERTAIN,
                    "reason": REASON_KEPT_BECAUSE_UNCERTAIN,
                    "outcome": OUTCOME_KEPT,
                },
                "total_records": 3,
                "sampled_records": 2,
                "records": [
                    {
                        "decision_id": bucket_records[0].decision_id,
                        "decision_type": bucket_records[0].decision_type,
                        "fingerprint": bucket_records[0].fingerprint,
                        "candidate_rule": bucket_records[0].candidate.normalized_rule,
                        "candidate_domain": bucket_records[0].candidate.domain,
                        "covering_rule": bucket_records[0].covering.normalized_rule,
                        "sample": {"index": 0},
                    },
                    {
                        "decision_id": bucket_records[1].decision_id,
                        "decision_type": bucket_records[1].decision_type,
                        "fingerprint": bucket_records[1].fingerprint,
                        "candidate_rule": bucket_records[1].candidate.normalized_rule,
                        "candidate_domain": bucket_records[1].candidate.domain,
                        "covering_rule": bucket_records[1].covering.normalized_rule,
                        "sample": {"index": 1},
                    },
                ],
            },
        ],
    }


def test_write_report_json_uses_atomic_sibling_temp_path(tmp_path: Path) -> None:
    report_path = tmp_path / "nested" / "coverage-proof.json"
    temp_path = report_path.with_suffix(".tmp")

    write_report_json(report_path, {"z": 1, "a": {"nested": True}})

    text = report_path.read_text(encoding="utf-8")
    assert json.loads(text) == {"z": 1, "a": {"nested": True}}
    assert text.index('"a"') < text.index('"z"')
    assert not temp_path.exists()
