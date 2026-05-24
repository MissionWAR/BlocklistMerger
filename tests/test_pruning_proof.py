from __future__ import annotations

import hashlib
import json

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
    PROOF_STATUS_PROVEN,
    PROOF_STATUS_UNCERTAIN,
    REASON_DUPLICATE_RULE,
    REASON_KEPT_BECAUSE_UNCERTAIN,
    RuleFacet,
    make_proof_record,
    record_to_dict,
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
