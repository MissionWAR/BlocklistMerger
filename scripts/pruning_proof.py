#!/usr/bin/env python3
"""
pruning_proof.py - Coverage proof records for pruning diagnostics.

This module defines a pure, stdlib-only proof vocabulary for later compiler
instrumentation. It intentionally does not import compiler internals or decide
whether a rule should be pruned; it only models and fingerprints proof records.
"""

import hashlib
import json
from typing import Final, NamedTuple

# =============================================================================
# PROOF VOCABULARY
# =============================================================================

DELTA_PRESERVED: Final[str] = "preserved"
DELTA_LOST: Final[str] = "lost"
DELTA_GAINED: Final[str] = "gained"
DELTA_CHANGED: Final[str] = "changed"
DELTA_UNCERTAIN: Final[str] = "uncertain"
DELTA_NOT_APPLICABLE: Final[str] = "not_applicable"

ALL_DELTAS: Final[tuple[str, ...]] = (
    DELTA_PRESERVED,
    DELTA_LOST,
    DELTA_GAINED,
    DELTA_CHANGED,
    DELTA_UNCERTAIN,
    DELTA_NOT_APPLICABLE,
)

OUTCOME_KEPT: Final[str] = "kept"
OUTCOME_PRUNED: Final[str] = "pruned"
OUTCOME_REMOVED: Final[str] = "removed"
OUTCOME_CHANGED: Final[str] = "changed"

PROOF_STATUS_PROVEN: Final[str] = "proven"
PROOF_STATUS_UNPROVEN: Final[str] = "unproven"
PROOF_STATUS_UNCERTAIN: Final[str] = "uncertain"
PROOF_STATUS_NOT_APPLICABLE: Final[str] = "not_applicable"

REASON_DUPLICATE_RULE: Final[str] = "duplicate_rule"
REASON_PARENT_COVERED: Final[str] = "parent_covered"
REASON_WILDCARD_COVERED: Final[str] = "wildcard_covered"
REASON_TLD_WILDCARD_COVERED: Final[str] = "tld_wildcard_covered"
REASON_EXCEPTION_COVERED: Final[str] = "exception_covered"
REASON_KEPT_BECAUSE_UNCERTAIN: Final[str] = "kept_because_uncertain"
REASON_UNSUPPORTED_MODIFIER_REMOVED: Final[str] = "unsupported_modifier_removed"
REASON_BADFILTER_DISABLED: Final[str] = "badfilter_disabled"
REASON_DNSREWRITE_CHANGED: Final[str] = "dnsrewrite_changed"
REASON_CROSS_FORMAT_BROADENED: Final[str] = "cross_format_broadened"

__all__ = [
    "ALL_DELTAS",
    "DELTA_CHANGED",
    "DELTA_GAINED",
    "DELTA_LOST",
    "DELTA_NOT_APPLICABLE",
    "DELTA_PRESERVED",
    "DELTA_UNCERTAIN",
    "OUTCOME_CHANGED",
    "OUTCOME_KEPT",
    "OUTCOME_PRUNED",
    "OUTCOME_REMOVED",
    "PROOF_STATUS_NOT_APPLICABLE",
    "PROOF_STATUS_PROVEN",
    "PROOF_STATUS_UNCERTAIN",
    "PROOF_STATUS_UNPROVEN",
    "REASON_BADFILTER_DISABLED",
    "REASON_CROSS_FORMAT_BROADENED",
    "REASON_DNSREWRITE_CHANGED",
    "REASON_DUPLICATE_RULE",
    "REASON_EXCEPTION_COVERED",
    "REASON_KEPT_BECAUSE_UNCERTAIN",
    "REASON_PARENT_COVERED",
    "REASON_TLD_WILDCARD_COVERED",
    "REASON_UNSUPPORTED_MODIFIER_REMOVED",
    "REASON_WILDCARD_COVERED",
    "ProofRecord",
    "RuleFacet",
    "fingerprint_payload",
    "make_proof_record",
    "record_to_dict",
]


# =============================================================================
# DATA STRUCTURES
# =============================================================================


class RuleFacet(NamedTuple):
    """
    Rule-level facets used to explain pruning proof decisions.

    Attributes:
        raw_rule: Original cleaned rule text.
        normalized_rule: Rule text after compiler normalization or compression.
        source_kind: Input source category such as abp, hosts, or plain_domain.
        rule_kind: Syntax kind used for proof grouping.
        domain: Normalized domain associated with the rule, if any.
        domain_shape: Domain relationship label such as apex, subdomain, or regex.
        effect: RuleEffect-compatible behavior label.
        scope: RuleEffect-compatible scope label.
        modifier_signature: Deterministic modifier signature for coverage proof.
        priority: Priority label, typically normal or important.
        agh_behavior_basis: Documentation or project-policy basis for the facet.
    """

    raw_rule: str
    normalized_rule: str
    source_kind: str
    rule_kind: str
    domain: str
    domain_shape: str
    effect: str
    scope: str
    modifier_signature: tuple[object, ...]
    priority: str
    agh_behavior_basis: str


class ProofRecord(NamedTuple):
    """
    One pruning proof decision with dual-baseline coverage deltas.

    Attributes:
        decision_id: Stable decision identifier assigned by the caller.
        decision_type: Decision family, such as duplicate or parent_domain.
        outcome: What happened to the candidate rule.
        proof_status: Whether coverage was proven, unproven, or not applicable.
        reason: Machine-readable reason for this decision.
        candidate: The candidate rule facet being explained.
        covering: Optional covering or related rule facet.
        strict_agh_delta: Delta against documented AGH behavior.
        project_policy_delta: Delta against this project's current policy.
        sample: Small JSON-compatible evidence payload for reports.
        fingerprint: Deterministic SHA-256 over normalized record data.
    """

    decision_id: str
    decision_type: str
    outcome: str
    proof_status: str
    reason: str
    candidate: RuleFacet
    covering: RuleFacet | None
    strict_agh_delta: str
    project_policy_delta: str
    sample: dict[str, object]
    fingerprint: str


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================


def _record_payload_without_fingerprint(record: ProofRecord) -> dict[str, object]:
    """Return the stable dictionary payload used for fingerprints and reports."""
    return {
        "candidate": record.candidate._asdict(),
        "covering": record.covering._asdict() if record.covering is not None else None,
        "decision_id": record.decision_id,
        "decision_type": record.decision_type,
        "outcome": record.outcome,
        "project_policy_delta": record.project_policy_delta,
        "proof_status": record.proof_status,
        "reason": record.reason,
        "sample": record.sample,
        "strict_agh_delta": record.strict_agh_delta,
    }


def fingerprint_payload(payload: object) -> str:
    """
    Return a deterministic SHA-256 fingerprint for a JSON-compatible payload.

    Dict insertion order does not affect the result because JSON keys are sorted
    and compact separators are used before hashing.
    """
    normalized = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def make_proof_record(
    *,
    decision_id: str,
    decision_type: str,
    outcome: str,
    proof_status: str,
    reason: str,
    candidate: RuleFacet,
    covering: RuleFacet | None,
    strict_agh_delta: str,
    project_policy_delta: str,
    sample: dict[str, object] | None = None,
) -> ProofRecord:
    """
    Build a proof record and calculate its normalized fingerprint.

    Args:
        decision_id: Stable identifier for this proof decision.
        decision_type: Decision family name.
        outcome: Candidate outcome label.
        proof_status: Proof status label.
        reason: Machine-readable decision reason.
        candidate: Candidate rule facet.
        covering: Optional covering or related rule facet.
        strict_agh_delta: Delta against documented AGH behavior.
        project_policy_delta: Delta against current project policy.
        sample: Optional JSON-compatible evidence payload.

    Returns:
        ProofRecord with a deterministic fingerprint.
    """
    record = ProofRecord(
        decision_id=decision_id,
        decision_type=decision_type,
        outcome=outcome,
        proof_status=proof_status,
        reason=reason,
        candidate=candidate,
        covering=covering,
        strict_agh_delta=strict_agh_delta,
        project_policy_delta=project_policy_delta,
        sample=dict(sample or {}),
        fingerprint="",
    )
    payload = _record_payload_without_fingerprint(record)
    return record._replace(fingerprint=fingerprint_payload(payload))


def record_to_dict(record: ProofRecord) -> dict[str, object]:
    """
    Return a JSON-compatible dictionary for one proof record.

    The fingerprint is included after the normalized payload fields so callers
    can render exact fixture sidecars and compact production samples.
    """
    return {
        **_record_payload_without_fingerprint(record),
        "fingerprint": record.fingerprint,
    }
