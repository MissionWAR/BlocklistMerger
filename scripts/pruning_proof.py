#!/usr/bin/env python3
"""
pruning_proof.py - Coverage proof records for pruning diagnostics.

This module defines a pure, stdlib-only proof vocabulary for later compiler
instrumentation. It intentionally does not import compiler internals or decide
whether a rule should be pruned; it only models and fingerprints proof records.
"""

import hashlib
import json
from collections import Counter, defaultdict
from collections.abc import Iterable
from pathlib import Path
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
REASON_IGNORED_NONBLOCKING: Final[str] = "ignored_nonblocking"
REASON_REGEX_UNCERTAIN_KEPT: Final[str] = "regex_uncertain_kept"
REASON_CROSS_FORMAT_BROADENED: Final[str] = "cross_format_broadened"

PROOF_REPORT_SCHEMA_VERSION: Final[int] = 1
DEFAULT_SAMPLE_CAP: Final[int] = 25

__all__ = [
    "ALL_DELTAS",
    "DEFAULT_SAMPLE_CAP",
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
    "REASON_IGNORED_NONBLOCKING",
    "REASON_KEPT_BECAUSE_UNCERTAIN",
    "REASON_PARENT_COVERED",
    "REASON_REGEX_UNCERTAIN_KEPT",
    "REASON_TLD_WILDCARD_COVERED",
    "REASON_UNSUPPORTED_MODIFIER_REMOVED",
    "REASON_WILDCARD_COVERED",
    "ProofRecord",
    "ProofLedger",
    "PROOF_REPORT_SCHEMA_VERSION",
    "RuleFacet",
    "fingerprint_payload",
    "make_proof_record",
    "record_to_dict",
    "render_capped_report",
    "render_full_report",
    "write_report_json",
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


class ProofLedger:
    """
    Append-only collection of proof records with deterministic report helpers.

    Full ledgers are intended for small fixture sidecars. Production-shaped
    output should use capped reports so sample exposure stays bounded.
    """

    def __init__(self, records: Iterable[ProofRecord] | None = None) -> None:
        self._records: list[ProofRecord] = []
        if records is not None:
            for record in records:
                self.append(record)

    @property
    def records(self) -> tuple[ProofRecord, ...]:
        """Return ledger records in append order."""
        return tuple(self._records)

    def append(self, record: ProofRecord) -> None:
        """Append one proof record."""
        self._records.append(record)

    def summary(self) -> dict[str, object]:
        """Return aggregate proof counters by all report dimensions."""
        return summarize_records(self._records)


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


def _sorted_count_dict(counter: Counter[str]) -> dict[str, int]:
    """Return a normal dict sorted by counter key."""
    return {key: counter[key] for key in sorted(counter)}


def _delta_count_dict(counter: Counter[str]) -> dict[str, int]:
    """Return delta counts with every required delta key present."""
    return {delta: counter.get(delta, 0) for delta in ALL_DELTAS}


def _sorted_records(records: Iterable[ProofRecord]) -> list[ProofRecord]:
    """Return records sorted for deterministic report output."""
    return sorted(records, key=lambda record: (record.decision_id, record.fingerprint))


def _as_ledger(ledger_or_records: ProofLedger | Iterable[ProofRecord]) -> ProofLedger:
    """Return a ProofLedger for either supported report input shape."""
    if isinstance(ledger_or_records, ProofLedger):
        return ledger_or_records
    return ProofLedger(ledger_or_records)


def _bucket_key(record: ProofRecord) -> tuple[str, str, str, str]:
    """Return the production sample bucket key for a proof record."""
    return (
        record.strict_agh_delta,
        record.project_policy_delta,
        record.reason,
        record.outcome,
    )


def _bucket_dict(bucket: tuple[str, str, str, str]) -> dict[str, str]:
    """Return a report dictionary for a sample bucket tuple."""
    strict_delta, project_delta, reason, outcome = bucket
    return {
        "strict_agh_delta": strict_delta,
        "project_policy_delta": project_delta,
        "reason": reason,
        "outcome": outcome,
    }


def _capped_sample_record(record: ProofRecord) -> dict[str, object]:
    """Return one compact production-report sample record."""
    return {
        "decision_id": record.decision_id,
        "decision_type": record.decision_type,
        "fingerprint": record.fingerprint,
        "candidate_rule": record.candidate.normalized_rule,
        "candidate_domain": record.candidate.domain,
        "covering_rule": record.covering.normalized_rule if record.covering is not None else None,
        "sample": record.sample,
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


def summarize_records(records: Iterable[ProofRecord]) -> dict[str, object]:
    """
    Return proof counters by decision type, outcome, status, deltas, and reason.

    Delta sections always include all coverage categories so report consumers
    can display lost/gained/changed/uncertain buckets even when a run has zero.
    """
    materialized = list(records)
    decision_type_counts: Counter[str] = Counter()
    outcome_counts: Counter[str] = Counter()
    proof_status_counts: Counter[str] = Counter()
    reason_counts: Counter[str] = Counter()
    strict_delta_counts: Counter[str] = Counter()
    project_delta_counts: Counter[str] = Counter()

    for record in materialized:
        decision_type_counts[record.decision_type] += 1
        outcome_counts[record.outcome] += 1
        proof_status_counts[record.proof_status] += 1
        reason_counts[record.reason] += 1
        strict_delta_counts[record.strict_agh_delta] += 1
        project_delta_counts[record.project_policy_delta] += 1

    return {
        "total_records": len(materialized),
        "by_decision_type": _sorted_count_dict(decision_type_counts),
        "by_outcome": _sorted_count_dict(outcome_counts),
        "by_proof_status": _sorted_count_dict(proof_status_counts),
        "by_reason": _sorted_count_dict(reason_counts),
        "by_strict_agh_delta": _delta_count_dict(strict_delta_counts),
        "by_project_policy_delta": _delta_count_dict(project_delta_counts),
    }


def render_full_report(ledger_or_records: ProofLedger | Iterable[ProofRecord]) -> dict[str, object]:
    """
    Render a deterministic full report containing every proof record.

    Full reports are designed for small fixture sidecars and are sorted by
    decision id plus fingerprint rather than append order.
    """
    ledger = _as_ledger(ledger_or_records)
    return {
        "schema_version": PROOF_REPORT_SCHEMA_VERSION,
        "report_type": "full",
        "summary": ledger.summary(),
        "records": [record_to_dict(record) for record in _sorted_records(ledger.records)],
    }


def render_capped_report(
    ledger_or_records: ProofLedger | Iterable[ProofRecord],
    *,
    sample_cap: int = DEFAULT_SAMPLE_CAP,
) -> dict[str, object]:
    """
    Render a production-shaped report with capped samples per proof bucket.

    Buckets are keyed by strict AGH delta, project-policy delta, reason, and
    outcome. Each bucket exposes stable fingerprints plus compact sample data.
    """
    if sample_cap < 1:
        msg = "sample_cap must be at least 1"
        raise ValueError(msg)

    ledger = _as_ledger(ledger_or_records)
    grouped: dict[tuple[str, str, str, str], list[ProofRecord]] = defaultdict(list)
    for record in _sorted_records(ledger.records):
        grouped[_bucket_key(record)].append(record)

    sample_buckets: list[dict[str, object]] = []
    for bucket in sorted(grouped):
        bucket_records = grouped[bucket]
        sampled_records = bucket_records[:sample_cap]
        sample_buckets.append({
            "bucket": _bucket_dict(bucket),
            "total_records": len(bucket_records),
            "sampled_records": len(sampled_records),
            "records": [_capped_sample_record(record) for record in sampled_records],
        })

    return {
        "schema_version": PROOF_REPORT_SCHEMA_VERSION,
        "report_type": "capped",
        "sample_cap": sample_cap,
        "summary": ledger.summary(),
        "sample_buckets": sample_buckets,
    }


def write_report_json(path: str | Path, data: dict[str, object]) -> None:
    """
    Write a proof report as sorted UTF-8 JSON through a sibling temp file.

    Args:
        path: Destination JSON path.
        data: JSON-compatible report object.
    """
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = output_path.with_suffix(".tmp")
    with open(temp_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")
    temp_path.replace(output_path)
