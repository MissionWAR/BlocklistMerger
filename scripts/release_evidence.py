#!/usr/bin/env python3
"""
release_evidence.py - Diagnostic release evidence helpers.

This module provides pure helper functions for release diagnostics that should
remain inspect-only until a later validator plan explicitly promotes stable,
deterministic regressions into release gates.
"""

import json
from collections import Counter
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Final, NamedTuple

from scripts.compiler import (
    LOCAL_HOSTNAMES,
    PLAIN_DOMAIN_PATTERN,
    extract_abp_info,
    extract_hosts_info,
    walk_parent_domains,
)
from scripts.pruning_proof import fingerprint_payload
from scripts.rule_semantics import (
    EFFECT_BLOCK,
    EFFECT_EXCEPTION,
    canonical_modifier_signature,
    classify_rule_effect,
    modifier_names,
    modifier_scope_covers,
    parse_modifier_text,
)
from scripts.rule_syntax import (
    RULE_KIND_ABP,
    RULE_KIND_HOSTS,
    RULE_KIND_PLAIN_DOMAIN,
    classify_rule_syntax,
)

# =============================================================================
# CONFIGURATION CONSTANTS
# =============================================================================

RELEASE_EVIDENCE_SCHEMA_VERSION: Final[int] = 1
DEFAULT_SAMPLE_CAP: Final[int] = 25

COVERAGE_EFFECT_BLOCK: Final[str] = "block"
COVERAGE_EFFECT_ALLOW: Final[str] = "allow"
COVERAGE_EFFECT_DIAGNOSTIC: Final[str] = "diagnostic"

SCOPE_APEX: Final[str] = "apex"
SCOPE_SUBDOMAIN: Final[str] = "subdomain"
SCOPE_APEX_AND_SUBDOMAINS: Final[str] = "apex_and_subdomains"
SCOPE_WILDCARD_CHILD: Final[str] = "wildcard_child"
SCOPE_WILDCARD_APEX_ALLOWED: Final[str] = "wildcard_apex_allowed"
SCOPE_EXACT_HOST: Final[str] = "exact_host"
SCOPE_UNSCOPED_GLOBAL: Final[str] = "unscoped_global"

_DEGRADED_SOURCE_STATUSES: Final[frozenset[str]] = frozenset({
    "failed",
    "fallback_cache",
    "stale_cache",
})

__all__ = [
    "COVERAGE_EFFECT_ALLOW",
    "COVERAGE_EFFECT_BLOCK",
    "COVERAGE_EFFECT_DIAGNOSTIC",
    "DEFAULT_SAMPLE_CAP",
    "RELEASE_EVIDENCE_SCHEMA_VERSION",
    "SCOPE_APEX",
    "SCOPE_APEX_AND_SUBDOMAINS",
    "SCOPE_EXACT_HOST",
    "SCOPE_SUBDOMAIN",
    "SCOPE_UNSCOPED_GLOBAL",
    "SCOPE_WILDCARD_APEX_ALLOWED",
    "SCOPE_WILDCARD_CHILD",
    "CoverageRecord",
    "MembershipChurn",
    "compact_source_health_context",
    "compare_membership",
    "coverage_record_to_dict",
    "coverage_records_for_rule",
    "coverage_records_from_rules",
    "fingerprint_membership",
    "membership_churn_to_dict",
    "normalize_membership",
    "record_covers_canary_scope",
    "render_diagnostic_sidecar",
    "write_report_json",
]


# =============================================================================
# DATA STRUCTURES
# =============================================================================


class MembershipChurn(NamedTuple):
    """
    Deterministic membership comparison evidence.

    Counts are exact for the provided iterables. Samples are sorted and capped so
    diagnostic sidecars stay bounded on production-sized release artifacts.
    """

    current_count: int
    previous_count: int
    added_count: int
    removed_count: int
    current_fingerprint: str
    previous_fingerprint: str
    added_fingerprint: str
    removed_fingerprint: str
    added_samples: tuple[str, ...]
    removed_samples: tuple[str, ...]


class CoverageRecord(NamedTuple):
    """
    Scope-aware evidence for one parsed release rule.

    The record is diagnostic data only. `is_global` is intentionally false for
    modifiers, exceptions, wildcard-child rules, exact-host inputs, and
    unsupported or uncertain effects.
    """

    raw_rule: str
    domain: str
    syntax_kind: str
    effect: str
    scope: str
    is_global: bool
    is_exception: bool
    is_wildcard: bool
    modifier_names: tuple[str, ...]
    modifier_signature: tuple[object, ...]
    notes: tuple[str, ...]


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================


def _require_sample_cap(sample_cap: int) -> None:
    """Reject sample caps that cannot provide useful diagnostic samples."""
    if sample_cap < 1:
        msg = "sample_cap must be at least 1"
        raise ValueError(msg)


def _safe_int(value: object) -> int:
    """Return a non-negative integer for compact report counters."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return max(value, 0)
    if isinstance(value, str):
        try:
            return max(int(value), 0)
        except ValueError:
            return 0
    return 0


def _sorted_count_dict(counter: Counter[str]) -> dict[str, int]:
    """Return a deterministic normal dictionary from a string counter."""
    return {key: counter[key] for key in sorted(counter)}


def _canonicalize_domain(domain: str) -> str:
    """Return a lowercase domain key without whitespace or trailing dots."""
    return domain.lower().strip().rstrip(".")


def _domain_matches_or_is_child(target: str, parent: str) -> bool:
    """Return True when target is parent or below parent."""
    return target == parent or parent in walk_parent_domains(target)


def _domain_is_child(target: str, parent: str) -> bool:
    """Return True when target is below parent, excluding the parent itself."""
    return parent in walk_parent_domains(target)


def _coverage_effect(raw_rule: str) -> str:
    """Map rule semantics effects to the release-evidence vocabulary."""
    effect = classify_rule_effect(raw_rule)
    if effect.effect == EFFECT_BLOCK:
        return COVERAGE_EFFECT_BLOCK
    if effect.effect == EFFECT_EXCEPTION:
        return COVERAGE_EFFECT_ALLOW
    return COVERAGE_EFFECT_DIAGNOSTIC


def _notes_from_reason(reason: str) -> tuple[str, ...]:
    """Return stable note fragments from a rule-semantics reason string."""
    return tuple(part for part in reason.split(";") if part)


def _json_compatible(value: object) -> object:
    """Return a JSON-compatible value with tuple-like containers normalized."""
    if isinstance(value, tuple | list):
        return [_json_compatible(item) for item in value]
    if isinstance(value, set | frozenset):
        return sorted(_json_compatible(item) for item in value)
    if isinstance(value, Mapping):
        return {str(key): _json_compatible(item) for key, item in value.items()}
    return value


def _make_coverage_record(
    *,
    raw_rule: str,
    domain: str,
    syntax_kind: str,
    effect: str,
    scope: str,
    is_exception: bool = False,
    is_wildcard: bool = False,
    modifier_text: str | None = None,
) -> CoverageRecord:
    """Build one canonical coverage record from parsed rule facets."""
    effect_info = classify_rule_effect(raw_rule)
    modifiers = parse_modifier_text(modifier_text)
    names = tuple(sorted(modifier_names(modifiers)))
    is_global = (
        effect == COVERAGE_EFFECT_BLOCK
        and scope == SCOPE_APEX_AND_SUBDOMAINS
        and not is_exception
        and not is_wildcard
        and not names
        and not effect_info.uncertain
        and modifier_scope_covers(modifiers, ())
    )
    return CoverageRecord(
        raw_rule=raw_rule.strip(),
        domain=_canonicalize_domain(domain),
        syntax_kind=syntax_kind,
        effect=effect,
        scope=scope,
        is_global=is_global,
        is_exception=is_exception,
        is_wildcard=is_wildcard,
        modifier_names=names,
        modifier_signature=canonical_modifier_signature(modifiers),
        notes=_notes_from_reason(effect_info.reason),
    )


def normalize_membership(lines: Iterable[str]) -> tuple[str, ...]:
    """
    Return sorted unique non-empty release artifact membership rows.

    Args:
        lines: Raw current or previous release output lines.

    Returns:
        Sorted tuple of stripped, non-empty rule strings.
    """
    return tuple(sorted({line.strip() for line in lines if line.strip()}))


def fingerprint_membership(lines: Iterable[str]) -> str:
    """
    Return a deterministic SHA-256 fingerprint for normalized membership.

    The hashing semantics intentionally reuse `scripts.pruning_proof` so proof
    and release-evidence fingerprints normalize JSON payloads identically.
    """
    return fingerprint_payload(normalize_membership(lines))


def compare_membership(
    current_lines: Iterable[str],
    previous_lines: Iterable[str],
    *,
    sample_cap: int = DEFAULT_SAMPLE_CAP,
) -> MembershipChurn:
    """
    Compare current and previous release membership as diagnostic evidence.

    Args:
        current_lines: Current release output rows.
        previous_lines: Previous release output rows.
        sample_cap: Maximum number of added and removed samples to retain.

    Returns:
        MembershipChurn with exact counts, fingerprints, and capped samples.
    """
    _require_sample_cap(sample_cap)

    current = normalize_membership(current_lines)
    previous = normalize_membership(previous_lines)
    current_set = set(current)
    previous_set = set(previous)
    added = tuple(sorted(current_set - previous_set))
    removed = tuple(sorted(previous_set - current_set))

    return MembershipChurn(
        current_count=len(current),
        previous_count=len(previous),
        added_count=len(added),
        removed_count=len(removed),
        current_fingerprint=fingerprint_payload(current),
        previous_fingerprint=fingerprint_payload(previous),
        added_fingerprint=fingerprint_payload(added),
        removed_fingerprint=fingerprint_payload(removed),
        added_samples=added[:sample_cap],
        removed_samples=removed[:sample_cap],
    )


def membership_churn_to_dict(churn: MembershipChurn) -> dict[str, object]:
    """Return a JSON-compatible dictionary for membership churn evidence."""
    return {
        "current_count": churn.current_count,
        "previous_count": churn.previous_count,
        "added_count": churn.added_count,
        "removed_count": churn.removed_count,
        "current_fingerprint": churn.current_fingerprint,
        "previous_fingerprint": churn.previous_fingerprint,
        "added_fingerprint": churn.added_fingerprint,
        "removed_fingerprint": churn.removed_fingerprint,
        "added_samples": list(churn.added_samples),
        "removed_samples": list(churn.removed_samples),
    }


def compact_source_health_context(source_health_report: Mapping[str, object]) -> dict[str, object]:
    """
    Return compact diagnostic source-health context.

    Rich per-source rows stay in the source-health report itself. This helper
    keeps only aggregate counts needed to correlate release diagnostics.
    """
    if not source_health_report:
        return {
            "available": False,
            "source_count": 0,
            "totals_by_status": {},
            "degraded_sources": 0,
        }

    sources = source_health_report.get("sources")
    source_count = _safe_int(source_health_report.get("source_count"))
    if source_count == 0 and isinstance(sources, list):
        source_count = len(sources)

    totals_by_status: Counter[str] = Counter()
    raw_totals = source_health_report.get("totals_by_status")
    if isinstance(raw_totals, Mapping):
        for status, count in raw_totals.items():
            status_text = str(status)
            if status_text:
                totals_by_status[status_text] = _safe_int(count)
    elif isinstance(sources, list):
        for source in sources:
            if isinstance(source, Mapping):
                status_text = str(source.get("status") or "")
                if status_text:
                    totals_by_status[status_text] += 1

    degraded_sources = sum(totals_by_status.get(status, 0) for status in _DEGRADED_SOURCE_STATUSES)
    return {
        "available": True,
        "source_count": source_count,
        "totals_by_status": _sorted_count_dict(totals_by_status),
        "degraded_sources": degraded_sources,
    }


def coverage_record_to_dict(record: CoverageRecord) -> dict[str, object]:
    """Return a deterministic JSON-compatible dictionary for one coverage record."""
    return {
        "raw_rule": record.raw_rule,
        "domain": record.domain,
        "syntax_kind": record.syntax_kind,
        "effect": record.effect,
        "scope": record.scope,
        "is_global": record.is_global,
        "is_exception": record.is_exception,
        "is_wildcard": record.is_wildcard,
        "modifier_names": list(record.modifier_names),
        "modifier_signature": _json_compatible(record.modifier_signature),
        "notes": list(record.notes),
    }


def coverage_records_for_rule(rule: str) -> tuple[CoverageRecord, ...]:
    """
    Return diagnostic coverage records for one ABP, hosts, or plain-domain rule.

    Parser and modifier behavior is delegated to existing compiler and
    rule-semantics helpers so this module does not drift into a second parser.
    """
    raw_rule = rule.strip()
    if not raw_rule:
        return ()

    syntax = classify_rule_syntax(raw_rule)
    if syntax.is_invalid:
        return ()

    if syntax.kind == RULE_KIND_ABP:
        domain, _legacy_modifiers, is_exception, is_wildcard = extract_abp_info(raw_rule)
        if not domain:
            return ()
        effect_info = classify_rule_effect(raw_rule)
        effect = _coverage_effect(raw_rule)
        if is_wildcard:
            scope = SCOPE_WILDCARD_CHILD
        elif effect == COVERAGE_EFFECT_DIAGNOSTIC and effect_info.scope:
            scope = effect_info.scope
        else:
            scope = SCOPE_APEX_AND_SUBDOMAINS
        return (
            _make_coverage_record(
                raw_rule=raw_rule,
                domain=domain,
                syntax_kind=syntax.kind,
                effect=effect,
                scope=scope,
                is_exception=is_exception,
                is_wildcard=is_wildcard,
                modifier_text=syntax.modifier_text,
            ),
        )

    if syntax.kind == RULE_KIND_HOSTS:
        _ip, domains = extract_hosts_info(raw_rule)
        return tuple(
            _make_coverage_record(
                raw_rule=raw_rule,
                domain=domain,
                syntax_kind=syntax.kind,
                effect=COVERAGE_EFFECT_BLOCK,
                scope=SCOPE_EXACT_HOST,
            )
            for domain in domains
        )

    if syntax.kind == RULE_KIND_PLAIN_DOMAIN and PLAIN_DOMAIN_PATTERN.match(raw_rule):
        domain = _canonicalize_domain(raw_rule)
        if domain in LOCAL_HOSTNAMES:
            return ()
        return (
            _make_coverage_record(
                raw_rule=raw_rule,
                domain=domain,
                syntax_kind=syntax.kind,
                effect=COVERAGE_EFFECT_BLOCK,
                scope=SCOPE_EXACT_HOST,
            ),
        )

    return ()


def coverage_records_from_rules(rules: Iterable[str]) -> tuple[CoverageRecord, ...]:
    """Return flattened coverage records sorted for deterministic reports."""
    records = [
        record
        for rule in rules
        for record in coverage_records_for_rule(rule)
    ]
    return tuple(sorted(records, key=lambda record: (record.domain, record.raw_rule, record.scope)))


def record_covers_canary_scope(
    record: CoverageRecord,
    domain: str,
    required_scope: str,
) -> bool:
    """
    Return True when one record conservatively satisfies a canary scope.

    Modifier-limited, unsupported, uncertain, diagnostic, exact-host-only, and
    wildcard-child-only records cannot satisfy broader global coverage.
    """
    target = _canonicalize_domain(domain)
    source = record.domain
    if not target or not source:
        return False

    if required_scope == SCOPE_WILDCARD_APEX_ALLOWED:
        return (
            record.effect == COVERAGE_EFFECT_BLOCK
            and record.scope == SCOPE_WILDCARD_CHILD
            and not record.modifier_names
            and target == source
        )

    if record.effect != COVERAGE_EFFECT_BLOCK or record.modifier_names:
        return False

    if required_scope == SCOPE_EXACT_HOST:
        return record.scope == SCOPE_EXACT_HOST and target == source

    if record.scope == SCOPE_EXACT_HOST:
        return False

    if required_scope == SCOPE_WILDCARD_CHILD:
        return record.scope == SCOPE_WILDCARD_CHILD and _domain_is_child(target, source)

    if record.scope == SCOPE_WILDCARD_CHILD:
        return False

    if record.scope != SCOPE_APEX_AND_SUBDOMAINS:
        return False

    if required_scope == SCOPE_UNSCOPED_GLOBAL:
        return record.is_global and _domain_matches_or_is_child(target, source)
    if required_scope == SCOPE_APEX:
        return record.is_global and target == source
    if required_scope == SCOPE_SUBDOMAIN:
        return record.is_global and _domain_is_child(target, source)
    if required_scope == SCOPE_APEX_AND_SUBDOMAINS:
        return record.is_global and target == source

    return False


def _coverage_record_mapping(record: object) -> dict[str, object]:
    """Return a JSON-compatible mapping for a coverage record-like object."""
    if isinstance(record, CoverageRecord):
        return coverage_record_to_dict(record)
    if isinstance(record, Mapping):
        return dict(_json_compatible(record))
    if hasattr(record, "_asdict"):
        return dict(_json_compatible(record._asdict()))
    msg = f"unsupported coverage record type: {type(record).__name__}"
    raise TypeError(msg)


def _sorted_coverage_records(records: Iterable[object]) -> list[dict[str, object]]:
    """Return coverage records sorted by normalized JSON payload."""
    mapped = [_coverage_record_mapping(record) for record in records]
    return sorted(
        mapped,
        key=lambda record: json.dumps(
            record,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ),
    )


def _coverage_summary(records: list[dict[str, object]], sample_cap: int) -> dict[str, object]:
    """Return compact coverage-record counters."""
    by_effect: Counter[str] = Counter()
    by_scope: Counter[str] = Counter()
    for record in records:
        effect = record.get("effect")
        scope = record.get("scope")
        if effect is not None:
            by_effect[str(effect)] += 1
        if scope is not None:
            by_scope[str(scope)] += 1

    return {
        "total_records": len(records),
        "sampled_records": min(len(records), sample_cap),
        "by_effect": _sorted_count_dict(by_effect),
        "by_scope": _sorted_count_dict(by_scope),
    }


def render_diagnostic_sidecar(
    *,
    membership_churn: MembershipChurn | None = None,
    source_health_context: Mapping[str, object] | None = None,
    coverage_records: Iterable[object] = (),
    sample_cap: int = DEFAULT_SAMPLE_CAP,
) -> dict[str, object]:
    """
    Render a bounded diagnostic-only release evidence sidecar.

    The returned object deliberately contains no finding, threshold, warning,
    error, or exit-code fields. Later validator code can display it, but this
    helper does not decide release policy.
    """
    _require_sample_cap(sample_cap)
    sorted_coverage_records = _sorted_coverage_records(coverage_records)
    return {
        "schema_version": RELEASE_EVIDENCE_SCHEMA_VERSION,
        "report_type": "release_evidence",
        "sample_cap": sample_cap,
        "membership_churn": (
            membership_churn_to_dict(membership_churn)
            if membership_churn is not None
            else None
        ),
        "source_health_context": dict(source_health_context or {"available": False}),
        "coverage_summary": _coverage_summary(sorted_coverage_records, sample_cap),
        "coverage_records": sorted_coverage_records[:sample_cap],
    }


def write_report_json(path: str | Path, data: dict[str, object]) -> None:
    """
    Write sorted UTF-8 JSON through a sibling temp file and atomic replacement.

    Args:
        path: Destination JSON report path.
        data: JSON-compatible report object.
    """
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = output_path.with_suffix(".tmp")
    with open(temp_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, sort_keys=True)
        f.write("\n")
    temp_path.replace(output_path)
