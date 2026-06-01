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

from scripts.pruning_proof import fingerprint_payload

# =============================================================================
# CONFIGURATION CONSTANTS
# =============================================================================

RELEASE_EVIDENCE_SCHEMA_VERSION: Final[int] = 1
DEFAULT_SAMPLE_CAP: Final[int] = 25

_DEGRADED_SOURCE_STATUSES: Final[frozenset[str]] = frozenset({
    "failed",
    "fallback_cache",
    "stale_cache",
})

__all__ = [
    "DEFAULT_SAMPLE_CAP",
    "RELEASE_EVIDENCE_SCHEMA_VERSION",
    "MembershipChurn",
    "compact_source_health_context",
    "compare_membership",
    "fingerprint_membership",
    "membership_churn_to_dict",
    "normalize_membership",
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


def _coverage_record_mapping(record: object) -> dict[str, object]:
    """Return a JSON-compatible mapping for a coverage record-like object."""
    if isinstance(record, Mapping):
        return dict(record)
    if hasattr(record, "_asdict"):
        return dict(record._asdict())
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
