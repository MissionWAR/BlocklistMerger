"""Aggregate internal stage diagnostics for cleaner and compiler decisions.

The helpers in this module project existing flat counters into named internal
stages. They are intentionally aggregate-only: no raw rules, samples,
fingerprints, or per-line records belong in the default pipeline stats surface.
"""

from collections.abc import Mapping
from typing import Final, TypedDict

from scripts.cleaner import (
    DISCARD_REASON_COMMENT,
    DISCARD_REASON_COSMETIC,
    DISCARD_REASON_EMPTY,
    DISCARD_REASON_INVALID,
    DISCARD_REASON_UNSUPPORTED_MODIFIER,
    DISCARD_REASON_URL_PATH,
)

# =============================================================================
# STAGE VOCABULARIES
# =============================================================================

CLEANER_STAGE_NORMALIZE: Final[str] = "normalize"
CLEANER_STAGE_PREFILTER: Final[str] = "prefilter"
CLEANER_STAGE_COMPATIBILITY: Final[str] = "compatibility"
CLEANER_STAGE_SYNTAX: Final[str] = "syntax"
CLEANER_STAGE_EMIT: Final[str] = "emit"

CLEANER_STAGES: Final[tuple[str, ...]] = (
    CLEANER_STAGE_NORMALIZE,
    CLEANER_STAGE_PREFILTER,
    CLEANER_STAGE_COMPATIBILITY,
    CLEANER_STAGE_SYNTAX,
    CLEANER_STAGE_EMIT,
)

COMPILER_STAGE_PARSE: Final[str] = "parse"
COMPILER_STAGE_NORMALIZE: Final[str] = "normalize"
COMPILER_STAGE_CLASSIFY: Final[str] = "classify"
COMPILER_STAGE_COMPRESS: Final[str] = "compress"
COMPILER_STAGE_INDEX: Final[str] = "index"
COMPILER_STAGE_PRUNE: Final[str] = "prune"
COMPILER_STAGE_WRITE: Final[str] = "write"

COMPILER_STAGES: Final[tuple[str, ...]] = (
    COMPILER_STAGE_PARSE,
    COMPILER_STAGE_NORMALIZE,
    COMPILER_STAGE_CLASSIFY,
    COMPILER_STAGE_COMPRESS,
    COMPILER_STAGE_INDEX,
    COMPILER_STAGE_PRUNE,
    COMPILER_STAGE_WRITE,
)

CLEANER_STAGE_BY_REASON: Final[dict[str, str]] = {
    DISCARD_REASON_COMMENT: CLEANER_STAGE_PREFILTER,
    DISCARD_REASON_EMPTY: CLEANER_STAGE_PREFILTER,
    DISCARD_REASON_COSMETIC: CLEANER_STAGE_COMPATIBILITY,
    DISCARD_REASON_UNSUPPORTED_MODIFIER: CLEANER_STAGE_COMPATIBILITY,
    DISCARD_REASON_URL_PATH: CLEANER_STAGE_COMPATIBILITY,
    DISCARD_REASON_INVALID: CLEANER_STAGE_SYNTAX,
}


# =============================================================================
# DATA STRUCTURES
# =============================================================================

class StageSummary(TypedDict):
    """JSON-friendly aggregate counters for one internal stage."""

    processed: int
    emitted: int
    discarded: int
    reasons: dict[str, int]


StageSummaries = dict[str, StageSummary]
StatsSource = Mapping[str, object] | object


# =============================================================================
# HELPERS
# =============================================================================

def _new_summary() -> StageSummary:
    """Return a zeroed summary for one stage."""
    return {
        "processed": 0,
        "emitted": 0,
        "discarded": 0,
        "reasons": {},
    }


def _new_stage_summaries(stages: tuple[str, ...]) -> StageSummaries:
    """Return zeroed summaries for every named stage."""
    return {stage: _new_summary() for stage in stages}


def _stat(stats: StatsSource, name: str) -> int:
    """Read an integer counter from a mapping or stats object."""
    value = stats.get(name, 0) if isinstance(stats, Mapping) else getattr(stats, name, 0)

    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return value


def _add_reason(
    summaries: StageSummaries,
    stage: str,
    reason: str,
    count: int,
    *,
    discarded: bool,
) -> None:
    """Add a reason count to one stage summary."""
    if count <= 0:
        return

    summary = summaries[stage]
    summary["processed"] += count
    if discarded:
        summary["discarded"] += count
    else:
        summary["emitted"] += count
    summary["reasons"][reason] = summary["reasons"].get(reason, 0) + count


def cleaner_stage_for_reason(reason: str) -> str:
    """Return the cleaner stage that owns an existing discard reason."""
    try:
        return CLEANER_STAGE_BY_REASON[reason]
    except KeyError as exc:
        msg = f"Unknown cleaner discard reason: {reason}"
        raise ValueError(msg) from exc


def cleaner_stage_summaries_from_stats(stats: Mapping[str, object]) -> StageSummaries:
    """Project flat cleaner counters into stable aggregate stage summaries."""
    summaries = _new_stage_summaries(CLEANER_STAGES)

    _add_reason(
        summaries,
        CLEANER_STAGE_NORMALIZE,
        "trimmed",
        _stat(stats, "trimmed"),
        discarded=False,
    )
    _add_reason(
        summaries,
        CLEANER_STAGE_PREFILTER,
        DISCARD_REASON_COMMENT,
        _stat(stats, "comments_removed"),
        discarded=True,
    )
    _add_reason(
        summaries,
        CLEANER_STAGE_PREFILTER,
        DISCARD_REASON_EMPTY,
        _stat(stats, "empty_removed"),
        discarded=True,
    )
    _add_reason(
        summaries,
        CLEANER_STAGE_COMPATIBILITY,
        DISCARD_REASON_COSMETIC,
        _stat(stats, "cosmetic_removed"),
        discarded=True,
    )
    _add_reason(
        summaries,
        CLEANER_STAGE_COMPATIBILITY,
        DISCARD_REASON_UNSUPPORTED_MODIFIER,
        _stat(stats, "unsupported_removed"),
        discarded=True,
    )
    _add_reason(
        summaries,
        CLEANER_STAGE_COMPATIBILITY,
        DISCARD_REASON_URL_PATH,
        _stat(stats, "url_path_removed"),
        discarded=True,
    )
    _add_reason(
        summaries,
        CLEANER_STAGE_SYNTAX,
        DISCARD_REASON_INVALID,
        _stat(stats, "invalid_removed"),
        discarded=True,
    )
    _add_reason(
        summaries,
        CLEANER_STAGE_EMIT,
        "kept",
        _stat(stats, "lines_clean"),
        discarded=False,
    )

    return summaries


def compiler_stage_summaries_from_stats(stats: StatsSource) -> StageSummaries:
    """Project flat compiler counters into stable aggregate stage summaries."""
    summaries = _new_stage_summaries(COMPILER_STAGES)

    total_input = _stat(stats, "total_input") or _stat(stats, "lines_clean")
    total_output = _stat(stats, "total_output") or _stat(stats, "lines_output")
    malformed = _stat(stats, "malformed_discarded")
    duplicate = _stat(stats, "duplicate_pruned")
    compressed = _stat(stats, "formats_compressed")
    promoted = _stat(stats, "compression_policy_broadened")
    index_entries = (
        _stat(stats, "abp_rule_keys")
        + _stat(stats, "abp_wildcard_keys")
        + _stat(stats, "exception_rule_keys")
        + _stat(stats, "duplicate_index_size")
        + _stat(stats, "other_rule_count")
    )
    pruned = {
        "abp_subdomain": _stat(stats, "abp_subdomain_pruned"),
        "tld_wildcard": _stat(stats, "tld_wildcard_pruned"),
        "whitelist_conflict": _stat(stats, "whitelist_conflict_pruned"),
        "local_hostname": _stat(stats, "local_hostname_pruned"),
    }

    summaries[COMPILER_STAGE_PARSE]["processed"] = total_input
    summaries[COMPILER_STAGE_PARSE]["emitted"] = max(total_input - malformed, 0)
    summaries[COMPILER_STAGE_PARSE]["discarded"] = malformed
    if malformed:
        summaries[COMPILER_STAGE_PARSE]["reasons"]["malformed"] = malformed

    summaries[COMPILER_STAGE_NORMALIZE]["processed"] = total_input
    summaries[COMPILER_STAGE_NORMALIZE]["emitted"] = total_input

    summaries[COMPILER_STAGE_CLASSIFY]["processed"] = total_input
    summaries[COMPILER_STAGE_CLASSIFY]["emitted"] = total_input
    for reason in (
        "block",
        "exception",
        "rewrite",
        "disable",
        "ignored",
        "unsupported",
        "uncertain",
    ):
        count = _stat(stats, f"rule_effect_{reason}")
        if count:
            summaries[COMPILER_STAGE_CLASSIFY]["reasons"][reason] = count

    summaries[COMPILER_STAGE_COMPRESS]["processed"] = compressed
    summaries[COMPILER_STAGE_COMPRESS]["emitted"] = compressed
    if promoted:
        summaries[COMPILER_STAGE_COMPRESS]["reasons"]["hosts_plain_promoted_to_abp"] = promoted

    summaries[COMPILER_STAGE_INDEX]["processed"] = index_entries + duplicate
    summaries[COMPILER_STAGE_INDEX]["emitted"] = index_entries
    summaries[COMPILER_STAGE_INDEX]["discarded"] = duplicate
    if duplicate:
        summaries[COMPILER_STAGE_INDEX]["reasons"]["duplicate"] = duplicate

    summaries[COMPILER_STAGE_PRUNE]["processed"] = total_output + sum(pruned.values())
    summaries[COMPILER_STAGE_PRUNE]["emitted"] = total_output
    summaries[COMPILER_STAGE_PRUNE]["discarded"] = sum(pruned.values())
    summaries[COMPILER_STAGE_PRUNE]["reasons"] = {
        reason: count for reason, count in pruned.items() if count
    }

    summaries[COMPILER_STAGE_WRITE]["processed"] = total_output
    summaries[COMPILER_STAGE_WRITE]["emitted"] = total_output

    return summaries
