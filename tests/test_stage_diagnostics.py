"""Tests for aggregate internal stage diagnostics."""

import pytest

from scripts.cleaner import (
    DISCARD_REASON_COMMENT,
    DISCARD_REASON_COSMETIC,
    DISCARD_REASON_EMPTY,
    DISCARD_REASON_INVALID,
    DISCARD_REASON_UNSUPPORTED_MODIFIER,
    DISCARD_REASON_URL_PATH,
)
from scripts.stage_diagnostics import (
    CLEANER_STAGE_COMPATIBILITY,
    CLEANER_STAGE_EMIT,
    CLEANER_STAGE_NORMALIZE,
    CLEANER_STAGE_PREFILTER,
    CLEANER_STAGE_SYNTAX,
    CLEANER_STAGES,
    COMPILER_STAGES,
    cleaner_stage_for_reason,
    cleaner_stage_summaries_from_stats,
    compiler_stage_summaries_from_stats,
)


def test_cleaner_stage_summary_contains_all_stages_when_zero() -> None:
    summaries = cleaner_stage_summaries_from_stats({})

    assert tuple(summaries) == CLEANER_STAGES
    assert set(summaries) == set(CLEANER_STAGES)
    assert all(summary == {
        "processed": 0,
        "emitted": 0,
        "discarded": 0,
        "reasons": {},
    } for summary in summaries.values())


def test_cleaner_trimmed_rows_are_normalize_metadata_only() -> None:
    summaries = cleaner_stage_summaries_from_stats({
        "lines_clean": 1,
        "trimmed": 2,
    })

    assert summaries[CLEANER_STAGE_NORMALIZE]["reasons"] == {"trimmed": 2}
    assert summaries[CLEANER_STAGE_NORMALIZE]["discarded"] == 0
    assert summaries[CLEANER_STAGE_EMIT]["reasons"] == {"kept": 1}
    assert all(
        "trimmed" not in summaries[stage]["reasons"]
        for stage in CLEANER_STAGES
        if stage != CLEANER_STAGE_NORMALIZE
    )


@pytest.mark.parametrize(
    ("reason", "stage"),
    [
        (DISCARD_REASON_COMMENT, CLEANER_STAGE_PREFILTER),
        (DISCARD_REASON_EMPTY, CLEANER_STAGE_PREFILTER),
        (DISCARD_REASON_COSMETIC, CLEANER_STAGE_COMPATIBILITY),
        (DISCARD_REASON_UNSUPPORTED_MODIFIER, CLEANER_STAGE_COMPATIBILITY),
        (DISCARD_REASON_URL_PATH, CLEANER_STAGE_COMPATIBILITY),
        (DISCARD_REASON_INVALID, CLEANER_STAGE_SYNTAX),
    ],
)
def test_cleaner_reason_projection_uses_existing_taxonomy(reason: str, stage: str) -> None:
    assert cleaner_stage_for_reason(reason) == stage


def test_unknown_cleaner_reason_raises_value_error() -> None:
    with pytest.raises(ValueError, match="Unknown cleaner discard reason"):
        cleaner_stage_for_reason("new_reason")


def test_compiler_stage_summary_contains_all_stages_when_zero() -> None:
    summaries = compiler_stage_summaries_from_stats({})

    assert tuple(summaries) == COMPILER_STAGES
    assert set(summaries) == set(COMPILER_STAGES)
    assert all(set(summary) == {"processed", "emitted", "discarded", "reasons"}
               for summary in summaries.values())
