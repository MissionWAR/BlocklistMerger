#!/usr/bin/env python3
"""
test_apex_wildcard_plumbing.py

Apex-covers-TLD-wildcard evidence plumbing suite (SAFE-01, Phase 15).

One module per pruning family (D-08), parallel to
test_denyallow_wildcard_pruning.py: this file owns the fixture-scale
stats-vs-ledger equality proof for the apex-covers-wildcard family.

Zero-behavior contract (Phase 15 lands additive plumbing only): no emission
site exists yet, so under default settings the paired counter reads 0 at every
layer, the new reason never enters any proof ledger, and compiled output stays
byte-identical to today's compiler. The direct-drive legs exercise the shared
_record_proven_pruning() recording path manually -- pairing the counter bump
with the ledger record exactly as Phase 16's future emission site will --
proving reason-to-counter equality 1:1 (including count exactness beyond the
capped-ledger sample cap) before any real prune exists.

Pattern source: tests/test_denyallow_wildcard_pruning.py (v1.2 denyallow suite).
"""

import os
import tempfile

# Importing the underscore-private helpers directly from scripts.compiler
# and scripts.pipeline (_parse_abp_rule, _record_proven_pruning,
# _new_pipeline_stats) is an intentional cross-module private import for
# unit pinning; no Ruff-selected rule flags it.
from scripts.compiler import (
    CompileStats,
    _parse_abp_rule,
    _record_proven_pruning,
    compile_rules,
)
from scripts.pipeline import PipelineStats, _new_pipeline_stats, process_files
from scripts.pruning_proof import (
    DEFAULT_SAMPLE_CAP,
    REASON_APEX_COVERS_TLD_WILDCARD,
    CappedProofLedger,
)

# ----------------------------------------------------------------------
# Zero-behavior fixture: fixed line list compiled under default settings.
# EXPECTED_OUTPUT_LINES was captured from today's observed compiler output
# at authoring time (never hand-predicted); the byte-identity leg pins it
# so any future behavioral flip fails loudly here first.
# ----------------------------------------------------------------------

FIXTURE_LINES = [
    "! apex plumbing fixture",
    "||*.autos^",
    "||autos^",
    "||ads.example.com^",
    "||ads.example.com^",
    "0.0.0.0 trackers.example.net",
    "example.org",
]

EXPECTED_OUTPUT_LINES = [
    "||*.autos^",
    "||autos^",
    "||ads.example.com^",
    "||trackers.example.net^",
    "||example.org^",
]


class TestApexCompilePlane:
    """Fixture-scale compile/recording legs for the apex-covers family."""

    def _compile(self, lines, **compile_kwargs):
        """Compile lines through the full pipeline, returning output and stats."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "output.txt")
            stats = compile_rules(lines, output, **compile_kwargs)
            with open(output, encoding="utf-8") as f:
                rules = [line.strip() for line in f if line.strip()]
            return rules, stats

    def _drive_once(self, ledger, candidate_text, covering_text):
        """Pair one manual increment with one recording-path record.

        Mirrors the adjacent increment+record discipline of the shipped
        denyallow emission site so these legs lock the exact shape the
        future apex emission site must copy.
        """
        candidate = _parse_abp_rule(candidate_text)
        covering = _parse_abp_rule(covering_text)
        assert candidate is not None
        assert covering is not None
        _record_proven_pruning(
            ledger,
            reason=REASON_APEX_COVERS_TLD_WILDCARD,
            candidate=candidate,
            covering=covering,
        )
        return candidate, covering

    def test_default_compile_is_byte_identical_with_zero_counter_and_no_apex_ledger_entries(self):
        """Default settings: output bytes unchanged, counter 0, reason absent."""
        ledger = CappedProofLedger()
        rules, stats = self._compile(FIXTURE_LINES, proof_ledger=ledger)

        assert rules == EXPECTED_OUTPUT_LINES
        assert stats.apex_covered_wildcard_pruned == 0
        summary = ledger.summary()
        assert REASON_APEX_COVERS_TLD_WILDCARD not in summary["by_reason"]

    def test_recording_path_pairs_reason_and_counter_one_to_one(self):
        """Direct drive: ledger tally equals the manually bumped counter."""
        stats = CompileStats()
        ledger = CappedProofLedger()

        self._drive_once(ledger, "||*.autos^", "||autos^")
        stats.apex_covered_wildcard_pruned += 1

        tally = ledger.summary()["by_reason"][REASON_APEX_COVERS_TLD_WILDCARD]
        assert tally == 1
        assert stats.apex_covered_wildcard_pruned == tally

    def test_ledger_record_carries_full_apex_witness_detail(self):
        """Witness detail rides free from the shared recording path (D-04)."""
        ledger = CappedProofLedger()

        self._drive_once(ledger, "||*.autos^", "||autos^")

        matches = [
            record
            for record in ledger.records
            if record.reason == REASON_APEX_COVERS_TLD_WILDCARD
        ]
        assert len(matches) == 1
        record = matches[0]
        assert record.sample["candidate_rule"] == "||*.autos^"
        assert record.sample["covering_rule"] == "||autos^"
        assert isinstance(record.sample["modifier_scope_proven"], bool)
        assert record.fingerprint
        assert record.candidate.rule_kind
        assert record.candidate.domain_shape
        assert record.candidate.modifier_signature is not None

    def test_cap_tally_keeps_counts_exact_beyond_sample_cap(self):
        """Counts stay exact past the cap; stored entries stay bounded (D-05)."""
        stats = CompileStats()
        ledger = CappedProofLedger()
        total_drives = DEFAULT_SAMPLE_CAP + 5

        for index in range(total_drives):
            label = f"dom{index}"
            self._drive_once(ledger, f"||*.{label}^", f"||{label}^")
            stats.apex_covered_wildcard_pruned += 1

        tally = ledger.summary()["by_reason"][REASON_APEX_COVERS_TLD_WILDCARD]
        assert tally == total_drives
        assert stats.apex_covered_wildcard_pruned == tally
        assert len(ledger.records) <= DEFAULT_SAMPLE_CAP


class TestApexPipelineSpine:
    """Pipeline wiring legs: typed key, zero-init seed, flatten transfer."""

    def test_pipeline_zero_init_declares_new_key(self):
        """The TypedDict declares the key and fresh stats zero-init it."""
        assert "apex_covered_wildcard_pruned" in PipelineStats.__annotations__
        assert _new_pipeline_stats()["apex_covered_wildcard_pruned"] == 0

    def test_pipeline_flatten_surfaces_new_key_at_fixture_scale(self, tmp_path):
        """End-to-end run surfaces the key through cleaning->compile->flatten."""
        input_dir = tmp_path / "input"
        input_dir.mkdir()
        (input_dir / "list.txt").write_text(
            "# apex flatten fixture\n"
            "||example.com^\n"
            "0.0.0.0 ads.example.net\n"
            "||example.com^\n",
            encoding="utf-8",
        )
        output_file = tmp_path / "merged.txt"

        stats = process_files(str(input_dir), str(output_file))

        assert stats["apex_covered_wildcard_pruned"] == 0


# ----------------------------------------------------------------------
# Schema-era guards (Plan 15-02).
#
# The drift guard protects the intentional D-09 duplication: the
# pipeline-stats schema constant is deliberately duplicated between the
# producer (scripts.pipeline) and the consumer (scripts.release_validator),
# and release_validator stays standalone by design (no consolidation
# import). These function-local imports keep the module header free of
# schema-era identifiers, matching how Plan 15-01 authored this file.
# ----------------------------------------------------------------------


def test_pipeline_stats_schema_version_matches_release_validator():
    """Guard the intentional D-09 duplication: producer and consumer must agree."""
    from scripts.pipeline import PIPELINE_STATS_SCHEMA_VERSION as producer
    from scripts.release_validator import PIPELINE_STATS_SCHEMA_VERSION as consumer

    assert producer == consumer
    assert producer == 5  # pin current era; update with each sanctioned bump


def test_proof_report_schema_version_stays_at_one():
    """Negative assertion (D-03): the proof-report era never moves with the stats era."""
    from scripts.pruning_proof import PROOF_REPORT_SCHEMA_VERSION

    assert PROOF_REPORT_SCHEMA_VERSION == 1
