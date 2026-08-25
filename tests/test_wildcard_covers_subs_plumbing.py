#!/usr/bin/env python3
"""
test_wildcard_covers_subs_plumbing.py

Wildcard-covers-sub evidence plumbing suite (PRUNE-01/EVID-01, Phase 19).

One module per pruning family (D-19-08), parallel to
test_apex_wildcard_plumbing.py: this file owns the fixture-scale
stats-vs-ledger equality proof for the wildcard-covers-sub family.

Zero-behavior contract (Phase 19 lands additive plumbing only): no emission
site exists yet, so in BOTH flag states the paired counter reads 0 at every
layer, the new reason never enters any proof ledger, and compiled output stays
byte-identical to today's compiler. The direct-drive legs exercise the shared
_record_proven_pruning() recording path manually -- pairing the counter bump
with the ledger record exactly as Phase 20's future emission site will --
proving reason-to-counter equality 1:1 (including count exactness beyond the
capped-ledger sample cap) before any real prune exists.

Pattern source: tests/test_apex_wildcard_plumbing.py (v1.3 apex plumbing suite).
"""

import os
import tempfile

import scripts.pruning_proof
from scripts.compiler import (
    CompileStats,
    _parse_abp_rule,
    _record_proven_pruning,
    compile_rules,
)
from scripts.pipeline import PipelineStats, _new_pipeline_stats, process_files
from scripts.pruning_proof import (
    DEFAULT_SAMPLE_CAP,
    REASON_TLD_WILDCARD_COVERED,
    REASON_WILDCARD_COVERED,
    REASON_WILDCARD_COVERS_SUB,
    CappedProofLedger,
)
from scripts.stage_diagnostics import COMPILER_STAGE_PRUNE, compiler_stage_summaries_from_stats

# ----------------------------------------------------------------------
# Zero-behavior fixture: fixed line list compiled under default settings.
# EXPECTED_OUTPUT_LINES was captured from today's observed compiler output
# at authoring time (never hand-predicted); the byte-identity leg pins it
# so any future behavioral flip fails loudly here first.
# ----------------------------------------------------------------------

FIXTURE_LINES = [
    "! wcs plumbing fixture",
    "||*.autos^",
    "||sub.autos^",
    "||autos^",
    "||ads.example.com^",
]

EXPECTED_OUTPUT_LINES = [
    "||*.autos^",
    "||autos^",
    "||ads.example.com^",
]


def _compile(lines, **compile_kwargs):
    """Compile lines through the full pipeline, returning output and stats.

    Single module-level copy shared by the compile-plane and
    stage-reconciliation classes (one-copy discipline from the matrix
    sibling's hoisted-helper pattern).
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        output = os.path.join(tmpdir, "output.txt")
        stats = compile_rules(lines, output, **compile_kwargs)
        with open(output, encoding="utf-8") as f:
            rules = [line.strip() for line in f if line.strip()]
        return rules, stats


class TestWcsVocabulary:
    """D-19-01 collision lock: the new reason value is unique in its family."""

    def test_reason_value_is_locked_and_distinct_from_occupied_siblings(self):
        """The locked value differs from both occupied wildcard-family strings."""
        assert REASON_WILDCARD_COVERS_SUB == "wildcard_covers_sub"
        assert REASON_WILDCARD_COVERS_SUB != REASON_WILDCARD_COVERED
        assert REASON_WILDCARD_COVERS_SUB != REASON_TLD_WILDCARD_COVERED

    def test_reason_identifier_is_exported_via_module_all(self):
        """The vocabulary constant joins the module's public export surface."""
        assert "REASON_WILDCARD_COVERS_SUB" in scripts.pruning_proof.__all__


class TestWcsCompilePlane:
    """Fixture-scale compile legs proving both flag states stay inert."""

    def test_default_compile_is_byte_identical_with_zero_counter_and_no_ledger_entries(self):
        """Default settings: output bytes unchanged, counter 0, reason absent."""
        ledger = CappedProofLedger()
        rules, stats = _compile(FIXTURE_LINES, proof_ledger=ledger)

        assert rules == EXPECTED_OUTPUT_LINES
        assert stats.wildcard_covered_sub_pruned == 0
        summary = ledger.summary()
        assert REASON_WILDCARD_COVERS_SUB not in summary["by_reason"]

    def test_flag_on_alone_stays_inert_with_zero_counter_and_no_ledger_entries(self):
        """wildcard_covers_subs_pruning=True alone: identical bytes, counter 0."""
        ledger = CappedProofLedger()
        rules, stats = _compile(
            FIXTURE_LINES,
            proof_ledger=ledger,
            wildcard_covers_subs_pruning=True,
        )

        assert rules == EXPECTED_OUTPUT_LINES
        assert stats.wildcard_covered_sub_pruned == 0
        summary = ledger.summary()
        assert REASON_WILDCARD_COVERS_SUB not in summary["by_reason"]


class TestWcsRecordingPath:
    """Direct-drive legs locking the pairing shape Phase 20 must copy."""

    def _drive_once(self, ledger, candidate_text, covering_text):
        """Pair one manual increment with one recording-path record.

        Mirrors the adjacent increment+record discipline of the shipped
        denyallow emission site so these legs lock the exact shape the
        future wildcard-covers-sub emission site must copy: candidate is
        the subdomain rule, covering is the surviving wildcard.
        """
        candidate = _parse_abp_rule(candidate_text)
        covering = _parse_abp_rule(covering_text)
        assert candidate is not None
        assert covering is not None
        _record_proven_pruning(
            ledger,
            reason=REASON_WILDCARD_COVERS_SUB,
            candidate=candidate,
            covering=covering,
        )

    def test_recording_path_pairs_reason_and_counter_one_to_one(self):
        """Direct drive: ledger tally equals the manually bumped counter."""
        stats = CompileStats()
        ledger = CappedProofLedger()

        self._drive_once(ledger, "||sub.autos^", "||*.autos^")
        stats.wildcard_covered_sub_pruned += 1

        tally = ledger.summary()["by_reason"][REASON_WILDCARD_COVERS_SUB]
        assert tally == 1
        assert stats.wildcard_covered_sub_pruned == tally

    def test_ledger_record_carries_full_wildcard_witness_detail(self):
        """Witness detail rides free from the shared recording path (D-19-02)."""
        ledger = CappedProofLedger()

        self._drive_once(ledger, "||sub.autos^", "||*.autos^")

        matches = [
            record for record in ledger.records if record.reason == REASON_WILDCARD_COVERS_SUB
        ]
        assert len(matches) == 1
        record = matches[0]
        assert record.sample["candidate_rule"] == "||sub.autos^"
        assert record.sample["covering_rule"] == "||*.autos^"
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
            self._drive_once(ledger, f"||sub.{label}^", f"||*.{label}^")
            stats.wildcard_covered_sub_pruned += 1

        tally = ledger.summary()["by_reason"][REASON_WILDCARD_COVERS_SUB]
        assert tally == total_drives
        assert stats.wildcard_covered_sub_pruned == tally
        assert len(ledger.records) <= DEFAULT_SAMPLE_CAP


class TestWcsPipelineSpine:
    """Pipeline wiring legs: typed key, zero-init seed, flatten transfer."""

    def test_pipeline_zero_init_declares_new_key(self):
        """The TypedDict declares the key and fresh stats zero-init it."""
        assert "wildcard_covered_sub_pruned" in PipelineStats.__annotations__
        assert _new_pipeline_stats()["wildcard_covered_sub_pruned"] == 0

    def test_pipeline_flatten_surfaces_new_key_at_fixture_scale(self, tmp_path):
        """End-to-end run surfaces the key through cleaning->compile->flatten."""
        input_dir = tmp_path / "input"
        input_dir.mkdir()
        (input_dir / "list.txt").write_text(
            "# wcs flatten fixture\n||example.com^\n0.0.0.0 ads.example.net\n||example.com^\n",
            encoding="utf-8",
        )
        output_file = tmp_path / "merged.txt"

        stats = process_files(str(input_dir), str(output_file))

        assert stats["wildcard_covered_sub_pruned"] == 0


class TestWcsStageReconciliation:
    """Close the Unregistered-Flags fence OFF-side with evidence (D-19-07).

    scripts/stage_diagnostics.py is READ-ONLY here BY DESIGN -- these legs
    prove auto-pickup zero-safety while the flag is unwired (the wcs bucket
    stays absent under the production default) plus zero-safety on a
    missing-key Mapping source, all through the missing-key-safe ``_stat``
    getter (stage_diagnostics.py:104-110) feeding the prune-stage reasons
    dict (:224-231). One byte of change to that module would defeat the
    point. The fence-inclusion nonzero leg waits for Phase 20's actual
    emission wiring per D-19-07 -- deliberately absent here.
    """

    def test_default_off_prune_stage_omits_wcs_covered_bucket(self):
        """Default OFF: prune-stage reasons stay empty; explicit absence companion."""
        _, stats_off = _compile(["||autos^", "||*.autos^"])

        summaries = compiler_stage_summaries_from_stats(stats_off)

        assert summaries[COMPILER_STAGE_PRUNE]["reasons"] == {}
        assert "wcs_covered" not in summaries[COMPILER_STAGE_PRUNE]["reasons"]

    def test_missing_key_mapping_projection_stays_zero_safe(self):
        """An empty Mapping source projects cleanly with empty prune reasons.

        Direct evidence for the missing-key-safe projection this phase's
        ``wcs_covered`` mapping entry rides on (D-19-07 OFF side).
        """
        summaries = compiler_stage_summaries_from_stats({})

        assert summaries[COMPILER_STAGE_PRUNE]["reasons"] == {}
