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
    _build_apex_survivor_index,
    _parse_abp_rule,
    _record_proven_pruning,
    _rule_storage_key,
    compile_rules,
    get_tld,
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
            record for record in ledger.records if record.reason == REASON_APEX_COVERS_TLD_WILDCARD
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
            "# apex flatten fixture\n||example.com^\n0.0.0.0 ads.example.net\n||example.com^\n",
            encoding="utf-8",
        )
        output_file = tmp_path / "merged.txt"

        stats = process_files(str(input_dir), str(output_file))

        assert stats["apex_covered_wildcard_pruned"] == 0


class TestApexWildcardPruning:
    """Both-flag-state legs for flag-gated apex-covered wildcard pruning."""

    def _compile(self, lines, **compile_kwargs):
        """Compile lines through the full pipeline, returning output and stats."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "output.txt")
            stats = compile_rules(lines, output, **compile_kwargs)
            with open(output, encoding="utf-8") as f:
                rules = [line.strip() for line in f if line.strip()]
            return rules, stats

    def test_tl03_golden_both_flag_states(self):
        """TL-03 golden: identical input compiled under each flag state."""
        ledger_off = CappedProofLedger()
        ledger_on = CappedProofLedger()
        lines = ["||autos^", "||*.autos^"]

        rules_off, stats_off = self._compile(lines, proof_ledger=ledger_off)

        assert rules_off == ["||*.autos^", "||autos^"]
        assert stats_off.apex_covered_wildcard_pruned == 0
        summary_off = ledger_off.summary()
        assert REASON_APEX_COVERS_TLD_WILDCARD not in summary_off["by_reason"]

        rules_on, stats_on = self._compile(
            lines,
            proof_ledger=ledger_on,
            wildcard_apex_pruning=True,
        )

        assert rules_on == ["||autos^"]
        assert stats_on.apex_covered_wildcard_pruned == 1
        matches = [
            record
            for record in ledger_on.records
            if record.reason == REASON_APEX_COVERS_TLD_WILDCARD
        ]
        assert len(matches) == 1
        sample = matches[0].sample
        assert sample["candidate_rule"] == "||*.autos^"
        assert sample["covering_rule"] == "||autos^"
        assert isinstance(sample["modifier_scope_proven"], bool)
        assert sample["modifier_scope_proven"] is True
        assert matches[0].fingerprint

    # ------------------------------------------------------------------
    # Builder-contract unit pins (Phase 16 plan 16-01, Task 2).
    #
    # These legs call _build_apex_survivor_index() DIRECTLY. Storages are
    # built by parsing rule text through _parse_abp_rule and keying through
    # the production derivations (_rule_storage_key for survivor buckets,
    # the parse-time get_tld bucket key for wildcard buckets) so no pin
    # ever exercises hand-invented keys.
    # ------------------------------------------------------------------

    @staticmethod
    def _survivor_storage(rule_texts):
        """Build pruned_abp-shaped storage via the real storage-key function."""
        storage = {}
        for text in rule_texts:
            record = _parse_abp_rule(text)
            assert record is not None
            storage.setdefault(_rule_storage_key(record), []).append(record)
        return storage

    @staticmethod
    def _wildcard_storage(rule_texts):
        """Build abp_wildcards-shaped storage via the real parse-time bucketing."""
        storage = {}
        for text in rule_texts:
            record = _parse_abp_rule(text)
            assert record is not None
            tld = get_tld(record.domain)
            assert tld is not None
            assert record.domain == tld  # fixture discipline: TLD-form wildcards only
            storage.setdefault(tld, []).append(record)
        return storage

    def test_index_projects_same_key_survivors_only(self):
        """Only wildcard keys holding same-key survivor buckets appear, by identity."""
        survivors = self._survivor_storage(["||autos^", "||other^"])
        wildcards = self._wildcard_storage(["||*.autos^"])
        lone_survivor = survivors["autos"][0]

        index = _build_apex_survivor_index(survivors, wildcards)

        assert list(index) == ["autos"]
        assert index["autos"] is survivors["autos"]
        assert index["autos"][0] is lone_survivor
        assert "other" not in index

    def test_index_omits_keys_without_survivors(self):
        """A wildcard key whose apex did not survive gets no index entry at all."""
        unrelated = self._survivor_storage(["||other^"])
        wildcards = self._wildcard_storage(["||*.autos^"])

        index = _build_apex_survivor_index(unrelated, wildcards)

        assert "autos" not in index
        assert index == {}

    def test_index_preserves_append_order_of_survivor_buckets(self):
        """Projected buckets keep source insertion order element-for-element."""
        survivors = self._survivor_storage(["||autos^", "||autos^$client=10.0.0.1"])
        wildcards = self._wildcard_storage(["||*.autos^"])

        index = _build_apex_survivor_index(survivors, wildcards)

        assert len(index["autos"]) == 2
        assert tuple(m.name for m in index["autos"][0].modifiers) == ()
        assert tuple(m.name for m in index["autos"][1].modifiers) == ("client",)
        assert index["autos"] == survivors["autos"]

    def test_non_wildcard_storage_key_equals_record_domain(self):
        """Non-wildcard storage keys equal record.domain (builder premise A4)."""
        for text in ["||autos^", "||ads.example.com^", "||com^"]:
            record = _parse_abp_rule(text)
            assert record is not None
            assert record.is_wildcard is False
            assert _rule_storage_key(record) == record.domain

    # ------------------------------------------------------------------
    # Direction-safety negatives (Phase 16 plan 16-02, Task 1).
    #
    # Every leg drives the REAL compile_rules() twice -- default OFF vs
    # wildcard_apex_pruning=True -- through the class _compile helper.
    # Expectations are exact-per-fixture; one claim per assert. These legs
    # prove what must NEVER happen: inverse pruning, witnessing from a
    # non-survivor, cross-key licensing, whole-bucket collapse.
    # ------------------------------------------------------------------

    def test_inverse_negative_lone_wildcard_kept_in_both_states(self):
        """F2a: a lone TLD wildcard has no witness and survives both flag states."""
        ledger_off = CappedProofLedger()
        ledger_on = CappedProofLedger()
        lines = ["||*.autos^"]

        rules_off, stats_off = self._compile(lines, proof_ledger=ledger_off)

        assert rules_off == ["||*.autos^"]
        assert stats_off.apex_covered_wildcard_pruned == 0
        summary_off = ledger_off.summary()
        assert REASON_APEX_COVERS_TLD_WILDCARD not in summary_off["by_reason"]

        rules_on, stats_on = self._compile(
            lines,
            proof_ledger=ledger_on,
            wildcard_apex_pruning=True,
        )

        assert rules_on == ["||*.autos^"]
        assert stats_on.apex_covered_wildcard_pruned == 0
        summary_on = ledger_on.summary()
        assert REASON_APEX_COVERS_TLD_WILDCARD not in summary_on["by_reason"]

    def test_pure_tld_same_key_pair_prunes_under_flag_on(self):
        """F2b: a pure-TLD apex is an eligible same-key witness (TL-09 family)."""
        ledger_off = CappedProofLedger()
        ledger_on = CappedProofLedger()
        lines = ["||com^", "||*.com^"]

        rules_off, stats_off = self._compile(lines, proof_ledger=ledger_off)

        assert rules_off == ["||*.com^", "||com^"]
        assert stats_off.apex_covered_wildcard_pruned == 0

        rules_on, stats_on = self._compile(
            lines,
            proof_ledger=ledger_on,
            wildcard_apex_pruning=True,
        )

        assert rules_on == ["||com^"]
        assert stats_on.apex_covered_wildcard_pruned == 1
        matches = [
            record
            for record in ledger_on.records
            if record.reason == REASON_APEX_COVERS_TLD_WILDCARD
        ]
        assert len(matches) == 1
        sample = matches[0].sample
        assert sample["candidate_rule"] == "||*.com^"
        assert sample["covering_rule"] == "||com^"
        assert sample["modifier_scope_proven"] is True

    def test_whitelisted_apex_isolation_survivor_only_witnessing(self):
        """F3: a whitelisted-away apex can never license removing its wildcard."""
        ledger_off = CappedProofLedger()
        ledger_on = CappedProofLedger()
        lines = [
            "@@||autos^$client=10.0.0.1",
            "||autos^$client=10.0.0.1",
            "||*.autos^",
        ]

        rules_off, stats_off = self._compile(lines, proof_ledger=ledger_off)

        assert rules_off == ["||*.autos^"]
        assert stats_off.whitelist_conflict_pruned == 1
        assert stats_off.apex_covered_wildcard_pruned == 0
        summary_off = ledger_off.summary()
        assert REASON_APEX_COVERS_TLD_WILDCARD not in summary_off["by_reason"]

        rules_on, stats_on = self._compile(
            lines,
            proof_ledger=ledger_on,
            wildcard_apex_pruning=True,
        )

        assert rules_on == ["||*.autos^"]
        assert stats_on.whitelist_conflict_pruned == 1
        assert stats_on.apex_covered_wildcard_pruned == 0
        summary_on = ledger_on.summary()
        assert REASON_APEX_COVERS_TLD_WILDCARD not in summary_on["by_reason"]

    def test_partial_bucket_prunes_only_proven_variant(self):
        """F4: multi-variant buckets lose exactly the individually proven variant."""
        ledger_off = CappedProofLedger()
        ledger_on = CappedProofLedger()
        lines = ["||autos^", "||*.autos^", "||*.autos^$important"]

        rules_off, stats_off = self._compile(lines, proof_ledger=ledger_off)

        assert rules_off == ["||*.autos^", "||*.autos^$important", "||autos^"]
        assert stats_off.apex_covered_wildcard_pruned == 0

        rules_on, stats_on = self._compile(
            lines,
            proof_ledger=ledger_on,
            wildcard_apex_pruning=True,
        )

        assert rules_on == ["||*.autos^$important", "||autos^"]
        assert stats_on.apex_covered_wildcard_pruned == 1
        matches = [
            record
            for record in ledger_on.records
            if record.reason == REASON_APEX_COVERS_TLD_WILDCARD
        ]
        assert len(matches) == 1
        assert matches[0].sample["candidate_rule"] == "||*.autos^"
        assert "||*.autos^$important" in rules_on

    def test_cross_key_boundary_never_prunes_across_keys(self):
        """F6: a cross-key apex never licenses removal under strict same-key witnessing."""
        ledger_off = CappedProofLedger()
        ledger_on = CappedProofLedger()
        # The wildcard carries a narrowing $client scope so the cross-key apex
        # ||example.co.uk^ survives Phase 3 (the pre-existing TLD-wildcard
        # coverage branch cannot prove over it either) and is present in
        # pruned_abp under key "example.co.uk" -- which the strict same-key
        # index ("co.uk") must never gather as a witness.
        lines = ["||*.co.uk^$client=10.0.0.1", "||example.co.uk^"]

        rules_off, stats_off = self._compile(lines, proof_ledger=ledger_off)

        assert rules_off == ["||*.co.uk^$client=10.0.0.1", "||example.co.uk^"]
        assert stats_off.apex_covered_wildcard_pruned == 0
        summary_off = ledger_off.summary()
        assert REASON_APEX_COVERS_TLD_WILDCARD not in summary_off["by_reason"]

        rules_on, stats_on = self._compile(
            lines,
            proof_ledger=ledger_on,
            wildcard_apex_pruning=True,
        )

        assert rules_on == ["||*.co.uk^$client=10.0.0.1", "||example.co.uk^"]
        assert stats_on.apex_covered_wildcard_pruned == 0
        summary_on = ledger_on.summary()
        assert REASON_APEX_COVERS_TLD_WILDCARD not in summary_on["by_reason"]


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
