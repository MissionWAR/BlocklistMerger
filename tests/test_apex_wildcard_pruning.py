#!/usr/bin/env python3
"""
test_apex_wildcard_pruning.py

AW modifier-asymmetry matrix + stage-diagnostics reconciliation suite
(D-16-03 matrix, OQ#3 stage fence; Phase 16 plan 16-03).

Sibling of tests/test_apex_wildcard_plumbing.py -- the one-module-per-pruning-family
convention (D-08) extended one file further: plumbing/equality/direction-safety proofs
live THERE; this module owns the six-row AW modifier-asymmetry matrix and the
stage-diagnostics reconciliation. Zero production overlap with plan 16-02's module:
no shared fixtures, no shared classes, and neither that file nor any production module
is edited here.

Every fixture drives the REAL compile_rules() twice through the shared helper --
default OFF vs wildcard_apex_pruning=True -- and every verdict derives solely from
modifier_scope_covers() branches reached through _find_covering_parent_record()
(rule_semantics.py:634-684 at authoring time; anchors drift -- Pitfall 8 -- so re-grep
before citing). Test code never reimplements comparison math. Expectations are
exact-per-fixture: no magnitude or distributional claims anywhere (corpus co-occurrence
stays unmeasured until Phase 17).
"""

import os
import tempfile

import pytest

from scripts.compiler import compile_rules
from scripts.pruning_proof import REASON_APEX_COVERS_TLD_WILDCARD, CappedProofLedger

# ----------------------------------------------------------------------
# D-16-03 six-row AW modifier-asymmetry matrix.
#
# Tuple layout: (id, input lines, expected OFF output, expected ON output,
# expected OFF counter, expected ON counter). Output write order everywhere:
# abp_wildcards loop first, pruned_abp second. Verdicts derive solely from
# modifier_scope_covers() branches reached via _find_covering_parent_record();
# the fixtures below assert exact outcomes, never distributions.
# ----------------------------------------------------------------------

ROWS = (
    (
        "row1-important-apex-asymmetry",
        ["||autos^$important", "||*.autos^"],
        ["||*.autos^", "||autos^$important"],
        ["||*.autos^", "||autos^$important"],
        0,
        0,
    ),
    (
        "row2-client-scope-equality-prunes-under-flag",
        ["||autos^$client=10.0.0.1", "||*.autos^$client=10.0.0.1"],
        ["||*.autos^$client=10.0.0.1", "||autos^$client=10.0.0.1"],
        ["||autos^$client=10.0.0.1"],
        0,
        1,
    ),
    (
        "row3-client-narrowed-apex-conservative-keep",
        ["||autos^$client=10.0.0.1", "||*.autos^"],
        ["||*.autos^", "||autos^$client=10.0.0.1"],
        ["||*.autos^", "||autos^$client=10.0.0.1"],
        0,
        0,
    ),
    (
        "row4-denyallow-carrier-wildcard-conservative-keep",
        ["||autos^", "||*.autos^$denyallow=ads.example.com"],
        ["||*.autos^$denyallow=ads.example.com", "||autos^"],
        ["||*.autos^$denyallow=ads.example.com", "||autos^"],
        0,
        0,
    ),
    (
        "row5-badfilter-apex-never-a-witness",
        ["||autos^$badfilter", "||*.autos^"],
        ["||*.autos^"],
        ["||*.autos^"],
        0,
        0,
    ),
    (
        "row6-dnstype-value-subset-conservative-keep",
        ["||autos^$dnstype=A", "||*.autos^$dnstype=A|AAAA"],
        ["||*.autos^$dnstype=A|AAAA", "||autos^$dnstype=A"],
        ["||*.autos^$dnstype=A|AAAA", "||autos^$dnstype=A"],
        0,
        0,
    ),
)


class TestApexWildcardMatrix:
    """D-16-03 six-row AW matrix asserted in BOTH flag states, plus deep dives."""

    def _compile(self, lines, **compile_kwargs):
        """Compile lines through the full pipeline, returning output and stats."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "output.txt")
            stats = compile_rules(lines, output, **compile_kwargs)
            with open(output, encoding="utf-8") as f:
                rules = [line.strip() for line in f if line.strip()]
            return rules, stats

    @pytest.mark.parametrize(
        (
            "lines",
            "expected_off_output",
            "expected_on_output",
            "expected_off_counter",
            "expected_on_counter",
        ),
        [pytest.param(*row[1:], id=row[0]) for row in ROWS],
    )
    def test_aw_matrix_six_rows_verdicts_both_flag_states(
        self,
        lines,
        expected_off_output,
        expected_on_output,
        expected_off_counter,
        expected_on_counter,
    ):
        """Six-row D-16-03 verdicts in both flag states through the real compiler.

        Per-row oracle map (branches of modifier_scope_covers(),
        rule_semantics.py:634-684, reached via _find_covering_parent_record()):
        - row1-important-apex-asymmetry: an $important apex NEVER licenses removal;
          the bare flag parses clean, so rejection lands on important presence-parity
          (:663-671) -- a valued/odd form would additionally fail the uncertainty
          gate (:647-649). Either way the wildcard is conservatively kept.
        - row2-client-scope-equality-prunes-under-flag: equal narrow-scope signatures
          satisfy equal-or-broader coverage, so removal IS proven.
        - row3-client-narrowed-apex-conservative-keep: narrowed apex cannot cover an
          unrestricted child -- parent present / child absent rejects (:679-680).
        - row4-denyallow-carrier-wildcard-conservative-keep: NO_COVERAGE_MODIFIERS
          wholesale-rejects denyallow carriers (v1.2 semantics, :657-658).
        - row5-badfilter-apex-never-a-witness: the $badfilter apex is discarded
          BEFORE storage (compiler Phase 1 nonblocking skip), so the index lookup
          misses; even a storage leak could not license removal because the oracle
          wholesale-rejects badfilter witnesses (:657-658) -- Pitfall 6 layer b.
        - row6-dnstype-value-subset-conservative-keep: a narrower dnstype value-set
          signature can never cover a broader child (value-signature mismatch,
          :681-682).

        Every leg runs on a fresh CappedProofLedger and asserts the per-leg ledger
        discipline alongside keep/drop and counters. One claim per assert.
        """
        ledger_off = CappedProofLedger()
        ledger_on = CappedProofLedger()

        rules_off, stats_off = self._compile(lines, proof_ledger=ledger_off)

        assert rules_off == expected_off_output
        assert stats_off.apex_covered_wildcard_pruned == expected_off_counter
        summary_off = ledger_off.summary()
        assert REASON_APEX_COVERS_TLD_WILDCARD not in summary_off["by_reason"]

        rules_on, stats_on = self._compile(
            lines,
            proof_ledger=ledger_on,
            wildcard_apex_pruning=True,
        )

        assert rules_on == expected_on_output
        assert stats_on.apex_covered_wildcard_pruned == expected_on_counter
        summary_on = ledger_on.summary()
        if expected_on_counter == 0:
            assert REASON_APEX_COVERS_TLD_WILDCARD not in summary_on["by_reason"]
        else:
            assert summary_on["by_reason"][REASON_APEX_COVERS_TLD_WILDCARD] == (expected_on_counter)

    def test_aw_matrix_client_equality_removal_carries_exact_witness_detail(self):
        """Row-2 deep dive: the one flagged removal carries exact D-04 witness detail."""
        ledger_on = CappedProofLedger()

        _, stats_on = self._compile(
            ["||autos^$client=10.0.0.1", "||*.autos^$client=10.0.0.1"],
            proof_ledger=ledger_on,
            wildcard_apex_pruning=True,
        )

        matches = [
            record
            for record in ledger_on.records
            if record.reason == REASON_APEX_COVERS_TLD_WILDCARD
        ]
        assert len(matches) == 1
        record = matches[0]
        assert record.sample["candidate_rule"] == "||*.autos^$client=10.0.0.1"
        assert record.sample["covering_rule"] == "||autos^$client=10.0.0.1"
        assert record.sample["modifier_scope_proven"] is True
        assert record.fingerprint
        tally = ledger_on.summary()["by_reason"][REASON_APEX_COVERS_TLD_WILDCARD]
        assert tally == 1
        assert stats_on.apex_covered_wildcard_pruned == 1

    def test_aw_row5_badfilter_discard_evidence_pinned_in_both_legs(self):
        """Row-5 evidence pin: the badfilter apex is discarded upstream of flag logic.

        rule_effect_disable counts the classification in both legs, and the
        disabled row never appears in either output list. The output-absence
        asserts are the anchor the Task-3 storage-leak teeth proof flips.
        """
        lines = ["||autos^$badfilter", "||*.autos^"]

        rules_off, stats_off = self._compile(lines)

        assert stats_off.rule_effect_disable == 1
        assert "||autos^$badfilter" not in rules_off

        rules_on, stats_on = self._compile(lines, wildcard_apex_pruning=True)

        assert stats_on.rule_effect_disable == 1
        assert "||autos^$badfilter" not in rules_on
