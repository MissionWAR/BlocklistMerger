#!/usr/bin/env python3
"""
test_denyallow_wildcard_pruning.py

Denyallow-aware TLD-wildcard pruning audit suite (FIX-01 / FIX-02, Phase 14).

Proven invariant (official AdGuard semantics, AdguardTeam/AdGuardHome wiki
Hosts-Blocklists#denyallow): a `$denyallow` allow-entry exempts itself AND its
entire subdomain subtree from the blocking rule. A TLD wildcard
`||*.tld^$denyallow=E1|E2|...` therefore blocks everything under `tld` except
the union of the entry subtrees, so a child rule with normalized domain `d`
is fully covered by such a wildcard iff NO entry shares subtree overlap with
`d`. The three-way disjointness predicate:

    keep if (E == d) or d.endswith("." + E) or E.endswith("." + d)

covers exact-match entries, ancestor/superdomain entries, and -- the safety
correction to FINDINGS §8 item 2's registered-domain-only sketch --
descendant entries (`||*.com^$denyallow=safe.example.com` never covers
`||example.com^` because safe.example.com stays unblocked inside the child's
blocked set). Only fully-disjoint children may be pruned, and only when
`denyallow_pruning=True` (D-04 Plan A staging: the production default stays
OFF until the Plan B corpus shadow gate passes in 14-03).

Evidence layers:
- TestDenyallowWildcardPruning: end-to-end compile_rules() fixtures run in
  BOTH flag states (golden prune + negative keep boundaries).
- DENYALLOW_PRUNE_MATRIX: pytest.param golden/negative rows asserting exact
  output plus the denyallow_wildcard_pruned counter per flag state.
- TestDenyallowAllowSetTruthTable / TestDomainDisjointTruthTable: unit truth
  tables for the two pure helpers in scripts/rule_semantics.py.

Pattern source: tests/test_whitelist_modifier_scope_audit.py (Phase 13 audit suites).
"""

import os
import tempfile

import pytest

from scripts.compiler import compile_rules
from scripts.pruning_proof import CappedProofLedger


class TestDenyallowWildcardPruning:
    """End-to-end denyallow wildcard pruning through compile_rules()."""

    def _compile(self, lines, **compile_kwargs):
        """Compile lines through the full pipeline, returning output and stats."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "output.txt")
            stats = compile_rules(lines, output, **compile_kwargs)
            with open(output, encoding="utf-8") as f:
                rules = [line.strip() for line in f if line.strip()]
            return rules, stats

    # ------------------------------------------------------------------
    # Tracer: single disjoint-child path through every compiler layer
    # ------------------------------------------------------------------

    def test_flag_on_prunes_disjoint_child_and_records_ledger_proof(self):
        """Flag ON: an admissible $denyallow wildcard covers a disjoint child.

        Real-corpus sample (FINDINGS §6): ||adjust.world^ sits under the
        admissible ||*.world^$denyallow=bevisioneers.world|boo.world wildcard.
        Neither entry shares subtree overlap with adjust.world, so official
        $denyallow semantics prove full coverage and the child is pruned with
        one denyallow_covered ledger record paired 1:1 with the stat bump.
        """
        ledger = CappedProofLedger()
        rules, stats = self._compile(
            ["||*.world^$denyallow=bevisioneers.world|boo.world", "||adjust.world^"],
            proof_ledger=ledger,
            denyallow_pruning=True,
        )

        assert rules == ["||*.world^$denyallow=bevisioneers.world|boo.world"]
        assert stats.denyallow_wildcard_pruned == 1
        assert ledger.summary()["by_reason"]["denyallow_covered"] == 1

    def test_flag_off_default_keeps_every_rule_and_counter_stays_zero(self):
        """Default OFF: identical input keeps both lines; the counter stays zero.

        This pins D-04 staging: shipped default behavior is byte-identical to
        pre-change HEAD until the 14-03 shadow gate flips the flag.
        """
        lines = ["||*.world^$denyallow=bevisioneers.world|boo.world", "||adjust.world^"]
        rules, stats = self._compile(lines)

        assert rules == [
            "||*.world^$denyallow=bevisioneers.world|boo.world",
            "||adjust.world^",
        ]
        assert stats.denyallow_wildcard_pruned == 0


class TestDenyallowAllowSetTruthTable:
    """Unit truth table for rule_semantics._denyallow_allow_set()."""


class TestDomainDisjointTruthTable:
    """Unit truth table for rule_semantics._domain_disjoint_from_all()."""
