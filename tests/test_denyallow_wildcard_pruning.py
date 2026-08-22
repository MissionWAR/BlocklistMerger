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
blocked set). Only fully-disjoint children may be pruned. Since v1.2 the
production default is denyallow_pruning=True (D-04: flipped after the 14-03
full-corpus shadow gate passed), so every OFF-semantics leg in this suite
passes denyallow_pruning=False EXPLICITLY to keep testing both flag states.

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
from scripts.pruning_proof import REASON_DENYALLOW_COVERED, CappedProofLedger
from scripts.rule_semantics import (
    _denyallow_allow_set,
    _domain_disjoint_from_all,
    parse_modifier_text,
)

# ----------------------------------------------------------------------
# DA-01..DA-10 denyallow boundary matrix.
#
# Tuple shape:
#   (wildcard_rules, child_rules, expected_output_on, expected_count_on)
# expected_output_on is the exact surviving output under
# denyallow_pruning=True; expected_count_on is CompileStats.
# denyallow_wildcard_pruned for that run. The flag-OFF matrix method
# asserts the same rows keep every child rule verbatim with counter zero.
#
# Corpus-real samples from FINDINGS §6 anchor DA-01/DA-02/DA-05/DA-06;
# DA-04 pins the descendant-entry safety correction to FINDINGS §8 item 2's
# registered-domain-only sketch.
# ----------------------------------------------------------------------

DENYALLOW_PRUNE_MATRIX = [
    # Golden prune: neither entry shares subtree overlap with adjust.world.
    pytest.param(
        ("||*.world^$denyallow=bevisioneers.world|boo.world",),
        ("||adjust.world^",),
        ["||*.world^$denyallow=bevisioneers.world|boo.world"],
        1,
        id="DA-01-disjoint-child-pruned",
    ),
    # Exact match between child domain and an allow-entry forces KEEP.
    pytest.param(
        ("||*.asia^$denyallow=amzn.asia|autoads.asia",),
        ("||autoads.asia^",),
        ["||*.asia^$denyallow=amzn.asia|autoads.asia", "||autoads.asia^"],
        0,
        id="DA-02-exact-entry-child-kept",
    ),
    # Child strictly below an allow-entry subtree forces KEEP.
    pytest.param(
        ("||*.com^$denyallow=example.com",),
        ("||shop.example.com^",),
        ["||*.com^$denyallow=example.com", "||shop.example.com^"],
        0,
        id="DA-03-child-under-entry-subtree-kept",
    ),
    # FINDINGS §8 safety correction: an allow-entry strictly BELOW the child
    # domain also forces KEEP — a registered-domain-only check would wrongly
    # prune ||example.com^ here and lose coverage of safe.example.com.
    pytest.param(
        ("||*.com^$denyallow=safe.example.com",),
        ("||example.com^",),
        ["||*.com^$denyallow=safe.example.com", "||example.com^"],
        0,
        id="DA-04-descendant-entry-child-kept",
    ),
    # Phase 13 D-02 boundary: $important children are never denyallow-pruned;
    # modifier_scope_covers((), child.modifiers) rejects the priority pair.
    pytest.param(
        ("||*.world^$denyallow=bevisioneers.world|boo.world",),
        ("||promo.world^$important",),
        ["||*.world^$denyallow=bevisioneers.world|boo.world", "||promo.world^$important"],
        0,
        id="DA-05-important-child-kept",
    ),
    # A child carrying its own NO_COVERAGE modifier ($denyallow) is ineligible
    # via the same eligibility gate (cf. test_cross_format_audit precedent).
    pytest.param(
        ("||*.world^$denyallow=bevisioneers.world|boo.world",),
        ("||other.world^$denyallow=safe.world",),
        [
            "||*.world^$denyallow=bevisioneers.world|boo.world",
            "||other.world^$denyallow=safe.world",
        ],
        0,
        id="DA-06-nocoverage-carrier-child-kept",
    ),
    # Research Pitfall 3: entry == wildcard TLD exempts everything the
    # wildcard could block, so the variant is inadmissible -> children kept.
    pytest.param(
        ("||*.com^$denyallow=com",),
        ("||example.com^",),
        ["||*.com^$denyallow=com", "||example.com^"],
        0,
        id="DA-07-degenerate-entry-equals-tld-kept",
    ),
    # Research Pitfall / OQ1 resolution: name-level negation makes the
    # wildcard inadmissible in v1 -> children kept in both states.
    pytest.param(
        ("||*.world^$~denyallow=x.world",),
        ("||adjust.world^",),
        ["||*.world^$~denyallow=x.world", "||adjust.world^"],
        0,
        id="DA-08a-name-negated-wildcard-kept",
    ),
    # Mixed modifiers alongside $denyallow reduce admissibility -> children
    # kept; only wildcards reducing to exactly one clean $denyallow prove.
    pytest.param(
        ("||*.world^$denyallow=a.world,client=1.2.3.4",),
        ("||adjust.world^",),
        ["||*.world^$denyallow=a.world,client=1.2.3.4", "||adjust.world^"],
        0,
        id="DA-08b-mixed-modifier-wildcard-kept",
    ),
    # Research Pitfall 5: multi-variant TLD keys scan variants in storage
    # (append) order — the FIRST admissible disjoint variant wins, so input
    # order fixes which wildcard proves coverage deterministically.
    pytest.param(
        ("||*.world^$~denyallow=x.world", "||*.world^$denyallow=zeta.world"),
        ("||adjust.world^",),
        ["||*.world^$~denyallow=x.world", "||*.world^$denyallow=zeta.world"],
        1,
        id="DA-09-multi-variant-first-admissible-wins",
    ),
    # Research Pitfall 1: entries normalize through lower().strip().rstrip(".")
    # before comparison, so BOO.World equals child boo.world after lowering.
    pytest.param(
        ("||*.world^$denyallow=BOO.World",),
        ("||boo.world^",),
        ["||*.world^$denyallow=BOO.World", "||boo.world^"],
        0,
        id="DA-10-mixed-case-exact-after-normalization-kept",
    ),
    # Companion to DA-10: case normalization never flips verdicts — a mixed-
    # case entry genuinely disjoint from the child still prunes with flag ON.
    pytest.param(
        ("||*.world^$denyallow=Bee.World",),
        ("||boo.world^",),
        ["||*.world^$denyallow=Bee.World"],
        1,
        id="DA-10-mixed-case-disjoint-still-prunes",
    ),
]


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

    def test_flag_off_explicit_keeps_every_rule_and_counter_stays_zero(self):
        """Explicit OFF: identical input keeps both lines; the counter stays zero.

        Since v1.2 the production default is denyallow_pruning=True (D-04
        flip after the 14-03 corpus gate), so this leg passes False
        explicitly to keep pinning the pre-v1.2 keep-everything semantics:
        byte-identical survival of every rule with a zeroed counter.
        """
        lines = ["||*.world^$denyallow=bevisioneers.world|boo.world", "||adjust.world^"]
        rules, stats = self._compile(lines, denyallow_pruning=False)

        assert rules == [
            "||*.world^$denyallow=bevisioneers.world|boo.world",
            "||adjust.world^",
        ]
        assert stats.denyallow_wildcard_pruned == 0

    # ------------------------------------------------------------------
    # DA-01..DA-10 golden/negative boundary matrix.
    #
    # Every row is compiled TWICE by the two matrix methods below: flag ON
    # asserts exact output plus the denyallow_wildcard_pruned counter (and
    # the 1:1 ledger pairing at fixture scale), explicit denyallow_pruning=
    # False asserts every child block rule survives verbatim with counter
    # zero — the feature-flag-tested-in-BOTH-states requirement from the
    # phase brief.
    #
    # Tuple shape:
    #   (wildcard_rules, child_rules, expected_output_on, expected_count_on)
    # ------------------------------------------------------------------

    @pytest.mark.parametrize(
        ("wildcard_rules", "child_rules", "expected_output_on", "expected_count_on"),
        DENYALLOW_PRUNE_MATRIX,
    )
    def test_denyallow_matrix_flag_on(
        self,
        wildcard_rules,
        child_rules,
        expected_output_on,
        expected_count_on,
    ):
        """Compile each DA row with denyallow_pruning=True; assert exact output.

        The CappedProofLedger attached to every row pins the FIX-02 stats↔ledger
        equality at fixture scale: by_reason[REASON_DENYALLOW_COVERED] must equal
        stats.denyallow_wildcard_pruned for prune rows AND stay paired at zero
        for keep rows (DA-01's dedicated pairing requirement generalizes here).
        """
        ledger = CappedProofLedger()
        rules, stats = self._compile(
            [*wildcard_rules, *child_rules],
            proof_ledger=ledger,
            denyallow_pruning=True,
        )

        assert rules == expected_output_on
        assert stats.denyallow_wildcard_pruned == expected_count_on
        summary = ledger.summary()
        assert summary["by_reason"].get(REASON_DENYALLOW_COVERED, 0) == expected_count_on

    @pytest.mark.parametrize(
        ("wildcard_rules", "child_rules", "expected_output_on", "expected_count_on"),
        DENYALLOW_PRUNE_MATRIX,
    )
    def test_denyallow_matrix_flag_off_keeps_children_verbatim(
        self,
        wildcard_rules,
        child_rules,
        expected_output_on,
        expected_count_on,
    ):
        """Compile each DA row with denyallow_pruning=False; children survive.

        This is the OFF-state half of the both-states requirement: since
        v1.2 the production default is True, so OFF semantics must be
        requested explicitly — every child block rule survives verbatim and
        the counter stays zero regardless of what the flag would do.
        """
        rules, stats = self._compile(
            [*wildcard_rules, *child_rules],
            denyallow_pruning=False,
        )

        assert stats.denyallow_wildcard_pruned == 0
        for child in child_rules:
            assert child in rules


# ----------------------------------------------------------------------
# Unit truth tables for the two pure helpers (direct calls, no fixtures).
#
# Inputs are built via parse_modifier_text() like the audit suite's
# MODIFIER_SCOPE_TRUTH_TABLE so the tables exercise real parser output
# instead of hand-assembled stand-ins. Importing the underscore-private
# helpers directly from scripts.rule_semantics is an intentional
# cross-module private import for unit pinning; no Ruff-selected rule
# flags it.
# ----------------------------------------------------------------------

DENYALLOW_ALLOW_SET_TRUTH_TABLE = [
    # Clean single denyallow: entries lowercased and trailing dots stripped.
    pytest.param(
        "denyallow=A.Example.com",
        "net",
        frozenset({"a.example.com"}),
        id="allowset-clean-single-entry-lowercased",
    ),
    pytest.param(
        "denyallow=amzn.asia|autoads.asia",
        "asia",
        frozenset({"amzn.asia", "autoads.asia"}),
        id="allowset-pipe-separated-entries-collected",
    ),
    # Exactly-one-modifier admissibility: anything else alongside reject.
    pytest.param(
        "denyallow=a.com,client=1.2.3.4",
        "com",
        None,
        id="allowset-multiple-modifiers-rejected",
    ),
    # Name-level negation can never prove coverage.
    pytest.param(
        "~denyallow=x.com",
        "com",
        None,
        id="allowset-name-negated-rejected",
    ),
    # Value-level negation (~entry) is undocumented syntax -> never prove.
    pytest.param(
        "denyallow=~x.com",
        "com",
        None,
        id="allowset-value-negated-rejected",
    ),
    # Underscore label fails PLAIN_DOMAIN_PATTERN after normalization.
    pytest.param(
        "denyallow=bad_domain.com",
        "com",
        None,
        id="allowset-plain-domain-pattern-rejected",
    ),
    # One invalid entry rejects the whole set — coverage needs ALL entries valid.
    pytest.param(
        "denyallow=a.com|bad_domain.com",
        "com",
        None,
        id="allowset-any-invalid-entry-rejects-whole-set",
    ),
    # Degenerate self-referential exemption of research Pitfall 3.
    pytest.param(
        "denyallow=com",
        "com",
        None,
        id="allowset-degenerate-entry-equals-tld-rejected",
    ),
]

DOMAIN_DISJOINT_TRUTH_TABLE = [
    # Equal domain/entry share subtrees by definition -> KEEP direction.
    pytest.param("boo.world", {"boo.world"}, False, id="disjoint-equal-entry-overlaps"),
    # Domain strictly below an entry subtree -> KEEP direction.
    pytest.param(
        "shop.example.com",
        {"example.com"},
        False,
        id="disjoint-domain-under-entry-subtree-overlaps",
    ),
    # Entry strictly below the domain (descendant correction) -> KEEP.
    pytest.param(
        "example.com",
        {"safe.example.com"},
        False,
        id="disjoint-descendant-entry-overlaps",
    ),
    # Fully disjoint subtrees from every entry -> prune may proceed.
    pytest.param(
        "adjust.world",
        {"bevisioneers.world", "boo.world"},
        True,
        id="disjoint-fully-disjoint-from-all-entries",
    ),
]


class TestDenyallowAllowSetTruthTable:
    """Direct rule_semantics._denyallow_allow_set() truth table."""

    @pytest.mark.parametrize(
        ("modifier_text", "tld", "expected"),
        DENYALLOW_ALLOW_SET_TRUTH_TABLE,
    )
    def test_denyallow_allow_set_truth_table(self, modifier_text, tld, expected):
        """Prove each admissibility boundary at the unit semantic layer."""
        modifiers = parse_modifier_text(modifier_text)

        assert _denyallow_allow_set(modifiers, tld) == expected


class TestDomainDisjointTruthTable:
    """Direct rule_semantics._domain_disjoint_from_all() truth table."""

    @pytest.mark.parametrize(
        ("domain", "entries", "expected"),
        DOMAIN_DISJOINT_TRUTH_TABLE,
    )
    def test_domain_disjoint_truth_table(self, domain, entries, expected):
        """Prove each three-way disjointness boundary at the unit layer."""
        assert _domain_disjoint_from_all(domain, frozenset(entries)) is expected
