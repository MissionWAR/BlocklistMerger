#!/usr/bin/env python3
"""
test_whitelist_modifier_scope_audit.py

Whitelist conflict & modifier-scope audit suite (AUD-04).

These tests prove that @@exception rules remove blocking rules only when BOTH
the domain hierarchy AND the modifier scope are proven equivalent or broader:

- Scoped exceptions ($client, $ctag, $dnstype) must NOT prune blocked entries
  unless the exception's modifier scope is proven equivalent or broader (D-01).
- $important asymmetry: a block carrying $important must NOT be removed by an
  exception that lacks a clean $important flag (D-02).
- NO_COVERAGE modifiers ($dnsrewrite, $denyallow, $badfilter), unknown
  modifier names, uncertain records, and duplicate names can never prove
  coverage for any pair.

Evidence layers:
- TestWhitelistModifierScopeAudit: end-to-end compile_rules() fixtures for the
  WL boundary matrix from Phase 13 research.
- TestModifierScopeTruthTable: direct modifier_scope_covers() truth-table
  calls isolating the unit semantic from compiler integration.
- TestCorpusWhitelistAudit (AUD-05 / D-03): slow-marked full-corpus run of
  lists/_raw/ through compile_rules() with a CappedProofLedger, producing
  structured whitelist-conflict metrics for FINDINGS.md analysis.

Pattern source: tests/test_cross_format_audit.py (Phase 12 audit suites).
"""

import os
import tempfile
import time
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from typing import Final, NamedTuple

import pytest

from scripts.compiler import CompileStats, clear_caches, compile_rules
from scripts.pruning_proof import (
    DEFAULT_SAMPLE_CAP,
    OUTCOME_KEPT,
    REASON_APEX_COVERS_TLD_WILDCARD,
    REASON_DENYALLOW_COVERED,
    REASON_EXCEPTION_COVERED,
    REASON_KEPT_BECAUSE_UNCERTAIN,
    CappedProofLedger,
    RuleFacet,
)
from scripts.rule_semantics import modifier_scope_covers, parse_modifier_text

# ----------------------------------------------------------------------
# WL boundary matrix (Phase 13 RESEARCH.md, Layer 1 scenarios).
#
# Tuple shape: (block_rules, exception_rules, expected_output, expected_pruned).
# expected_output asserts the exact surviving output lines; expected_pruned is
# CompileStats.whitelist_conflict_pruned. Exceptions themselves are never
# emitted, so every "kept" case surfaces as the surviving block lines only.
# ----------------------------------------------------------------------

WHITELIST_SCOPE_MATRIX = [
    # D-01: a scoped exception cannot remove an unrestricted block.
    pytest.param(
        ("||example.com^",),
        ("@@||example.com^$client=10.0.0.1",),
        ["||example.com^"],
        0,
        id="WL-01-scoped-exception-keeps-unrestricted-block",
    ),
    # Absence of restriction is broader than presence of one.
    pytest.param(
        ("||example.com^$client=10.0.0.1",),
        ("@@||example.com^",),
        [],
        1,
        id="WL-02-bare-exception-covers-scoped-child",
    ),
    pytest.param(
        ("||example.com^$client=A",),
        ("@@||example.com^$client=B",),
        ["||example.com^$client=A"],
        0,
        id="WL-03-client-value-mismatch-prevents-coverage",
    ),
    # D-02: $important priority asymmetry between block and exception.
    pytest.param(
        ("||example.com^$important",),
        ("@@||example.com^",),
        ["||example.com^$important"],
        0,
        id="WL-04-non-important-exception-keeps-important-block",
    ),
    # Equal priority + equal scope covers. Single-$ AGH combined syntax.
    pytest.param(
        ("||example.com^$important,client=X",),
        ("@@||example.com^$important,client=X",),
        [],
        1,
        id="WL-05-important-scoped-exception-covers-equal-block",
    ),
    # TLD wildcard removal happens at write time under the same dual lock.
    pytest.param(
        ("||*.autos^$client=X",),
        ("@@||*.autos^$client=X",),
        [],
        1,
        id="WL-06-tld-wildcard-scoped-exception-covers-equal-wildcard",
    ),
    pytest.param(
        ("||*.autos^",),
        ("@@||*.autos^$client=X",),
        ["||*.autos^"],
        0,
        id="WL-07-scoped-tld-exception-keeps-bare-tld-wildcard",
    ),
    # dnsrewrite rows are rewrite diagnostics: never emitted, so there is
    # nothing for the bare exception to prune.
    pytest.param(
        ("||example.com^$dnsrewrite=1.2.3.4",),
        ("@@||example.com^",),
        [],
        0,
        id="WL-08-dnsrewrite-block-not-emitted-and-not-pruned",
    ),
    pytest.param(
        ("||sub.example.com^",),
        ("@@||*.example.com^$ctag=pc",),
        ["||sub.example.com^"],
        0,
        id="WL-09-scoped-wildcard-exception-keeps-bare-subdomain",
    ),
    pytest.param(
        ("||sub.example.com^$ctag=pc",),
        ("@@||*.example.com^$ctag=pc",),
        [],
        1,
        id="WL-10-matching-scoped-wildcard-exception-covers-scoped-subdomain",
    ),
    # Correct by design (research WL-11): the parent exception carries
    # $dnstype=A while the deep child block carries none. A narrow-scope
    # modifier present on the parent but missing on the child means the child
    # blocks strictly more than the exception unblocks, so keeping the block
    # is the safe outcome rather than a missed dedup opportunity.
    pytest.param(
        ("||a.b.example.com^",),
        ("@@||example.com^$dnstype=A",),
        ["||a.b.example.com^"],
        0,
        id="WL-11-parent-narrow-dnstype-keeps-deep-bare-child",
    ),
    # Unknown modifier names cannot prove coverage; consumed silently.
    pytest.param(
        ("||example.com^",),
        ("@@||example.com^$future=value",),
        ["||example.com^"],
        0,
        id="WL-12-unknown-modifier-exception-cannot-prune",
    ),
    # EX-01: negated dnstype value signatures are incomparable -> keep.
    pytest.param(
        ("||example.com^$dnstype=A",),
        ("@@||example.com^$dnstype=~AAAA",),
        ["||example.com^$dnstype=A"],
        0,
        id="WL-13-negated-dnstype-incomparability-prevents-coverage",
    ),
    # EX-02: multi-narrowing exceptions require ALL narrow names to match;
    # the child lacking dnstype means coverage is unproven despite the equal
    # client value.
    pytest.param(
        ("||example.com^$client=10.0.0.1",),
        ("@@||example.com^$client=10.0.0.1,dnstype=a",),
        ["||example.com^$client=10.0.0.1"],
        0,
        id="WL-14-multi-narrow-exception-requires-all-names-on-child",
    ),
    # EX-04: duplicate modifier names within one side reject coverage.
    pytest.param(
        ("||example.com^",),
        ("@@||example.com^$client=A,client=B",),
        ["||example.com^"],
        0,
        id="WL-15-duplicate-name-exception-cannot-prove-coverage",
    ),
    # VD-01 (D-07): priority direction — an @@$important exception removes a
    # bare block. $important raises the exception above ordinary blocking
    # priority, so the asymmetry only protects important BLOCKS (WL-04),
    # never bare blocks against an important exception.
    pytest.param(
        ("||example.com^",),
        ("@@||example.com^$important",),
        [],
        1,
        id="WL-16-important-exception-prunes-bare-block",
    ),
]


class TestWhitelistModifierScopeAudit:
    """End-to-end whitelist/modifier-scope audit through compile_rules()."""

    def _compile(self, lines):
        """Compile lines through the full pipeline, returning output and stats."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "output.txt")
            stats = compile_rules(lines, output)
            with open(output, encoding="utf-8") as f:
                rules = [line.strip() for line in f if line.strip()]
            return rules, stats

    # ------------------------------------------------------------------
    # Tracer: core whitelist invariant across all compiler layers
    # ------------------------------------------------------------------

    def test_bare_exception_removes_unrestricted_block(self):
        """A bare @@||domain^ exception removes the unrestricted ||domain^ block.

        This single fixture exercises the full chain compile_rules() ->
        _parse_and_compress_lines() (exception capture) -> _prune_redundant_rules()
        -> _find_covering_exception() -> _exception_covers_block() -> both domain
        and modifier scope checks -> pruning. It proves exceptions are consumed
        silently (never emitted) while their covered blocks disappear.
        """
        rules, stats = self._compile([
            "||example.com^",
            "@@||example.com^",
        ])

        assert "||example.com^" not in rules
        assert not any(rule.startswith("@@") for rule in rules)
        assert stats.whitelist_conflict_pruned == 1

    # ------------------------------------------------------------------
    # WL-01..WL-15 scoped-modifier boundary matrix (D-01 / D-02)
    # ------------------------------------------------------------------

    @pytest.mark.parametrize(
        ("block_rules", "exception_rules", "expected_output", "expected_pruned"),
        WHITELIST_SCOPE_MATRIX,
    )
    def test_whitelist_boundary_matrix(
        self,
        block_rules,
        exception_rules,
        expected_output,
        expected_pruned,
    ):
        """Compile each WL fixture end-to-end; assert exact output and prunes.

        Exceptions are never emitted, so kept outcomes contain only the
        surviving block lines. Two documented nuances:

        - WL-11 is correct by design: a narrow-scope modifier present on the
          parent exception but absent from the child block means the child
          blocks strictly more than the exception unblocks, so keeping the
          block is the safe outcome (modifier_scope_covers returns False).
        - WL-05 uses single-$ combined-modifier syntax ($important,client=X);
          repeating the '$' would reparse "$client" as an unknown name.
        """
        rules, stats = self._compile([*block_rules, *exception_rules])

        assert rules == expected_output
        assert stats.whitelist_conflict_pruned == expected_pruned

    def test_wl08_dnsrewrite_block_is_rewrite_diagnostics_not_block(self):
        """WL-08 mechanism: $dnsrewrite rows never reach blocking indexes.

        The dnsrewrite block is classified EFFECT_REWRITE and dropped during
        compiler Phase 1 before any exception interaction can occur. The bare
        exception therefore prunes nothing. NO_COVERAGE protection is layered:
        rewrite diagnostics are excluded upstream, while modifier_scope_covers()
        independently rejects any pair containing dnsrewrite (see
        TestModifierScopeTruthTable for the unit-level proof).
        """
        rules, stats = self._compile([
            "||example.com^$dnsrewrite=1.2.3.4",
            "@@||example.com^",
        ])

        assert rules == []
        assert stats.whitelist_conflict_pruned == 0
        assert stats.rule_effect_rewrite == 1

    def test_wl12_unknown_modifier_exception_rejected_upstream(self):
        """WL-12 mechanism: unknown-modifier exceptions carry no pruning power.

        $future=value makes classify_rule_effect() report EFFECT_UNSUPPORTED,
        so compiler Phase 1 drops the exception before it even enters the
        exception index. The block survives untouched.
        """
        rules, stats = self._compile([
            "||example.com^",
            "@@||example.com^$future=value",
        ])

        assert rules == ["||example.com^"]
        assert stats.whitelist_conflict_pruned == 0
        assert stats.rule_effect_unsupported == 1

    def test_wl15_duplicate_name_exception_consumed_but_unproven(self):
        """WL-15 mechanism: duplicate names reach the exception index unproven.

        Each duplicate chunk parses cleanly on its own, so the exception is
        still consumed into the exception index (rule_effect_exception == 1),
        but _has_duplicate_names() inside modifier_scope_covers() rejects
        coverage regardless of the other side — the conservative answer while
        AGH behavior for duplicate modifiers is undocumented.
        """
        rules, stats = self._compile([
            "||example.com^",
            "@@||example.com^$client=A,client=B",
        ])

        assert rules == ["||example.com^"]
        assert stats.whitelist_conflict_pruned == 0
        assert stats.rule_effect_exception == 1

    def test_vd02_exception_scan_proves_no_early_return_past_scoped_mismatch(self):
        """VD-02 (D-07): the exception scan continues past scope mismatches.

        Ordered so a scoped-mismatch exception precedes the covering bare
        exception. _find_covering_exception() scans ALL exceptions instead of
        returning early on the first domain match, so the later bare coverer
        still removes the block. An early-return implementation would keep
        ||example.com^ here and prune nothing.
        """
        rules, stats = self._compile([
            "||example.com^",
            "@@||example.com^$client=192.168.1.1",
            "@@||example.com^",
        ])

        assert rules == []
        assert stats.whitelist_conflict_pruned == 1


# ----------------------------------------------------------------------
# modifier_scope_covers() truth table (Phase 13 RESEARCH.md, Layer 3).
#
# Rows: (parent_modifier_text, child_modifier_text, expected_coverage).
# ParsedModifier records are built inline through parse_modifier_text() so the
# truth table exercises the real parser output — including dnstype value
# canonicalization — instead of hand-assembled stand-ins.
# ----------------------------------------------------------------------

MODIFIER_SCOPE_TRUTH_TABLE = [
    pytest.param("", "", True, id="empty-parent-covers-empty-child"),
    # A bare parent (no restrictions) is broader than a scoped child.
    pytest.param("", "client=10.0.0.1", True, id="bare-parent-covers-scoped-child"),
    # A scoped parent can never cover a bare child.
    pytest.param("client=10.0.0.1", "", False, id="scoped-parent-cannot-cover-bare-child"),
    pytest.param("client=A", "client=A", True, id="exact-client-value-match"),
    pytest.param("client=A", "client=B", False, id="client-value-mismatch"),
    pytest.param("ctag=pc", "ctag=mobile", False, id="ctag-value-mismatch"),
    # dnstype values canonicalize case-insensitively.
    pytest.param("dnstype=a", "dnstype=A", True, id="dnstype-case-insensitive-canonicalization"),
    # NO_COVERAGE modifiers reject any pair they appear in.
    pytest.param("dnsrewrite=1.2.3.4", "", False, id="dnsrewrite-no-coverage-rejection"),
    pytest.param("denyallow=safe.example", "", False, id="denyallow-no-coverage-rejection"),
    pytest.param("badfilter", "", False, id="badfilter-no-coverage-rejection"),
    # Unknown names are uncertain and rejected.
    pytest.param("unknown_mod=V", "", False, id="unknown-modifier-name-rejected"),
    # VD-03 (D-07): negation-equality branch of narrow-scope comparison.
    # Identical negated client signatures cover each other...
    pytest.param("client=~10.0.0.1", "client=~10.0.0.1", True, id="vd03-negation-equality-covers"),
    # ...but a bare value never covers its negated form (or vice versa).
    pytest.param("client=10.0.0.1", "client=~10.0.0.1", False, id="vd03-negation-mismatch-rejects"),
]


class TestModifierScopeTruthTable:
    """Direct modifier_scope_covers() truth table, independent of compile_rules()."""

    @pytest.mark.parametrize(
        ("parent_text", "child_text", "expected"),
        MODIFIER_SCOPE_TRUTH_TABLE,
    )
    def test_modifier_scope_truth_table(self, parent_text, child_text, expected):
        """Prove each truth-table entry at the unit semantic layer.

        This isolates scripts/rule_semantics.modifier_scope_covers() from
        compiler integration so regressions surface here before they can
        manifest as incorrect pruning decisions end-to-end.

        Note: $important pairs are intentionally absent from this direct-call
        table. In production, priority asymmetry is resolved by
        compiler._important_priority_state() BEFORE important is stripped and
        remaining modifiers reach this function, so plain modifier_scope_covers()
        semantics for important pairs are not the production contract.
        """
        parent = parse_modifier_text(parent_text)
        child = parse_modifier_text(child_text)

        assert modifier_scope_covers(parent, child) is expected


# ----------------------------------------------------------------------
# Full-corpus audit (AUD-05 / D-03).
#
# Streams the entire lists/_raw/ production corpus through compile_rules()
# with a CappedProofLedger and quantifies whitelist-conflict activity at
# scale. The run takes minutes over ~138 MB of input, so it is gated behind
# the registered `slow` marker (deselected unless --run-slow is passed); the
# skipif keeps forks without a fetched corpus green even with the flag.
# ----------------------------------------------------------------------

CORPUS_DIR: Final[Path] = Path(__file__).resolve().parent.parent / "lists" / "_raw"
CORPUS_FILES_PRESENT: Final[bool] = CORPUS_DIR.is_dir() and any(CORPUS_DIR.glob("*.txt"))


@pytest.mark.slow
class TestCorpusWhitelistAudit:
    """Full-corpus AUD-05 evidence run through compile_rules() + CappedProofLedger."""

    def _corpus_lines(self):
        """Stream raw corpus rows lazily so peak memory stays compilation-bound."""
        for corpus_file in sorted(CORPUS_DIR.glob("*.txt")):
            with open(corpus_file, encoding="utf-8-sig", errors="replace") as handle:
                yield from handle

    @pytest.mark.skipif(
        not CORPUS_FILES_PRESENT,
        reason="lists/_raw/ corpus not fetched; run `python run.py fetch` first",
    )
    def test_full_corpus_compile_with_proof_ledger(self):
        """Compile the whole production corpus under proof instrumentation.

        Per D-03 this is the corpus execution step producing structured
        metrics. The assertions pin the invariants; the informational values
        (printed for FINDINGS.md analysis) quantify corpus behavior:

        - Sanity: total_input exceeds 1M rows so a silently-empty corpus run
          can never masquerade as a clean audit.
        - Dual lock: every removal-by-exception must carry
          modifier_scope_proven=True in its proof sample. A False value would
          mean pruning happened without the modifier lock — the dual-lock
          bypass bug this audit hunts for.
        - Uncertain keeps are counted but never asserted: their magnitude is
          an upstream-composition fact (research assumption A3), not a
          compiler-correctness contract.
        """
        ledger = CappedProofLedger(sample_cap=10_000)
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "corpus_output.txt")
            stats = compile_rules(self._corpus_lines(), output, proof_ledger=ledger)

        # Sanity threshold from the plan: corpus actually loaded.
        assert stats.total_input > 1_000_000

        # Informational metric floor backed by corpus evidence: the first six
        # lists/_raw files alone produced 31 whitelist conflicts during the
        # Phase 13 audit, so a full-corpus run must prune at least one rule
        # for this counter to be trustworthy (IN-01 fix — replaces the old
        # tautological >= 0 assertion).
        assert stats.whitelist_conflict_pruned > 0

        summary = ledger.summary()

        # Cross-check: each whitelist prune produced exactly one proof record.
        exception_covered_records = summary["by_reason"].get(REASON_EXCEPTION_COVERED, 0)
        assert exception_covered_records == stats.whitelist_conflict_pruned

        # Dual-lock invariant scan across materialized proof samples.
        dual_lock_violations = [
            record
            for record in ledger.records
            if record.reason == REASON_EXCEPTION_COVERED
            and record.sample.get("modifier_scope_proven") is False
        ]
        assert not dual_lock_violations

        # Informational: blocks kept because a domain-matching exception had
        # unproven modifiers (kept_because_uncertain records whose detail
        # names an exception). Two metric caveats (IN-02/IN-03 documentation):
        # (a) the tally depends on exact reason_detail wording — if compiler
        # detail constants change, this count silently degrades to zero
        # without failing anything, so treat drops as a wording-drift signal;
        # (b) counts are bounded by the CappedProofLedger sample cap per
        # bucket, so printed values are sample-bounded figures, not corpus
        # totals.
        uncertain_exception_keeps = sum(
            1
            for record in ledger.records
            if record.outcome == OUTCOME_KEPT
            and record.reason == REASON_KEPT_BECAUSE_UNCERTAIN
            and "exception" in str(record.sample.get("reason_detail", ""))
        )

        print(f"\n[AUD-05] total_input={stats.total_input:,}")
        print(f"[AUD-05] whitelist_conflict_pruned={stats.whitelist_conflict_pruned:,}")
        exception_rule_keys = stats.exception_rule_keys
        print(f"[AUD-05] exception_rule_keys={exception_rule_keys:,}")
        print(
            f"[AUD-05] uncertain_exception_keeps(sampled<={ledger.sample_cap})="
            f"{uncertain_exception_keeps}"
        )
        print(f"[AUD-05] ledger_summary={summary}")

        # Ledger integrity: aggregated count matches the reported total.
        assert summary["total_records"] == len(ledger)


# ----------------------------------------------------------------------
# Denyallow shadow-comparison machinery (D-04 Plan B gate infrastructure).
#
# Reusable two-leg comparator: compiles one rule stream twice (denyallow
# flag OFF then ON) inside a single process with fresh capped tallying
# ledgers, clearing compiler LRU caches BETWEEN legs. The uncapped
# tallying subclass records every denyallow_covered candidate identity so
# removals can be witnessed by exact identity rather than capped samples.
# The fast unit layer below proves the machinery on synthetic fixture
# lines; TestDenyallowShadowEquivalence feeds it the full corpus.
# ----------------------------------------------------------------------


class DenyallowTallyingLedger(CappedProofLedger):
    """CappedProofLedger that tallies every denyallow_covered candidate.

    FINDINGS §8 item 3 tally-before-delegating pattern: when an incoming
    decision carries REASON_DENYALLOW_COVERED, the candidate facet is
    resolved eagerly and its emitted rule text joins ``denyallow_candidates``
    BEFORE delegating to super() unchanged. This bypasses sample_cap
    truncation for exactly one dimension (~500k short strings ≈ tens of MB,
    far cheaper than materializing full proof records), giving the shadow
    gate an exact per-line witness instead of a capped sample.
    """

    def __init__(self, sample_cap: int = DEFAULT_SAMPLE_CAP) -> None:
        super().__init__(sample_cap=sample_cap)
        self.denyallow_candidates: set[str] = set()

    def append_decision(
        self,
        *,
        decision_id: str,
        decision_type: str,
        outcome: str,
        proof_status: str,
        reason: str,
        candidate_factory: Callable[[], RuleFacet],
        covering_factory: Callable[[], RuleFacet | None],
        strict_agh_delta: str,
        project_policy_delta: str,
        sample_factory: Callable[[], dict[str, object] | None] | None = None,
    ) -> None:
        """Tally denyallow candidates uncapped, then delegate unchanged."""
        if reason == REASON_DENYALLOW_COVERED:
            # normalized_rule is the exact text _write_output() emits, so
            # tally identities compare equal against output-file lines.
            self.denyallow_candidates.add(candidate_factory().normalized_rule)
        super().append_decision(
            decision_id=decision_id,
            decision_type=decision_type,
            outcome=outcome,
            proof_status=proof_status,
            reason=reason,
            candidate_factory=candidate_factory,
            covering_factory=covering_factory,
            strict_agh_delta=strict_agh_delta,
            project_policy_delta=project_policy_delta,
            sample_factory=sample_factory,
        )


class ApexTallyingLedger(CappedProofLedger):
    """CappedProofLedger that tallies every apex-covered wildcard candidate.

    Phase 17 shadow-machinery twin of DenyallowTallyingLedger (same
    tally-before-delegating pattern): when an incoming decision carries
    REASON_APEX_COVERS_TLD_WILDCARD, the candidate facet is resolved
    eagerly and its emitted rule text joins ``apex_candidates`` BEFORE
    delegating to super() unchanged. Additionally records
    ``(candidate, covering)`` normalized-rule pairs in ``apex_pairs`` so
    signature element S8 (survivor-coverer membership) can be asserted
    past any sample cap -- capped samples hold at most sample_cap records
    per bucket and are display evidence only. Both sets are uncapped but
    bounded by the wildcard-removal population itself (tiny vs millions
    of input rows). ``normalized_rule`` equals the exact text
    _write_output() emits, so set identity against output-file lines is
    sound.
    """

    def __init__(self, sample_cap: int = DEFAULT_SAMPLE_CAP) -> None:
        super().__init__(sample_cap=sample_cap)
        self.apex_candidates: set[str] = set()
        self.apex_pairs: set[tuple[str, str]] = set()

    def append_decision(
        self,
        *,
        decision_id: str,
        decision_type: str,
        outcome: str,
        proof_status: str,
        reason: str,
        candidate_factory: Callable[[], RuleFacet],
        covering_factory: Callable[[], RuleFacet | None],
        strict_agh_delta: str,
        project_policy_delta: str,
        sample_factory: Callable[[], dict[str, object] | None] | None = None,
    ) -> None:
        """Tally apex candidates and pairs uncapped, then delegate unchanged."""
        if reason == REASON_APEX_COVERS_TLD_WILDCARD:
            candidate_rule = candidate_factory().normalized_rule
            self.apex_candidates.add(candidate_rule)
            covering_facet = covering_factory()
            if covering_facet is not None:
                self.apex_pairs.add((candidate_rule, covering_facet.normalized_rule))
        super().append_decision(
            decision_id=decision_id,
            decision_type=decision_type,
            outcome=outcome,
            proof_status=proof_status,
            reason=reason,
            candidate_factory=candidate_factory,
            covering_factory=covering_factory,
            strict_agh_delta=strict_agh_delta,
            project_policy_delta=project_policy_delta,
            sample_factory=sample_factory,
        )


class ShadowComparisonResult(NamedTuple):
    """Paired flag-OFF/flag-ON compile outcomes for shadow-gate assertions.

    off_seconds/on_seconds are per-leg wall clocks surfaced only for the
    corpus gate's informational prints; all correctness assertions are
    computed from the six evidence fields.
    """

    off_lines: list[str]
    on_lines: list[str]
    off_stats: CompileStats
    on_stats: CompileStats
    off_ledger: DenyallowTallyingLedger
    on_ledger: DenyallowTallyingLedger
    off_seconds: float
    on_seconds: float


class ApexShadowComparisonResult(NamedTuple):
    """Paired apex-flag-OFF/ON compile outcomes for apex shadow-gate assertions.

    Same shape as ShadowComparisonResult, typed to ApexTallyingLedger so
    the uncapped ``apex_candidates``/``apex_pairs`` witnesses travel with
    each leg. Per D-16-01 both legs run production-default denyallow
    pruning, making ``wildcard_apex_pruning`` the ONLY moving part; per
    16-RESEARCH Derived Implication 3 the ON leg's total_records exceeds
    OFF by exactly the removal count (deliberate S4 delta direction).
    """

    off_lines: list[str]
    on_lines: list[str]
    off_stats: CompileStats
    on_stats: CompileStats
    off_ledger: ApexTallyingLedger
    on_ledger: ApexTallyingLedger
    off_seconds: float
    on_seconds: float


def _shadow_line_factory(
    lines: Callable[[], Iterable[str]] | Iterable[str],
) -> Callable[[], Iterable[str]]:
    """Normalize a line source into a zero-arg factory of fresh iterators.

    Args:
        lines: Re-iterable rule source (list/tuple) or a zero-arg callable
            returning a fresh iterable (e.g., the corpus harness's generator
            method). Each shadow leg MUST compile its own fresh iterator
            because compile_rules() consumes the stream exactly once.

    Returns:
        A callable producing an independent line iterator per call.

    Raises:
        TypeError: When ``lines`` is already a one-shot iterator, which could
            never feed both legs.
    """
    if isinstance(lines, Iterator):
        raise TypeError(
            "lines must be re-iterable or a zero-arg factory returning fresh "
            "iterators; a one-shot iterator cannot feed both shadow legs"
        )
    if callable(lines):
        return lines
    return lambda: iter(lines)


def _compile_shadow_leg(
    line_source: Callable[[], Iterable[str]],
    output_path: Path,
    *,
    ledger_factory: Callable[..., CappedProofLedger] | None = None,
    **compile_kwargs: object,
) -> tuple[CompileStats, CappedProofLedger, float]:
    """Run one shadow leg with a fresh ledger and fresh lines iterator.

    Generalized per the 16-02 handoff (Phase 17 designated first task):
    arbitrary compile_rules kwargs forward verbatim, so the denyallow
    family keeps passing ``denyallow_pruning=`` exactly as before while
    the apex family adds ``wildcard_apex_pruning=True`` on its ON leg.
    When ``ledger_factory`` is None the legacy default applies unchanged:
    a fresh DenyallowTallyingLedger with a 10,000-entry sample cap.
    """
    if ledger_factory is None:
        ledger: CappedProofLedger = DenyallowTallyingLedger(sample_cap=10_000)
    else:
        ledger = ledger_factory(sample_cap=10_000)
    leg_start = time.perf_counter()
    stats = compile_rules(
        line_source(),
        str(output_path),
        proof_ledger=ledger,
        **compile_kwargs,
    )
    return stats, ledger, time.perf_counter() - leg_start


def _read_output_lines(output_path: Path) -> list[str]:
    """Read compiled output back as stripped non-empty lines (mirrors _compile)."""
    with open(output_path, encoding="utf-8") as handle:
        return [line.strip() for line in handle if line.strip()]


def _run_shadow_comparison(
    lines: Callable[[], Iterable[str]] | Iterable[str],
) -> ShadowComparisonResult:
    """Compile the same rule stream twice (flag OFF, then ON) in one process.

    D-04 Plan B machinery. Each leg receives its own fresh capped tallying
    ledger and its own fresh lines iterator; compiler.clear_caches() runs
    BETWEEN the two compile legs because the module LRU caches are
    process-global and conftest's autouse fixture only clears between tests,
    never mid-test (research Pitfall 7).

    Args:
        lines: Re-iterable rule source (list/tuple) or a zero-arg callable
            returning a fresh iterable (e.g., the corpus generator method).

    Returns:
        ShadowComparisonResult pairing both legs' output lines, stats, and
        ledgers plus per-leg wall-clock seconds.
    """
    line_source = _shadow_line_factory(lines)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        off_output = tmp_path / "shadow_off.txt"
        off_stats, off_ledger, off_seconds = _compile_shadow_leg(
            line_source,
            off_output,
            denyallow_pruning=False,
        )
        off_lines = _read_output_lines(off_output)

        # Cache hygiene between legs: the ON leg must not inherit warmed
        # domain/TLD caches from the OFF leg.
        clear_caches()

        on_output = tmp_path / "shadow_on.txt"
        on_stats, on_ledger, on_seconds = _compile_shadow_leg(
            line_source,
            on_output,
            denyallow_pruning=True,
        )
        on_lines = _read_output_lines(on_output)

    return ShadowComparisonResult(
        off_lines=off_lines,
        on_lines=on_lines,
        off_stats=off_stats,
        on_stats=on_stats,
        off_ledger=off_ledger,
        on_ledger=on_ledger,
        off_seconds=off_seconds,
        on_seconds=on_seconds,
    )


def _run_apex_shadow_comparison(
    lines: Callable[[], Iterable[str]] | Iterable[str],
) -> ApexShadowComparisonResult:
    """Compile the same rule stream twice (apex flag OFF, then ON) in one process.

    Phase 17 apex shadow machinery. Each leg receives its own fresh
    ApexTallyingLedger and its own fresh lines iterator; the OFF leg passes
    NO extra compile kwargs so it runs the production defaults
    (denyallow_pruning=True, wildcard_apex_pruning=False), and the ON leg
    adds ONLY ``wildcard_apex_pruning=True`` -- per D-16-01 both apex legs
    ride production-default denyallow pruning so the apex flag is the sole
    moving part between legs. compiler.clear_caches() runs BETWEEN legs
    because the module LRU caches are process-global and conftest's autouse
    fixture only clears between tests, never mid-test.

    Signature note (S4): the ON leg's ledger total_records DELIBERATELY
    exceeds the OFF leg's by exactly the removal count -- a to-be-pruned
    wildcard has no OFF-leg record because write-time keeps emit nothing
    (D-16-01 write-time placement, D-16-02 strict same-key witnessing).
    Callers must assert the delta, never totals equality.
    """
    line_source = _shadow_line_factory(lines)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        off_output = tmp_path / "apex_shadow_off.txt"
        off_stats, off_ledger, off_seconds = _compile_shadow_leg(
            line_source,
            off_output,
            ledger_factory=ApexTallyingLedger,
        )
        off_lines = _read_output_lines(off_output)

        # Cache hygiene between legs: the ON leg must not inherit warmed
        # domain/TLD caches from the OFF leg.
        clear_caches()

        on_output = tmp_path / "apex_shadow_on.txt"
        on_stats, on_ledger, on_seconds = _compile_shadow_leg(
            line_source,
            on_output,
            ledger_factory=ApexTallyingLedger,
            wildcard_apex_pruning=True,
        )
        on_lines = _read_output_lines(on_output)

    return ApexShadowComparisonResult(
        off_lines=off_lines,
        on_lines=on_lines,
        off_stats=off_stats,
        on_stats=on_stats,
        off_ledger=off_ledger,
        on_ledger=on_ledger,
        off_seconds=off_seconds,
        on_seconds=on_seconds,
    )


# ----------------------------------------------------------------------
# Denyallow shadow-comparison machinery unit layer (fast fixtures).
#
# Proves the two-leg comparison helper produces the exact delta signature
# on synthetic fixture lines BEFORE the full corpus gate runs. The slow
# corpus consumer lives in TestDenyallowShadowEquivalence below and reuses
# every component proven here.
# ----------------------------------------------------------------------


class TestShadowComparisonMachinery:
    """Unit-proven two-leg shadow comparison over synthetic fixture lines.

    Fixture mirrors FINDINGS §6 samples: an admissible $denyallow TLD
    wildcard covers two disjoint children (pruned under flag ON), while an
    $important child and an unrelated-domain rule must survive both legs.
    """

    SHADOW_FIXTURE_LINES = [
        "||*.world^$denyallow=bevisioneers.world|boo.world",
        "||adjust.world^",
        "||autoads.world^",
        "||promo.world^$important",
        "||unrelated.example^",
    ]

    def _result(self):
        return _run_shadow_comparison(list(self.SHADOW_FIXTURE_LINES))

    def test_two_leg_delta_signature_exact_on_fixture_lines(self):
        """Flag ON removes exactly the disjoint children; nothing else moves.

        Pins the D-04/D-05 delta signature end-to-end: removed set exact,
        added empty, kept_because_uncertain drops by precisely the
        denyallow_covered count, every other by_reason bucket identical,
        total_records identical, stats↔ledger equality in BOTH legs, and the
        uncapped tally witness equals the removed set by identity.
        """
        result = self._result()
        removed = set(result.off_lines) - set(result.on_lines)
        added = set(result.on_lines) - set(result.off_lines)

        # Only the two disjoint children disappear; no line appears or changes.
        assert removed == {"||adjust.world^", "||autoads.world^"}
        assert not added

        off_by_reason = result.off_ledger.summary()["by_reason"]
        on_by_reason = result.on_ledger.summary()["by_reason"]
        denyallow_off = off_by_reason.get(REASON_DENYALLOW_COVERED, 0)
        denyallow_on = on_by_reason.get(REASON_DENYALLOW_COVERED, 0)

        # Stats ↔ ledger equality holds in BOTH legs; OFF leg pins 0 == 0 so a
        # regression that prunes with the flag disabled fails loudly here.
        assert denyallow_off == result.off_stats.denyallow_wildcard_pruned
        assert denyallow_on == result.on_stats.denyallow_wildcard_pruned
        assert denyallow_on > 0
        assert denyallow_off == 0

        # Exact uncertain-bucket delta: keeps drop by exactly the prune count.
        kept_drop = (
            off_by_reason[REASON_KEPT_BECAUSE_UNCERTAIN]
            - on_by_reason[REASON_KEPT_BECAUSE_UNCERTAIN]
        )
        assert kept_drop == denyallow_on

        # Every other attribution bucket is byte-stable in both directions.
        # The two buckets that may differ are skipped here because each is
        # already pinned EXACTLY above: kept_because_uncertain by the
        # kept_drop == denyallow_on assertion, denyallow_covered by the
        # stats↔ledger equality assertions.
        for reason, off_count in off_by_reason.items():
            if reason in {REASON_DENYALLOW_COVERED, REASON_KEPT_BECAUSE_UNCERTAIN}:
                continue
            assert on_by_reason.get(reason, 0) == off_count
        for reason, on_count in on_by_reason.items():
            if reason in {REASON_DENYALLOW_COVERED, REASON_KEPT_BECAUSE_UNCERTAIN}:
                continue
            assert off_by_reason.get(reason, 0) == on_count

        # total_records identical across legs (one record per decision either way).
        assert result.off_ledger.summary()["total_records"] == (
            result.on_ledger.summary()["total_records"]
        )

        # Uncapped tally bypasses sample truncation: identities match removals.
        assert result.on_ledger.denyallow_candidates == removed
        assert result.off_ledger.denyallow_candidates == set()

    def test_shadow_reruns_are_byte_deterministic(self):
        """Two invocations over the same lines yield identical off/on outputs.

        Storage-order first-match determinism (research Pitfall 5): rerunning
        the comparison must reproduce byte-identical legs or corpus-scale
        fingerprints would be meaningless.
        """
        first = self._result()
        second = self._result()

        assert first.off_lines == second.off_lines
        assert first.on_lines == second.on_lines

    def test_apex_covers_tld_wildcard_zero_pairing_in_both_shadow_legs(self):
        """Fast fixture twin of the corpus gate's apex zero-pairing pins.

        Locks D-05 count-identity for the apex family — the ledger
        by_reason tally equals the paired CompileStats counter — in BOTH
        flag legs through the genuine _run_shadow_comparison() machinery,
        both reading 0 until Phase 16 introduces the flag-gated emission
        site. Four separate asserts, one claim each (never chained).
        """
        result = self._result()
        off_by_reason = result.off_ledger.summary()["by_reason"]
        on_by_reason = result.on_ledger.summary()["by_reason"]
        apex_off = off_by_reason.get(REASON_APEX_COVERS_TLD_WILDCARD, 0)
        apex_on = on_by_reason.get(REASON_APEX_COVERS_TLD_WILDCARD, 0)
        assert apex_off == result.off_stats.apex_covered_wildcard_pruned
        assert apex_off == 0
        assert apex_on == result.on_stats.apex_covered_wildcard_pruned
        assert apex_on == 0


# ----------------------------------------------------------------------
# Full-corpus denyallow shadow equivalence (D-04 Plan B gate).
#
# THE equivalence checkpoint for flipping denyallow_pruning ON: streams the
# entire lists/_raw/ production corpus through _run_shadow_comparison()
# (two same-process compile legs with mid-call cache clearing) and asserts
# the EXACT delta signature — enabling the flag removes exactly the
# denyallow-proven population and nothing else. A red gate here HALTS the
# rollout before any default flip; it is never silenced by weakening an
# assertion. Runs ~25-35 min over ~132 MB of input, so it is gated behind
# the registered `slow` marker (deselected unless --run-slow is passed);
# the skipif keeps forks without a fetched corpus green even with the flag.
# ----------------------------------------------------------------------


@pytest.mark.slow
class TestDenyallowShadowEquivalence:
    """D-04 Plan B full-corpus shadow gate through _run_shadow_comparison()."""

    def _corpus_lines(self):
        """Stream raw corpus rows lazily so peak memory stays compilation-bound."""
        for corpus_file in sorted(CORPUS_DIR.glob("*.txt")):
            with open(corpus_file, encoding="utf-8-sig", errors="replace") as handle:
                yield from handle

    @pytest.mark.skipif(
        not CORPUS_FILES_PRESENT,
        reason="lists/_raw/ corpus not fetched; run `python run.py fetch` first",
    )
    def test_full_corpus_shadow_equivalence(self):
        """Prove flag ON removes ONLY the denyallow-proven population at scale.

        Locked D-04/D-05 signature, asserted via computed values (never
        chained comparisons — each claim gets its own assert so no bound is
        compared against the wrong operand):

        - Both legs ingest identical input; input exceeds 1M rows.
        - Output diff: added-lines empty; removed set positive.
        - denyallow_covered == stats.denyallow_wildcard_pruned (both legs,
          OFF pinning 0 == 0) AND == len(removed) — exact, not sampled,
          via the uncapped tally witness.
        - apex ledger tally == stats.apex_covered_wildcard_pruned == 0 in
          BOTH legs — Phase 15 plumbing must stay inert until Phase 16's
          flag-gated emission site exists (D-05 zero-pairing).
        - kept_because_uncertain drops by EXACTLY the denyallow count;
          every other by_reason bucket byte-stable; total_records identical.

        Informational prints compare magnitudes against FINDINGS §4's
        518,754 uncertain-keep upper bound without asserting them.
        """
        result = _run_shadow_comparison(self._corpus_lines)

        removed = set(result.off_lines) - set(result.on_lines)
        added = set(result.on_lines) - set(result.off_lines)

        # Input identity + sanity (separate asserts: a chained expression
        # would compare the second leg against the literal, always False).
        assert result.off_stats.total_input == result.on_stats.total_input
        assert result.off_stats.total_input > 1_000_000

        off_summary = result.off_ledger.summary()
        on_summary = result.on_ledger.summary()
        off_by_reason = off_summary["by_reason"]
        on_by_reason = on_summary["by_reason"]

        denyallow_off = off_by_reason.get(REASON_DENYALLOW_COVERED, 0)
        denyallow_on = on_by_reason.get(REASON_DENYALLOW_COVERED, 0)

        # Output diff shape.
        assert not added
        assert len(removed) > 0

        # Stats ↔ ledger equality in BOTH legs (OFF pins 0 == 0 so a future
        # regression that prunes with the flag disabled fails loudly here).
        assert denyallow_on == result.on_stats.denyallow_wildcard_pruned
        assert denyallow_off == result.off_stats.denyallow_wildcard_pruned
        exception_covered_off = off_by_reason.get(REASON_EXCEPTION_COVERED, 0)
        assert exception_covered_off == result.off_stats.whitelist_conflict_pruned
        exception_covered_on = on_by_reason.get(REASON_EXCEPTION_COVERED, 0)
        assert exception_covered_on == result.on_stats.whitelist_conflict_pruned

        # Phase 15 plumbing-inertness (D-05): the apex reason/counter pair
        # is wired end-to-end but has no emission site until Phase 16's flag
        # exists — pin tally == counter == 0 in BOTH legs so same-leg firing
        # (invisible to the byte-stability skip-loops below) fails loudly.
        apex_off = off_by_reason.get(REASON_APEX_COVERS_TLD_WILDCARD, 0)
        apex_on = on_by_reason.get(REASON_APEX_COVERS_TLD_WILDCARD, 0)
        assert apex_off == result.off_stats.apex_covered_wildcard_pruned
        assert apex_off == 0
        assert apex_on == result.on_stats.apex_covered_wildcard_pruned
        assert apex_on == 0

        # Every removed line carries an uncapped proof witness by identity.
        assert denyallow_on == len(removed)
        assert result.on_ledger.denyallow_candidates == removed
        assert result.off_ledger.denyallow_candidates == set()

        # Exact uncertain-bucket delta (D-05 at corpus scale).
        kept_before = off_by_reason[REASON_KEPT_BECAUSE_UNCERTAIN]
        kept_after = on_by_reason[REASON_KEPT_BECAUSE_UNCERTAIN]
        assert kept_before - kept_after == denyallow_on

        # Byte-stable attribution everywhere else, both directions.
        for reason, off_count in off_by_reason.items():
            if reason in {REASON_DENYALLOW_COVERED, REASON_KEPT_BECAUSE_UNCERTAIN}:
                continue
            assert on_by_reason.get(reason, 0) == off_count
        for reason, on_count in on_by_reason.items():
            if reason in {REASON_DENYALLOW_COVERED, REASON_KEPT_BECAUSE_UNCERTAIN}:
                continue
            assert off_by_reason.get(reason, 0) == on_count

        # One ledger record per decision either way.
        assert off_summary["total_records"] == on_summary["total_records"]

        # Informational evidence block (asserts nothing about magnitude).
        print(f"\n[D-04 SHADOW] total_input={result.off_stats.total_input:,}")
        print(f"[D-04 SHADOW] removed={len(removed):,} (FINDINGS §4 upper bound: 518,754)")
        print(f"[D-04 SHADOW] denyallow_covered={denyallow_on:,}")
        print(f"[D-04 SHADOW] apex_covered_wildcard_pruned={apex_on:,}")
        print(f"[D-04 SHADOW] kept_because_uncertain {kept_before:,} -> {kept_after:,}")
        print(f"[D-04 SHADOW] off_leg_seconds={result.off_seconds:.1f}")
        print(f"[D-04 SHADOW] on_leg_seconds={result.on_seconds:.1f}")


# ----------------------------------------------------------------------
# Apex shadow-comparison machinery unit layer (Phase 17, SAFE-03).
#
# Fixture-scale twin layer for the apex OFF/ON shadow gate that Phase
# 17-03 feeds the frozen corpus. Proves the generalized kwargs-forwarding
# leg helper, the uncapped-witnessing ApexTallyingLedger (candidates AND
# (candidate, covering) pairs past any sample cap), and the
# placement-specific signature S1-S8 locked by Phase 16 composites --
# INCLUDING the deliberate S4 DELTA direction (ON total_records exceeds
# OFF by exactly the removal count; a to-be-pruned wildcard has no
# OFF-leg record) and S6 uncertain-keeps STASIS that distinguish this
# gate from the v1.2 denyallow precedent.
#
# Fixture recipe extends the proven 16-02 composite (28 real single-label
# public-suffix pairs + autos) with ONE multi-label public-suffix pair
# (||*.co.uk^ / ||co.uk^ -- genuine same-key prune, exercising the
# multipart bucket end-to-end), ONE $important keep control, ONE
# uncertain keep control, ONE whitelist-conflict control, and ONE
# $denyallow control whose two children are pruned identically in BOTH
# legs because both legs run production-default denyallow_pruning=True
# (D-16-01 lineage): the apex flag is the only moving part.
# ----------------------------------------------------------------------

# Real single-label public suffixes ONLY: synthetic TLD names never reach
# abp_wildcards (PSL parse bucketing), so composite removal populations
# must use real suffixes (16-02 decision).
APEX_SHADOW_PAIR_TLDS: Final[tuple[str, ...]] = (
    "xyz",
    "online",
    "site",
    "top",
    "icu",
    "club",
    "shop",
    "store",
    "tech",
    "cloud",
    "space",
    "website",
    "fun",
    "pro",
    "cyou",
    "live",
    "life",
    "world",
    "today",
    "email",
    "link",
    "zone",
    "agency",
    "digital",
    "global",
    "network",
    "media",
    "systems",
)

APEX_SHADOW_FIXTURE_LINES: Final[list[str]] = [
    *[line_part for tld in APEX_SHADOW_PAIR_TLDS for line_part in (f"||{tld}^", f"||*.{tld}^")],
    # Apex pair + $important keep control: the important-carrying wildcard
    # must survive BOTH legs (narrower priority never qualifies).
    "||autos^",
    "||*.autos^",
    "||*.autos^$important",
    # Uncertain keep control pair: no ||com^ apex present, and the
    # $important child cannot have its scope proven against the plain
    # ||*.com^ wildcard -- so exactly one kept_because_uncertain record
    # lands in BOTH legs (mirrors the proven 16-02 composite).
    "||*.com^",
    "||foo.com^$important",
    # Whitelist-conflict control: identical exception_covered count in both legs.
    "@@||whi.test^",
    "||whi.test^",
    # $denyallow control: children are NOT named in the exemption list, so
    # both legs denyallow-prune them identically under production defaults.
    # (Naming them inside $denyallow would exempt exactly those domains.)
    "||*.buzz^$denyallow=safe.buzz|keep.buzz",
    "||one.buzz^",
    "||two.buzz^",
    # Multi-label public-suffix pair: exercises the multipart_suffix_apex
    # bucket end-to-end through a genuine strict same-key prune.
    "||*.co.uk^",
    "||co.uk^",
]


class TestApexShadowMachinery:
    """Unit-proven apex two-leg shadow comparison over synthetic fixture lines.

    Fast twins proving the generalized shadow machinery reproduces the
    placement-specific apex signature BEFORE the corpus gate consumes the
    same components against the frozen dataset.
    """

    def _result(self):
        return _run_apex_shadow_comparison(list(APEX_SHADOW_FIXTURE_LINES))

    def test_apex_delta_signature_exact_on_fixture_lines(self):
        """Flag ON removes exactly the apex-proven wildcards; nothing else moves.

        Pins signature elements S1-S8 as separate asserts over computed
        values (never chained comparisons). S4 asserts the DELTA direction
        and S6 asserts uncertain-keeps STASIS per 16-RESEARCH Derived
        Implications 3-4 -- deliberately unlike the denyallow gate where
        totals stayed stable and uncertain dropped by the prune count.
        """
        result = self._result()

        # S1: input identity across legs.
        assert result.off_stats.total_input == result.on_stats.total_input

        removed = set(result.off_lines) - set(result.on_lines)
        added = set(result.on_lines) - set(result.off_lines)
        expected_removed = {f"||*.{tld}^" for tld in APEX_SHADOW_PAIR_TLDS} | {
            "||*.autos^",
            "||*.co.uk^",
        }

        # S2: added-lines empty -- wildcards can only vanish.
        assert not added

        # Exact removed population on this fixture (locked computed values).
        assert len(removed) == len(expected_removed)
        assert removed == expected_removed

        # S3: uncapped witness identity trio -- ledger set, stats counter,
        # removed set all agree past the sample cap.
        assert result.on_ledger.apex_candidates == removed
        assert result.on_stats.apex_covered_wildcard_pruned == len(removed)

        # S4: ON total_records exceeds OFF by EXACTLY the removal count
        # (a to-be-pruned wildcard has NO OFF-leg record; write-time keeps
        # emit nothing). Never assert totals equality across these legs.
        off_total_records = result.off_ledger.summary()["total_records"]
        on_total_records = result.on_ledger.summary()["total_records"]
        assert on_total_records - off_total_records == len(removed)

        off_by_reason = result.off_ledger.summary()["by_reason"]
        on_by_reason = result.on_ledger.summary()["by_reason"]

        # S5a: whitelist-conflict bucket bit-identical across legs.
        whitelist_off = off_by_reason.get(REASON_EXCEPTION_COVERED, 0)
        whitelist_on = on_by_reason.get(REASON_EXCEPTION_COVERED, 0)
        assert whitelist_off == whitelist_on

        # S5b: denyallow bucket identical across legs -- both legs run the
        # production default denyallow_pruning=True so the apex flag is the
        # only moving part.
        denyallow_off = off_by_reason.get(REASON_DENYALLOW_COVERED, 0)
        denyallow_on = on_by_reason.get(REASON_DENYALLOW_COVERED, 0)
        assert denyallow_off == denyallow_on

        # S6: uncertain-keeps STASIS (equality is correct here).
        kept_before = off_by_reason[REASON_KEPT_BECAUSE_UNCERTAIN]
        kept_after = on_by_reason[REASON_KEPT_BECAUSE_UNCERTAIN]
        assert kept_before == kept_after

        # S7: every other attribution bucket byte-stable, both directions.
        # The buckets that may differ are skipped because each is pinned
        # EXACTLY above: apex by S3/S4, kept_because_uncertain by S6.
        skipped_reasons = {REASON_APEX_COVERS_TLD_WILDCARD, REASON_KEPT_BECAUSE_UNCERTAIN}
        for reason, off_count in off_by_reason.items():
            if reason in skipped_reasons:
                continue
            assert on_by_reason.get(reason, 0) == off_count
        for reason, on_count in on_by_reason.items():
            if reason in skipped_reasons:
                continue
            assert off_by_reason.get(reason, 0) == on_count

        # S8: survivor-coverer membership via the UNCAPPED pairs set --
        # never via capped samples (samples cap at DEFAULT_SAMPLE_CAP per
        # bucket and are display evidence only).
        on_line_set = set(result.on_lines)
        pairs = result.on_ledger.apex_pairs
        assert len(pairs) == len(removed)
        for candidate_rule, covering_rule in sorted(pairs):
            assert candidate_rule in removed
            assert covering_rule in on_line_set

        # OFF-side witnessing stays empty: the flag-OFF leg emits nothing.
        assert result.off_ledger.apex_candidates == set()
        assert result.off_ledger.apex_pairs == set()

        # Informational evidence block (asserts nothing about magnitude).
        print(f"\n[APEX SHADOW] total_input={result.off_stats.total_input:,}")
        print(f"[APEX SHADOW] removed={len(removed):,}")
        print(f"[APEX SHADOW] apex_pairs={len(pairs):,}")
        print(f"[APEX SHADOW] off_leg_seconds={result.off_seconds:.3f}")
        print(f"[APEX SHADOW] on_leg_seconds={result.on_seconds:.3f}")

    def test_apex_shadow_reruns_are_byte_deterministic(self):
        """Two invocations over the same lines yield identical off/on outputs."""
        first = self._result()
        second = self._result()

        assert first.off_lines == second.off_lines
        assert first.on_lines == second.on_lines

    def test_generalized_leg_helper_preserves_default_denyallow_ledger(self):
        """Omitting ledger_factory reproduces the legacy denyallow contract.

        Behavior-preservation twin of the 16-02 handoff generalization:
        existing callers pass exactly what they passed before and receive
        a DenyallowTallyingLedger-backed leg unchanged.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "legacy_leg.txt"
            stats, ledger, seconds = _compile_shadow_leg(
                lambda: iter(["||unrelated.example^"]),
                output_path,
                denyallow_pruning=False,
            )

        assert isinstance(ledger, DenyallowTallyingLedger)
        assert ledger.denyallow_candidates == set()
        assert isinstance(stats, CompileStats)
        assert seconds >= 0.0
