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
    denyallow_pruning: bool,
) -> tuple[CompileStats, DenyallowTallyingLedger, float]:
    """Run one shadow leg with a fresh ledger and fresh lines iterator."""
    ledger = DenyallowTallyingLedger(sample_cap=10_000)
    leg_start = time.perf_counter()
    stats = compile_rules(
        line_source(),
        str(output_path),
        proof_ledger=ledger,
        denyallow_pruning=denyallow_pruning,
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
