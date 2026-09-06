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

import copy
import gc
import hashlib
import json
import os
import re
import statistics
import sys
import tempfile
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, NamedTuple

import pytest

from scripts.benchmark import _python_identity, build_corpus_manifest, manifest_digest
from scripts.compiler import (
    CompileStats,
    _parse_abp_rule,
    _wildcard_covers_sub,
    _write_output,
    clear_caches,
    compile_rules,
    get_tld,
)
from scripts.pruning_proof import (
    DEFAULT_SAMPLE_CAP,
    OUTCOME_KEPT,
    REASON_APEX_COVERS_TLD_WILDCARD,
    REASON_DENYALLOW_COVERED,
    REASON_EXCEPTION_COVERED,
    REASON_KEPT_BECAUSE_UNCERTAIN,
    REASON_WILDCARD_COVERS_SUB,
    CappedProofLedger,
    RuleFacet,
    _capped_sample_record,
)
from scripts.release_validator import (
    DEFAULT_MINIMUM_OUTPUT_RULES,
    DEFAULT_PREVIOUS_EXTREME_ABSOLUTE_DELTA,
    DEFAULT_PREVIOUS_EXTREME_DROP_RATIO,
    DEFAULT_PREVIOUS_EXTREME_INCREASE_RATIO,
    DEFAULT_PREVIOUS_MODERATE_DELTA_RATIO,
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
        rules, stats = self._compile(
            [
                "||example.com^",
                "@@||example.com^",
            ]
        )

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
        rules, stats = self._compile(
            [
                "||example.com^$dnsrewrite=1.2.3.4",
                "@@||example.com^",
            ]
        )

        assert rules == []
        assert stats.whitelist_conflict_pruned == 0
        assert stats.rule_effect_rewrite == 1

    def test_wl12_unknown_modifier_exception_rejected_upstream(self):
        """WL-12 mechanism: unknown-modifier exceptions carry no pruning power.

        $future=value makes classify_rule_effect() report EFFECT_UNSUPPORTED,
        so compiler Phase 1 drops the exception before it even enters the
        exception index. The block survives untouched.
        """
        rules, stats = self._compile(
            [
                "||example.com^",
                "@@||example.com^$future=value",
            ]
        )

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
        rules, stats = self._compile(
            [
                "||example.com^",
                "@@||example.com^$client=A,client=B",
            ]
        )

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
        rules, stats = self._compile(
            [
                "||example.com^",
                "@@||example.com^$client=192.168.1.1",
                "@@||example.com^",
            ]
        )

        assert rules == []
        assert stats.whitelist_conflict_pruned == 1

    def test_bare_child_exception_plus_admissible_denyallow_prunes_via_denyallow(self):
        """Regression lock: exception-matched subs stay denyallow-eligible (HYG-01 IN-03 revert).

        The TLD branch unconditionally reports the wildcard detail, so the
        denyallow gate below still opens for bare children with admissible
        allow-sets — even when an exception domain-scope match was recorded
        first. Locks the 23-09 IN-03 guard revert: the 23-09 guard closed this
        gate (denyallow_pruned 0, keep-as-uncertain), changing output bytes,
        counters, and ledger buckets inside a zero-behavior-change phase.
        A bare child plus an admissible denyallow wildcard must prune.
        """
        ledger = CappedProofLedger()
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "output.txt")
            stats = compile_rules(
                [
                    "||*.autos^$denyallow=other.autos",
                    "||sub.autos^",
                    "@@||sub.autos^$client=10.0.0.1",
                ],
                output,
                proof_ledger=ledger,
                denyallow_pruning=True,
            )
            with open(output, encoding="utf-8") as f:
                rules = [line.strip() for line in f if line.strip()]

        assert rules == ["||*.autos^$denyallow=other.autos"]
        assert stats.denyallow_wildcard_pruned == 1

        matches = [record for record in ledger.records if record.reason == REASON_DENYALLOW_COVERED]
        assert len(matches) == 1


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
        - Zero-pairing pin: wildcard-covers-sub ledger tally ==
          stats.wildcard_covered_sub_pruned == 0 under production-default
          flags (Phase 19 plumbing inertness, D-19-10).
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

        # Phase 19 zero-pairing pin at production-default flags (D-19-10):
        # a different kwarg combination than either shadow leg, so
        # premature wcs firing on the plain default path fails here too.
        wcs_default = summary["by_reason"].get(REASON_WILDCARD_COVERS_SUB, 0)
        assert wcs_default == stats.wildcard_covered_sub_pruned
        assert wcs_default == 0

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
        """Tally denyallow candidates uncapped, then delegate unchanged.

        21-IN-02 purity contract: the tally below invokes
        candidate_factory once, and the delegated super() call invokes
        the same factories again, so every factory passed here must be
        pure and repeatable (never one-shot or side-effecting).
        """
        if reason == REASON_DENYALLOW_COVERED:
            # 21-IN-02: super() re-invokes candidate_factory; keep it pure.
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
        """Tally apex candidates and pairs uncapped, then delegate unchanged.

        21-IN-02 purity contract: the tally below invokes the factories
        once, and the delegated super() call invokes the same factories
        again, so every factory passed here must be pure and repeatable
        (never one-shot or side-effecting).
        """
        if reason == REASON_APEX_COVERS_TLD_WILDCARD:
            # 21-IN-02: super() re-invokes both factories; keep them pure.
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


class WcsTallyingLedger(CappedProofLedger):
    """CappedProofLedger that tallies every wildcard-covers-sub candidate.

    Phase 21 dirb-shadow twin of ApexTallyingLedger (same
    tally-before-delegating pattern): when an incoming decision carries
    REASON_WILDCARD_COVERS_SUB, the candidate facet is resolved
    eagerly and its emitted rule text joins ``wcs_candidates`` BEFORE
    delegating to super() unchanged. Additionally records
    ``(candidate, covering)`` normalized-rule pairs in ``wcs_pairs`` so
    signature element B8 (survivor-coverer membership) can be asserted
    past any sample cap -- capped samples hold at most sample_cap records
    per bucket and are display evidence only. Both sets are uncapped but
    bounded by the wildcard-removal population itself (tiny vs millions
    of input rows). ``normalized_rule`` equals the exact text
    _write_output() emits, so set identity against output-file lines is
    sound.
    """

    def __init__(self, sample_cap: int = DEFAULT_SAMPLE_CAP) -> None:
        super().__init__(sample_cap=sample_cap)
        self.wcs_candidates: set[str] = set()
        self.wcs_pairs: set[tuple[str, str]] = set()

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
        """Tally wcs candidates and pairs uncapped, then delegate unchanged.

        21-IN-02 purity contract: the tally below invokes the factories
        once, and the delegated super() call invokes the same factories
        again, so every factory passed here must be pure and repeatable
        (never one-shot or side-effecting).
        """
        if reason == REASON_WILDCARD_COVERS_SUB:
            # 21-IN-02: super() re-invokes both factories; keep them pure.
            candidate_rule = candidate_factory().normalized_rule
            self.wcs_candidates.add(candidate_rule)
            covering_facet = covering_factory()
            if covering_facet is not None:
                self.wcs_pairs.add((candidate_rule, covering_facet.normalized_rule))
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


# 21-IN-01: PEP 695 bound preserves Wcs/ApexTallyingLedger subclasses for checkers.
def _compile_shadow_leg[LedgerT: CappedProofLedger](
    line_source: Callable[[], Iterable[str]],
    output_path: Path,
    *,
    ledger_factory: Callable[..., LedgerT] | None = None,
    **compile_kwargs: object,
) -> tuple[CompileStats, LedgerT, float]:
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
        assert (
            result.off_ledger.summary()["total_records"]
            == (result.on_ledger.summary()["total_records"])
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

    def test_wildcard_covers_sub_zero_pairing_in_both_shadow_legs(self):
        """Fast fixture twin of the corpus gate's wildcard-covers-sub pins.

        Locks D-19-10 count-identity for the family — the ledger
        by_reason tally equals the paired CompileStats counter — in BOTH
        flag legs through the genuine _run_shadow_comparison() machinery
        via self._result(), both reading 0 until Phase 20 introduces the
        flag-gated emission site. Four separate asserts, one claim each
        (never chained).
        """
        result = self._result()
        off_by_reason = result.off_ledger.summary()["by_reason"]
        on_by_reason = result.on_ledger.summary()["by_reason"]
        wcs_off = off_by_reason.get(REASON_WILDCARD_COVERS_SUB, 0)
        wcs_on = on_by_reason.get(REASON_WILDCARD_COVERS_SUB, 0)
        assert wcs_off == result.off_stats.wildcard_covered_sub_pruned
        assert wcs_off == 0
        assert wcs_on == result.on_stats.wildcard_covered_sub_pruned
        assert wcs_on == 0


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
        - wildcard-covers-sub ledger tally == stats.wildcard_covered_sub_pruned
          == 0 in BOTH legs — Phase 19 plumbing must stay inert until
          Phase 20's flag-gated emission site exists (D-19-10 zero-pairing).
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

        # Phase 19 plumbing-inertness (D-19-10/D-19-01): the
        # wildcard-covers-sub reason/counter pair is wired end-to-end by
        # the evidence spine but has no emission site until Phase 20 —
        # pin tally == counter == 0 in BOTH legs so same-leg firing
        # (invisible to the byte-stability skip-loops below) fails loudly.
        wcs_off = off_by_reason.get(REASON_WILDCARD_COVERS_SUB, 0)
        assert wcs_off == result.off_stats.wildcard_covered_sub_pruned
        assert wcs_off == 0
        wcs_on = on_by_reason.get(REASON_WILDCARD_COVERS_SUB, 0)
        assert wcs_on == result.on_stats.wildcard_covered_sub_pruned
        assert wcs_on == 0

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
        print(f"[D-04 SHADOW] wildcard_covered_sub_pruned={wcs_on:,}")
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


# ----------------------------------------------------------------------
# Shadow manifest writer unit layer (Phase 17, D-17-02/05/06/07/08/09).
#
# The in-gate always-write manifest machinery that 17-03's corpus gate
# and 17-04's canonical run reuse verbatim: evidence computed -> checks
# evaluated into an explicit verdict FIELD -> JSON+MD written ATOMICALLY
# -> only then assertions (D-17-08 write-before-assert ordering, so a
# red run still leaves forensic artifacts recording observed deltas).
#
# Population math implements the D-01 bucket classifier operationalized
# by witness-key label count (research A1): single-label public-suffix
# keys vs multi-label keys. The >=1.0% split bar is INCLUSIVE per
# FA-1/D-17-06 and near-zero populations are a calibration fact handled
# by the divide-by-zero guard, never a verdict input (Pitfall 11).
# ----------------------------------------------------------------------

SHADOW_REPORT_SCHEMA_VERSION: Final[int] = 1
"""Shadow-manifest schema version; consumers fail closed on unknown versions.

House versioned-schema pattern mirroring PROOF_REPORT_SCHEMA_VERSION
(scripts/pruning_proof.py); a future sanctioned bump must move every
consumer pin atomically.
"""

SPLIT_BAR_PERCENT: Final[float] = 1.0
"""Pre-registered D-17-06 reason-split bar (INCLUSIVE >= comparison)."""

BUCKET_SINGLE_LABEL_SUFFIX_APEX: Final[str] = "single_label_suffix_apex"
BUCKET_MULTIPART_SUFFIX_APEX: Final[str] = "multipart_suffix_apex"
"""Manifest population bucket names (RESEARCH E2 inventory verbatim)."""

_FILENAME_STEM_RE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
"""Whitelist for evidence filename stems (WR-08): operator env must not escape."""


def _classify_apex_bucket(key: str) -> str:
    """Classify one witness key into its D-01 apex-form bucket.

    Args:
        key: The wildcard storage key the compiler witnessed (e.g. ``com``
            or ``co.uk``).

    Returns:
        ``single_label_suffix_apex`` for single-label suffix keys,
        ``multipart_suffix_apex`` for multi-label public-suffix keys.

    Raises:
        ValueError: When the key is empty or carries leading/trailing dots.

    Note:
        Research A1 operationalization: witness-key label count is the
        only measurable axis distinguishing D-01's exemplars because
        every removal pair is mechanically same-key under D-16-02 strict
        witnessing. Cites D-17-05 (bucket granularity) and D-17-06
        (inclusive split bar consumed downstream).
    """
    if not key:
        raise ValueError("witness key must be non-empty")
    if key.startswith(".") or key.endswith("."):
        raise ValueError(f"witness key must not have leading/trailing dots: {key!r}")
    if len(key.split(".")) >= 2:
        return BUCKET_MULTIPART_SUFFIX_APEX
    return BUCKET_SINGLE_LABEL_SUFFIX_APEX


def _apex_candidate_storage_key(candidate_rule: str) -> str:
    """Extract the wildcard storage key from emitted apex-candidate text.

    Under D-16-02 strict same-key witnessing every removal pair is
    mechanically (candidate ``||*.K^``, witness ``||K^``), so the key
    parsed from the candidate's emitted text IS the witness key the
    compiler recorded. Strips the ``||*.`` prefix, any ``$...`` modifier
    tail, and the trailing ``^`` anchor.
    """
    body = candidate_rule.removeprefix("||*.")
    body = body.split("$", 1)[0]
    return body.removesuffix("^")


def _summarize_population(
    candidates: set[str],
    pairs: set[tuple[str, str]],
    *,
    capped_samples: Iterable[Mapping[str, object]] = (),
    sample_cap: int = DEFAULT_SAMPLE_CAP,
) -> dict[str, object]:
    """Aggregate an uncapped apex removal population into D-01 buckets.

    Pure aggregation: classifies each uncapped candidate by its witness
    key, computes guarded share percentages (FA-2:
    ``round(count * 100.0 / total, 2)`` with a divide-by-zero guard that
    yields ``0.0`` shares and no split for near-zero populations), and
    places capped sample records into the bucket their candidate key
    classifies into, honoring ``sample_cap`` per bucket.

    Args:
        candidates: Uncapped removed-candidate rule texts
            (``ApexTallyingLedger.apex_candidates``).
        pairs: Uncapped ``(candidate, covering)`` witnesses
            (``ApexTallyingLedger.apex_pairs``). Accepted alongside
            ``candidates`` so callers pass the full ledger witness pair;
            classification needs only candidate keys because pairs are
            mechanically same-key.
        capped_samples: Display-evidence sample dicts already mapped to
            the ``_capped_sample_record`` field names; capped per bucket
            at ``sample_cap`` so bulk rule text never lands in git
            (T-17-01-B).
        sample_cap: Per-bucket display cap (mirrors the ledger's own cap).

    Returns:
        Population dict following RESEARCH E2: total, both buckets with
        count/share_percent/samples, partition boolean, inclusive
        split-bar fields. Asserts nothing -- the partition claim is
        asserted by twins and later by the corpus gate (Pitfall 9 lives
        at the assertion sites).
    """
    single_count = 0
    multipart_count = 0
    for candidate in candidates:
        bucket_name = _classify_apex_bucket(_apex_candidate_storage_key(candidate))
        if bucket_name == BUCKET_SINGLE_LABEL_SUFFIX_APEX:
            single_count += 1
        else:
            multipart_count += 1

    total = len(candidates)

    def _share(count: int) -> float:
        """Guarded FA-2 share percentage."""
        return round(count * 100.0 / total, 2) if total > 0 else 0.0

    bucket_samples: dict[str, list[dict[str, object]]] = {
        BUCKET_SINGLE_LABEL_SUFFIX_APEX: [],
        BUCKET_MULTIPART_SUFFIX_APEX: [],
    }
    for sample_record in capped_samples:
        sample_candidate = str(sample_record.get("candidate_rule", ""))
        sample_bucket = _classify_apex_bucket(_apex_candidate_storage_key(sample_candidate))
        samples_list = bucket_samples[sample_bucket]
        if len(samples_list) < sample_cap:
            samples_list.append(dict(sample_record))

    pure_tld_share_percent = _share(single_count)
    return {
        "total": total,
        "buckets": {
            BUCKET_SINGLE_LABEL_SUFFIX_APEX: {
                "count": single_count,
                "share_percent": _share(single_count),
                "samples": bucket_samples[BUCKET_SINGLE_LABEL_SUFFIX_APEX],
            },
            BUCKET_MULTIPART_SUFFIX_APEX: {
                "count": multipart_count,
                "share_percent": _share(multipart_count),
                "samples": bucket_samples[BUCKET_MULTIPART_SUFFIX_APEX],
            },
        },
        "buckets_partition_total": single_count + multipart_count == total,
        "pure_tld_share_percent": pure_tld_share_percent,
        "split_bar_percent": SPLIT_BAR_PERCENT,
        "reason_split_triggered": pure_tld_share_percent >= SPLIT_BAR_PERCENT,
    }


def _atomic_write_text(path: Path, text: str) -> None:
    """Write text through an atomic sibling temp file.

    Idiom copied from scripts/release_validator.py (test-module standalone
    copy keeps this module import-light per house isolation).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(".tmp")
    with open(temp_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    temp_path.replace(path)


def _atomic_write_json(path: Path, data: Mapping[str, object]) -> None:
    """Write JSON through an atomic sibling temp file (release_validator idiom)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(".tmp")
    with open(temp_path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")
    temp_path.replace(path)


def _default_non_binding_guards() -> dict[str, object]:
    """Return the reserved non-binding proposed-guards slot (D-17-09).

    The real headroom-derived draft over flip-trippable release_validator
    guards is 17-04 scope; this stub only reserves the schema slot and
    marks the block explicitly data-only/non-binding.
    """
    return {
        "binding": False,
        "note": "data-only draft; headroom derivation lands in Phase 17 plan 04",
        "proposals": {},
    }


def _render_shadow_markdown(manifest: Mapping[str, object]) -> str:
    """Render the human-readable MD sibling of a shadow manifest.

    Mirrors render_markdown_summary's list-append + section-header
    structure. Renders values straight from the assembled manifest dict
    so JSON and MD can never drift apart (FA-2 single-formatting-source
    discipline).
    """
    verdict = str(manifest.get("verdict", "unknown"))
    banner = "PASS" if verdict == "pass" else "FAIL"
    # Gate title derives from the report type so the dirb emission carries
    # honest provenance while apex output stays byte-identical (21-02 gate
    # emission; the default report_type keeps the apex title).
    gate_name = "Dirb" if str(manifest.get("report_type")) == "dirb_shadow_gate" else "Apex"
    population = manifest.get("population") or {}
    buckets = population.get("buckets") or {}

    lines: list[str] = [
        f"# {gate_name} Shadow Gate: {banner}",
        "",
        f"- Verdict: {verdict}",
        f"- Schema version: {manifest.get('schema_version')}",
        f"- Report type: {manifest.get('report_type')}",
        f"- Created at: {manifest.get('created_at')}",
        "",
        "## Signature",
    ]
    signature = manifest.get("signature") or {}
    for key, value in signature.items():
        lines.append(f"- {key}: {value}")

    lines.append("")
    lines.append("## Population")
    if str(manifest.get("report_type")) == "dirb_shadow_gate":
        lines.append(f"- Total removals: {population.get('total', 0)}")
        lines.append(f"- Audit expected: {population.get('audit_expected')}")
        divergences = population.get("audit_divergences", [])
        lines.append(f"- Audit divergences: {len(divergences)}")
        for sample_record in population.get("samples", []):
            if isinstance(sample_record, dict):
                lines.append(f"  - sample: {sample_record.get('candidate_rule')}")
            else:
                lines.append(f"  - sample: {sample_record}")
    else:
        lines.append(f"- Total removals: {population.get('total', 0)}")
        lines.append(f"- Pure-TLD share percent: {population.get('pure_tld_share_percent')}")
        lines.append(
            f"- Split bar percent: {population.get('split_bar_percent')} "
            f"(triggered: {population.get('reason_split_triggered')})"
        )
        for bucket_name in (BUCKET_SINGLE_LABEL_SUFFIX_APEX, BUCKET_MULTIPART_SUFFIX_APEX):
            bucket = buckets.get(bucket_name) or {}
            lines.append(
                f"- {bucket_name}: {bucket.get('count', 0)} ({bucket.get('share_percent', 0.0)}%)"
            )
            for sample_record in bucket.get("samples", []):
                lines.append(f"  - sample: {sample_record.get('candidate_rule')}")

    lines.append("")
    lines.append("## Timing")
    timing = manifest.get("timing")
    if timing is None:
        lines.append("- Not measured (timing legs run as separate invocations).")
    else:
        for key, value in timing.items():
            lines.append(f"- {key}: {value}")

    source_health = manifest.get("source_health")
    if source_health is not None:
        lines.append("")
        lines.append("## Source Health")
        for key, value in source_health.items():
            lines.append(f"- {key}: {value}")

    guards = manifest.get("proposed_guards")
    if guards is not None:
        lines.append("")
        lines.append("## Proposed Guards (NON-BINDING)")
        lines.append("- Data-only draft; Phase 18 wires values atomically with the flip.")
        for key, value in guards.items():
            lines.append(f"- {key}: {value}")

    lines.append("")
    return "\n".join(lines)


def _evaluate_and_write_manifest(
    *,
    checks: Mapping[str, tuple[object, object]],
    evidence: Mapping[str, object],
    population: Mapping[str, object],
    output_dir: Path,
    filename_stem: str = "apex-shadow-v1",
    report_type: str = "apex_shadow_gate",
    flags: Mapping[str, object] | None = None,
    identity: Mapping[str, object] | None = None,
    corpus: Mapping[str, object] | None = None,
    timing: Mapping[str, object] | None = None,
    source_health: Mapping[str, object] | None = None,
    proposed_guards: Mapping[str, object] | None = None,
) -> tuple[str, dict[str, object]]:
    """Evaluate checks into an explicit verdict FIELD and always write both siblings.

    D-17-08 write-before-assert ordering: evidence is computed by the
    caller, checks are evaluated into a verdict HERE, and BOTH files are
    written unconditionally before any caller assertion runs -- a red run
    leaves forensic artifacts recording each failing check's observed and
    expected values (no early returns before the writes).

    Args:
        checks: Mapping of check name to ``(observed, expected)`` pairs;
            ``ok`` is computed as equality and drives the verdict.
        evidence: Computed signature evidence serialized under
            ``signature`` (input rows, diff counts, ledger deltas...).
        population: ``_summarize_population()`` output (already rounded
            at assembly per FA-2 so JSON and MD render identical values).
        output_dir: Caller-supplied destination directory; paths derive
            ONLY from this parameter plus the fixed stem (T-17-01-A).
        filename_stem: Versioned stem without extension (D-17-07;
            default ``apex-shadow-v1``, flip-day re-run writes v2).
        report_type: Manifest report discriminator (default
            ``apex_shadow_gate``; the 21-02 dirb gate passes
            ``dirb_shadow_gate`` -- 21-01 staged this parameterization).
        flags: Manifest flag-provenance block (default None keeps the
            legacy apex flag block so apex output stays byte-identical;
            the 21-02 dirb gate passes DIRB_SHADOW_FLAGS).
        identity: Optional provenance block (python/platform/git revision).
        corpus: Optional frozen-corpus provenance incl. manifest SHA-256.
        timing: Optional timing block; serializes as null until measured
            (FA-3 -- this plan reserves the slot only).
        source_health: Optional per-source health summary (D-17-13).
        proposed_guards: Optional non-binding guard draft; defaults to
            the reserved data-only stub (D-17-09).

    Returns:
        ``(verdict, manifest)`` where manifest is the assembled dict both
        siblings were rendered from.
    """
    if not _FILENAME_STEM_RE.fullmatch(filename_stem):
        raise ValueError(f"refusing unsafe filename_stem: {filename_stem!r}")
    if filename_stem.startswith("dirb-shadow-"):
        _probe_path = output_dir / f"{filename_stem}.json"
        if _probe_path.exists() and os.environ.get("DIRB_SHADOW_OVERWRITE") != "1":
            raise RuntimeError(
                f"refusing to overwrite {_probe_path.name}; "
                "set DIRB_SHADOW_DATASET_ID=dirb-shadow-v2 for a new stem "
                "(see Closure Note item 4)"
            )
    evaluated_checks = {
        name: {"observed": observed, "expected": expected, "ok": observed == expected}
        for name, (observed, expected) in checks.items()
    }
    all_ok = all(check["ok"] for check in evaluated_checks.values())
    verdict = "pass" if all_ok else "fail"

    manifest: dict[str, object] = {
        "schema_version": SHADOW_REPORT_SCHEMA_VERSION,
        "report_type": report_type,
        "verdict": verdict,
        "created_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "identity": dict(identity) if identity is not None else None,
        "corpus": dict(corpus) if corpus is not None else None,
        "flags": (
            dict(flags)
            if flags is not None
            else {
                "denyallow_pruning": True,
                "wildcard_apex_pruning_off": False,
                "wildcard_apex_pruning_on": True,
            }
        ),
        "signature": dict(evidence),
        "population": dict(population),
        "checks": evaluated_checks,
        "timing": dict(timing) if timing is not None else None,
        "source_health": dict(source_health) if source_health is not None else None,
        "proposed_guards": (
            dict(proposed_guards) if proposed_guards is not None else _default_non_binding_guards()
        ),
    }

    if str(report_type) == "dirb_shadow_gate":
        _sig_block = manifest.get("signature")
        if isinstance(_sig_block, dict) and "leg_seconds_note" not in _sig_block:
            _sig_block["leg_seconds_note"] = (
                "single-run walls WITH WcsTallyingLedger proof recording; "
                "do not compare against timing medians"
            )
        _tim_block = manifest.get("timing")
        if isinstance(_tim_block, dict):
            _methodology = _tim_block.get("methodology")
            if isinstance(_methodology, str) and "WITHOUT proof ledger" not in _methodology:
                _tim_block["methodology"] = (
                    f"{_methodology}; timing legs run WITHOUT proof ledger "
                    "(direct compile_rules, no WcsTallyingLedger)"
                )

    json_path = output_dir / f"{filename_stem}.json"
    md_path = output_dir / f"{filename_stem}.md"
    _atomic_write_json(json_path, manifest)
    _atomic_write_text(md_path, _render_shadow_markdown(manifest))
    return verdict, manifest


class TestShadowManifestWriter:
    """Unit-proven manifest writer: classifier, population, forensics."""

    def test_classifier_splits_single_label_and_multipart_keys(self):
        """Witness-key label count is the only bucket axis (D-17-05/A1)."""
        assert _classify_apex_bucket("com") == "single_label_suffix_apex"
        assert _classify_apex_bucket("co.uk") == "multipart_suffix_apex"

    def test_classifier_rejects_empty_and_dotted_keys(self):
        """Malformed keys fail loudly instead of misclassifying silently."""
        with pytest.raises(ValueError):
            _classify_apex_bucket("")
        with pytest.raises(ValueError):
            _classify_apex_bucket(".com")
        with pytest.raises(ValueError):
            _classify_apex_bucket("com.")

    def test_population_summary_partitions_counts_and_shares(self):
        """Buckets partition total exactly; shares follow the FA-2 contract."""
        candidates = {"||*.com^", "||*.net^", "||*.org^", "||*.co.uk^"}
        pairs = {(candidate, candidate.replace("*.", "")) for candidate in candidates}
        samples = [
            {
                "decision_id": "d-single",
                "decision_type": "t",
                "fingerprint": "f1",
                "candidate_rule": "||*.com^",
                "candidate_domain": "",
                "covering_rule": "||com^",
                "sample": None,
            },
        ]

        summary = _summarize_population(candidates, pairs, capped_samples=samples)

        assert summary["total"] == 4
        assert summary["buckets"]["single_label_suffix_apex"]["count"] == 3
        assert summary["buckets"]["multipart_suffix_apex"]["count"] == 1
        assert summary["buckets_partition_total"] is True
        assert summary["pure_tld_share_percent"] == 75.0
        assert summary["split_bar_percent"] == 1.0
        assert summary["reason_split_triggered"] is True

    def test_population_summary_places_capped_samples_in_own_bucket(self):
        """Samples ride the bucket their candidate key classifies into."""
        candidates = {"||*.co.uk^"}
        pairs = {("||*.co.uk^", "||co.uk^")}
        samples = [
            {
                "decision_id": "d-multipart",
                "decision_type": "t",
                "fingerprint": "f2",
                "candidate_rule": "||*.co.uk^",
                "candidate_domain": "",
                "covering_rule": "||co.uk^",
                "sample": None,
            },
        ]

        summary = _summarize_population(candidates, pairs, capped_samples=samples)

        bucket_samples = summary["buckets"]["multipart_suffix_apex"]["samples"]
        assert len(bucket_samples) == 1
        assert bucket_samples[0]["candidate_rule"] == "||*.co.uk^"
        assert bucket_samples[0]["covering_rule"] == "||co.uk^"

    def test_population_summary_handles_zero_removal_population(self):
        """Divide-by-zero guard: zero removals yield 0.0 shares and no split."""
        summary = _summarize_population(set(), set())

        assert summary["total"] == 0
        assert summary["buckets"]["single_label_suffix_apex"]["count"] == 0
        assert summary["buckets"]["single_label_suffix_apex"]["share_percent"] == 0.0
        assert summary["buckets"]["multipart_suffix_apex"]["share_percent"] == 0.0
        assert summary["buckets_partition_total"] is True
        assert summary["pure_tld_share_percent"] == 0.0
        assert summary["reason_split_triggered"] is False

    def test_split_bar_boundary_is_inclusive_at_one_percent(self):
        """FA-1/D-17-06: exactly 1.0% triggers; 0.99% does not."""
        at_bar = {f"||*.m{i:03d}.co.uk^" for i in range(99)} | {"||*.com^"}
        below_bar = {f"||*.m{i:04d}.co.uk^" for i in range(9901)} | {
            f"||*.s{i:02d}^" for i in range(99)
        }

        summary_at_bar = _summarize_population(at_bar, set())
        summary_below = _summarize_population(below_bar, set())

        assert summary_at_bar["total"] == 100
        assert summary_at_bar["pure_tld_share_percent"] == 1.0
        assert summary_at_bar["reason_split_triggered"] is True
        assert summary_below["total"] == 10000
        assert summary_below["pure_tld_share_percent"] == 0.99
        assert summary_below["reason_split_triggered"] is False

    def test_writer_round_trip_writes_json_and_md_siblings(self, tmp_path):
        """Passing run leaves schema-versioned JSON+MD twins, no .tmp residue."""
        checks = {"removed_identity": (True, True)}
        evidence = {"input_rows": 67, "added_count": 0, "removed_count": 30}
        population = _summarize_population(
            {"||*.co.uk^"},
            {("||*.co.uk^", "||co.uk^")},
        )

        verdict, manifest = _evaluate_and_write_manifest(
            checks=checks,
            evidence=evidence,
            population=population,
            output_dir=tmp_path,
        )

        json_path = tmp_path / "apex-shadow-v1.json"
        md_path = tmp_path / "apex-shadow-v1.md"

        assert verdict == "pass"
        assert json_path.is_file()
        assert md_path.is_file()
        assert list(tmp_path.glob("*.tmp")) == []

        loaded = json.loads(json_path.read_text(encoding="utf-8"))
        assert loaded["schema_version"] == SHADOW_REPORT_SCHEMA_VERSION
        assert loaded["schema_version"] == 1
        assert loaded["report_type"] == "apex_shadow_gate"
        assert loaded["verdict"] == "pass"
        for key in (
            "created_at",
            "identity",
            "corpus",
            "flags",
            "signature",
            "population",
            "checks",
            "timing",
            "source_health",
            "proposed_guards",
        ):
            assert key in loaded
        assert loaded["identity"] is None
        assert loaded["corpus"] is None
        assert loaded["timing"] is None
        assert loaded["source_health"] is None
        assert isinstance(manifest, dict)

    def test_red_run_still_writes_manifest_with_observed_delta(self, tmp_path):
        """D-17-08 core: a failing check records observed deltas on disk."""
        checks = {"delta_equals_removed": (31, 30)}
        evidence = {"input_rows": 67, "added_count": 0, "removed_count": 30}
        population = _summarize_population(set(), set())

        verdict, _ = _evaluate_and_write_manifest(
            checks=checks,
            evidence=evidence,
            population=population,
            output_dir=tmp_path,
        )

        json_path = tmp_path / "apex-shadow-v1.json"
        md_path = tmp_path / "apex-shadow-v1.md"

        assert verdict == "fail"
        assert json_path.is_file()
        assert md_path.is_file()

        loaded = json.loads(json_path.read_text(encoding="utf-8"))
        assert loaded["verdict"] == "fail"
        assert loaded["checks"]["delta_equals_removed"]["ok"] is False
        assert loaded["checks"]["delta_equals_removed"]["observed"] == 31
        assert loaded["checks"]["delta_equals_removed"]["expected"] == 30

    def test_versioned_stems_do_not_clobber_each_other(self, tmp_path):
        """D-17-07: v1 and v2 stems leave four distinct files in one home."""
        common = dict(
            checks={"check": (True, True)},
            evidence={"removed_count": 0},
            population=_summarize_population(set(), set()),
            output_dir=tmp_path,
        )
        _evaluate_and_write_manifest(**common, filename_stem="apex-shadow-v1")
        _evaluate_and_write_manifest(**common, filename_stem="apex-shadow-v2")

        written = sorted(path.name for path in tmp_path.iterdir())
        assert written == [
            "apex-shadow-v1.json",
            "apex-shadow-v1.md",
            "apex-shadow-v2.json",
            "apex-shadow-v2.md",
        ]

    def test_markdown_sibling_carries_verdict_sections_and_buckets(self):
        """MD mirrors the manifest: banner, signature, buckets, timing, guards."""
        passing_manifest = {
            "schema_version": 1,
            "report_type": "apex_shadow_gate",
            "verdict": "pass",
            "created_at": "2026-08-24T00:00:00Z",
            "signature": {"removed_count": 30},
            "population": {
                "total": 30,
                "buckets": {
                    "single_label_suffix_apex": {
                        "count": 29,
                        "share_percent": 96.67,
                        "samples": [],
                    },
                    "multipart_suffix_apex": {
                        "count": 1,
                        "share_percent": 3.33,
                        "samples": [],
                    },
                },
            },
            "timing": None,
            "source_health": None,
            "proposed_guards": {"binding": False},
        }

        markdown_pass = _render_shadow_markdown(passing_manifest)
        assert "PASS" in markdown_pass
        assert "## Signature" in markdown_pass
        assert "single_label_suffix_apex" in markdown_pass
        assert "multipart_suffix_apex" in markdown_pass
        assert "96.67" in markdown_pass
        assert "not measured" in markdown_pass.lower()
        assert "NON-BINDING" in markdown_pass

        failing_manifest = dict(passing_manifest, verdict="fail")
        markdown_fail = _render_shadow_markdown(failing_manifest)
        assert "FAIL" in markdown_fail

    def test_dirb_population_renders_audit_vocabulary_without_apex_buckets(self):
        """WR-02: dirb Population shows audit counts, never apex None lines."""
        dirb_manifest = {
            "schema_version": 1,
            "report_type": "dirb_shadow_gate",
            "verdict": "fail",
            "created_at": "2026-09-03T15:56:17Z",
            "signature": {"removed_count": 0},
            "population": {
                "total": 0,
                "audit_expected": 0,
                "audit_divergences": ["UNPARSABLE_SKIPPED total=2 samples=[x]"],
                "samples": [],
            },
            "timing": None,
            "source_health": None,
            "proposed_guards": {"binding": False},
        }
        markdown = _render_shadow_markdown(dirb_manifest)
        assert "- Total removals: 0" in markdown
        assert "- Audit expected: 0" in markdown
        assert "- Audit divergences: 1" in markdown
        assert "Pure-TLD share percent" not in markdown
        assert "Split bar percent" not in markdown
        assert "single_label_suffix_apex" not in markdown
        assert "multipart_suffix_apex" not in markdown
        assert "None" not in markdown.split("## Population")[1].split("## Timing")[0]

    def test_default_proposed_guards_carry_explicit_non_binding_marker(self, tmp_path):
        """D-17-09: the reserved slot is explicitly data-only/non-binding."""
        _, manifest = _evaluate_and_write_manifest(
            checks={"check": (True, True)},
            evidence={"removed_count": 0},
            population=_summarize_population(set(), set()),
            output_dir=tmp_path,
        )

        guards = manifest["proposed_guards"]
        assert guards["binding"] is False

    def test_writer_rejects_hostile_filename_stem(self, tmp_path):
        """WR-08: env-controlled stem cannot escape the output dir."""
        for hostile in ("../escape", "a/b"):
            with pytest.raises(ValueError, match="refusing unsafe filename_stem"):
                _evaluate_and_write_manifest(
                    checks={"check": (True, True)},
                    evidence={"removed_count": 0},
                    population=_summarize_population(set(), set()),
                    output_dir=tmp_path,
                    filename_stem=hostile,
                )

    def test_dirb_manifest_carries_leg_and_timing_annotations(self, tmp_path):
        """WR-04: future dirb manifests annotate leg vs timing methodology."""
        _, manifest = _evaluate_and_write_manifest(
            checks={"check": (True, True)},
            evidence={"removed_count": 0, "leg_seconds": {"off": 1.0, "on": 2.0}},
            population={"total": 0, "audit_expected": 0, "audit_divergences": []},
            output_dir=tmp_path,
            filename_stem="dirb-shadow-wr04",
            report_type="dirb_shadow_gate",
            timing={"methodology": "in-gate median-of-N; informational only"},
        )
        signature = manifest["signature"]
        assert isinstance(signature, dict)
        assert "leg_seconds_note" in signature
        assert "WcsTallyingLedger" in str(signature["leg_seconds_note"])
        assert "do not compare" in str(signature["leg_seconds_note"])
        timing = manifest["timing"]
        assert isinstance(timing, dict)
        assert "WITHOUT proof ledger" in str(timing.get("methodology"))

    def test_apex_manifest_carries_no_dirb_annotations(self, tmp_path):
        """WR-04: apex output stays byte-identical without dirb notes."""
        _, manifest = _evaluate_and_write_manifest(
            checks={"check": (True, True)},
            evidence={"removed_count": 0, "leg_seconds": {"off": 1.0, "on": 2.0}},
            population=_summarize_population(set(), set()),
            output_dir=tmp_path,
            filename_stem="apex-shadow-wr04",
            timing={"methodology": "in-gate median-of-N; informational only"},
        )
        assert "leg_seconds_note" not in manifest["signature"]
        assert "WITHOUT proof ledger" not in str(manifest["timing"]["methodology"])


# ----------------------------------------------------------------------
# Pre-freeze source-health reconciliation (Phase 17, D-17-13 / Pitfall P3).
#
# A totally-failed upstream fetch records byte_size=0 / sha256=None in
# the downloader's health report (scripts/downloader.py failed-fetch
# shape), while freeze_dataset's fail-closed consumer
# (_source_health_manifest_entry) refuses any health row lacking
# non-empty identity -- so one dead source would block the entire
# canonical run, contradicting D-17-13's "degraded sources proceed".
# The reconciliation helper bridges producer shape to consumer shape:
# identity is filled FROM the on-disk raw file while status stays
# honestly "failed", the original report is never mutated in place, and
# a reconciled copy is ALWAYS atomically written. OQ#2 resolution: the
# helper lives in this gate layer BY DESIGN -- scripts/benchmark_pipeline.py
# stays byte-untouched, and the twins below import the REAL production
# consumer to prove the contract end-to-end (never a mock).
# ----------------------------------------------------------------------


def _streaming_sha256(path: Path) -> str:
    """Return a chunked SHA-256 hex digest for a file.

    Local mirror of the streaming hashing idiom used by
    scripts/benchmark_pipeline._sha256 and the downloader so file
    identities compare equal across modules regardless of which helper
    computed them (the Stage-A provenance chain hashes the same raw
    files in several places; identical idiom keeps digests comparable).
    """
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _reconcile_source_health_for_freeze(
    report_path: Path,
    raw_dir: Path,
    output_path: Path,
) -> int:
    """Fill failed-no-identity health rows from disk; touch nothing else.

    Closes the D-17-13 hole (research Pitfall P3 / Open Question #2): a
    totally-failed fetch records ``byte_size=0`` and ``sha256=None``
    (scripts/downloader.py failed-fetch shape), which would make the
    fail-closed freezer raise "metadata incomplete" and abort the whole
    canonical run. For every row with ``status == "failed"`` and a falsy
    ``sha256`` whose named raw file EXISTS on disk, this helper fills
    ``byte_size``/``sha256`` FROM that file while keeping ``status``
    honestly ``failed``. Reconciliation bridges producer shape to
    consumer shape WITHOUT weakening the consumer's disk re-verification:
    post-reconciliation content drift still fails closed, proven by
    TestSourceHealthReconciliation against the REAL
    ``_source_health_manifest_entry``.

    Args:
        report_path: Downloader-written source-health JSON report.
        raw_dir: Directory holding the on-disk raw files rows name.
        output_path: Destination for the reconciled COPY (the original
            report file is never mutated in place).

    Returns:
        The number of rows actually filled from disk.

    Raises:
        ValueError: When the document is not a JSON object or lacks a
            list-shaped ``sources`` member -- fail-closed BEFORE any
            filesystem or write activity.

    Note:
        OQ#2 resolution: this helper lives in the gate layer BY DESIGN so
        scripts/benchmark_pipeline.py semantics stay byte-untouched;
        freeze's traversal/symlink/drift fail-closed validation is never
        relaxed here.
    """
    document = json.loads(report_path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("source-health report must be a JSON object")
    sources = document.get("sources")
    if not isinstance(sources, list):
        raise ValueError("source-health report must contain a sources list")

    reconciled_sources = copy.deepcopy(sources)
    filled_count = 0
    for row in reconciled_sources:
        if not isinstance(row, dict):
            continue
        filename = row.get("filename")
        if not isinstance(filename, str) or not filename:
            continue
        if row.get("status") != "failed" or row.get("sha256"):
            continue
        candidate = raw_dir / filename
        if not candidate.is_file():
            continue
        row["byte_size"] = candidate.stat().st_size
        row["sha256"] = _streaming_sha256(candidate)
        filled_count += 1

    # ALWAYS write the full reconciled document atomically, even when zero
    # rows were filled, so callers get one consistent artifact path.
    output_document = dict(document)
    output_document["sources"] = reconciled_sources
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = output_path.with_suffix(".tmp")
    with open(temp_path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(output_document, handle, indent=2, sort_keys=True)
        handle.write("\n")
    temp_path.replace(output_path)
    return filled_count


class TestSourceHealthReconciliation:
    """Fail-closed contract twins for the pre-freeze reconciliation helper.

    Every contract here is proven against the REAL production consumer
    ``scripts.benchmark_pipeline._source_health_manifest_entry``
    (imported deliberately inside the twins): reconciliation must produce
    exactly the shape that consumer accepts while preserving the honest
    ``failed`` status and leaving its disk re-verification fully intact.
    """

    DEAD_FILENAME = "dead.txt"
    LIVE_FILENAME = "live.txt"
    GHOST_FILENAME = "ghost.txt"
    DEAD_BYTES = b"||dead.example^\n||ads.dead.example^\n"
    LIVE_BYTES = b"||live.example^\n"

    def _seed_raw_dir(self, raw_dir: Path) -> None:
        """Create the tiny on-disk raw corpus (dead + live; ghost missing)."""
        raw_dir.mkdir(parents=True, exist_ok=True)
        (raw_dir / self.DEAD_FILENAME).write_bytes(self.DEAD_BYTES)
        (raw_dir / self.LIVE_FILENAME).write_bytes(self.LIVE_BYTES)

    def _failed_row(self, filename: str, url: str) -> dict[str, object]:
        """Return the downloader's exact failed-fetch health shape."""
        return {
            "url": url,
            "filename": filename,
            "status": "failed",
            "changed": False,
            "byte_size": 0,
            "sha256": None,
            "cache_age_seconds": None,
            "failure_reason": "download timed out",
        }

    def _fresh_fetch_row(self, raw_path: Path, filename: str, url: str) -> dict[str, object]:
        """Return a fully-valid fresh_fetch row with correct disk identity."""
        return {
            "url": url,
            "filename": filename,
            "status": "fresh_fetch",
            "changed": True,
            "byte_size": raw_path.stat().st_size,
            "sha256": hashlib.sha256(raw_path.read_bytes()).hexdigest(),
            "cache_age_seconds": None,
            "failure_reason": None,
        }

    def _write_report(
        self,
        report_path: Path,
        sources: list[dict[str, object]],
        *,
        generated_at: str = "2026-08-24T00:00:00Z",
    ) -> None:
        """Write a source-health report carrying an unknown top-level key."""
        document = {
            "generated_at": generated_at,
            "sources": sources,
        }
        report_path.write_text(json.dumps(document), encoding="utf-8")

    def _reconciled_sources(self, output_path: Path) -> list[dict[str, object]]:
        """Load the sources list back out of a reconciled report copy."""
        loaded = json.loads(output_path.read_text(encoding="utf-8"))
        return loaded["sources"]

    def test_reconciled_row_satisfies_real_freeze_consumer(self, tmp_path):
        """THE load-bearing twin: reconciled rows pass the REAL consumer.

        After reconciliation, calling the production
        ``_source_health_manifest_entry`` against the failed-no-identity
        row and its on-disk raw file must succeed WITHOUT raising and must
        return an entry whose source_health_status stays honestly
        ``failed`` with byte_size/sha256 equal to the file's actual
        identity on disk.
        """
        from scripts.benchmark_pipeline import _source_health_manifest_entry

        raw_dir = tmp_path / "raw"
        report_path = tmp_path / "source-health.json"
        output_path = tmp_path / "reconciled-source-health.json"
        self._seed_raw_dir(raw_dir)
        self._write_report(
            report_path,
            [
                self._failed_row(self.DEAD_FILENAME, "https://dead.example/list"),
                self._fresh_fetch_row(
                    raw_dir / self.LIVE_FILENAME,
                    self.LIVE_FILENAME,
                    "https://live.example/list",
                ),
            ],
        )

        fills = _reconcile_source_health_for_freeze(report_path, raw_dir, output_path)

        dead_row = self._reconciled_sources(output_path)[0]
        entry = _source_health_manifest_entry(raw_dir / self.DEAD_FILENAME, dead_row)

        # Exactly the one failed-no-identity row was filled.
        assert fills == 1
        assert entry["source_health_status"] == "failed"
        assert entry["byte_size"] == len(self.DEAD_BYTES)
        assert entry["sha256"] == hashlib.sha256(self.DEAD_BYTES).hexdigest()
        # Our streaming hasher agrees byte-for-byte with production hashing.
        assert entry["sha256"] == _streaming_sha256(raw_dir / self.DEAD_FILENAME)

    def test_failed_status_url_and_extra_keys_survive_byte_for_byte(self, tmp_path):
        """Reconciliation fills ONLY identity; every other key stays verbatim."""
        raw_dir = tmp_path / "raw"
        report_path = tmp_path / "source-health.json"
        output_path = tmp_path / "reconciled-source-health.json"
        self._seed_raw_dir(raw_dir)
        before = self._failed_row(self.DEAD_FILENAME, "https://dead.example/list")
        self._write_report(report_path, [before])

        _reconcile_source_health_for_freeze(report_path, raw_dir, output_path)

        after = self._reconciled_sources(output_path)[0]

        assert after["status"] == "failed"
        assert after["url"] == before["url"]
        assert after["filename"] == before["filename"]
        assert after["failure_reason"] == before["failure_reason"]
        assert after["changed"] is False
        assert after["cache_age_seconds"] is None
        # The ONLY intended changes are the two identity fields.
        assert after["byte_size"] == len(self.DEAD_BYTES)
        assert after["sha256"] == hashlib.sha256(self.DEAD_BYTES).hexdigest()

    def test_valid_identity_rows_pass_through_untouched(self, tmp_path):
        """A fully-valid fresh_fetch row is deep-equal before and after."""
        raw_dir = tmp_path / "raw"
        report_path = tmp_path / "source-health.json"
        output_path = tmp_path / "reconciled-source-health.json"
        self._seed_raw_dir(raw_dir)
        live_before = self._fresh_fetch_row(
            raw_dir / self.LIVE_FILENAME,
            self.LIVE_FILENAME,
            "https://live.example/list",
        )
        live_snapshot = copy.deepcopy(live_before)
        dead_row = self._failed_row(self.DEAD_FILENAME, "https://dead.example/list")
        self._write_report(report_path, [dead_row, live_before])

        fills = _reconcile_source_health_for_freeze(report_path, raw_dir, output_path)

        sources_after = self._reconciled_sources(output_path)
        live_after = next(
            source for source in sources_after if source["filename"] == self.LIVE_FILENAME
        )

        assert fills == 1
        assert live_after == live_snapshot

    def test_missing_raw_file_rows_left_untouched_and_uncounted(self, tmp_path):
        """A failed-no-identity row without an on-disk file passes through.

        freeze_dataset only consults health rows for raw files PRESENT on
        disk, so a ghost row needs no fill and contributes zero to the
        return count.
        """
        raw_dir = tmp_path / "raw"
        report_path = tmp_path / "source-health.json"
        output_path = tmp_path / "reconciled-source-health.json"
        self._seed_raw_dir(raw_dir)
        ghost_row = self._failed_row(self.GHOST_FILENAME, "https://ghost.example/list")
        dead_row = self._failed_row(self.DEAD_FILENAME, "https://dead.example/list")
        self._write_report(report_path, [ghost_row, dead_row])

        fills = _reconcile_source_health_for_freeze(report_path, raw_dir, output_path)

        sources_after = {
            source["filename"]: source for source in self._reconciled_sources(output_path)
        }
        ghost_after = sources_after[self.GHOST_FILENAME]

        assert fills == 1
        assert ghost_after["byte_size"] == 0
        assert ghost_after["sha256"] is None
        assert ghost_after["status"] == "failed"

    def test_post_reconciliation_content_drift_still_fails_closed(self, tmp_path):
        """Reconciliation fills identity; it never relaxes verification.

        Overwriting the raw file AFTER reconciliation must trip the real
        consumer's stat+sha re-verification, proving the helper does not
        launder content drift into the freezer.
        """
        from scripts.benchmark_pipeline import _source_health_manifest_entry

        raw_dir = tmp_path / "raw"
        report_path = tmp_path / "source-health.json"
        output_path = tmp_path / "reconciled-source-health.json"
        self._seed_raw_dir(raw_dir)
        self._write_report(
            report_path,
            [self._failed_row(self.DEAD_FILENAME, "https://dead.example/list")],
        )

        _reconcile_source_health_for_freeze(report_path, raw_dir, output_path)
        dead_raw = raw_dir / self.DEAD_FILENAME
        dead_raw.write_bytes(b"||tampered.after.reconciliation^\n")

        reconciled_dead = self._reconciled_sources(output_path)[0]
        with pytest.raises(ValueError):
            _source_health_manifest_entry(dead_raw, reconciled_dead)

    def test_malformed_report_rejected_before_any_write(self, tmp_path):
        """A document without a sources list fails closed pre-write."""
        raw_dir = tmp_path / "raw"
        report_path = tmp_path / "source-health.json"
        output_path = tmp_path / "reconciled-source-health.json"
        self._seed_raw_dir(raw_dir)
        report_path.write_text(
            json.dumps({"generated_at": "2026-08-24T00:00:00Z"}), encoding="utf-8"
        )

        with pytest.raises(ValueError) as excinfo:
            _reconcile_source_health_for_freeze(report_path, raw_dir, output_path)

        assert "sources" in str(excinfo.value)
        assert not output_path.exists()
        assert list(tmp_path.glob("*.tmp")) == []

    def test_non_dict_document_rejected_before_any_write(self, tmp_path):
        """A non-object JSON document also fails closed pre-write."""
        raw_dir = tmp_path / "raw"
        report_path = tmp_path / "source-health.json"
        output_path = tmp_path / "reconciled-source-health.json"
        self._seed_raw_dir(raw_dir)
        report_path.write_text(json.dumps([{"sources": []}]), encoding="utf-8")

        with pytest.raises(ValueError) as excinfo:
            _reconcile_source_health_for_freeze(report_path, raw_dir, output_path)

        assert "object" in str(excinfo.value)
        assert not output_path.exists()
        assert list(tmp_path.glob("*.tmp")) == []

    def test_atomic_write_hygiene_and_return_count(self, tmp_path):
        """Output parses, unknown keys survive, no .tmp residue, count exact."""
        raw_dir = tmp_path / "raw"
        report_path = tmp_path / "source-health.json"
        output_path = tmp_path / "reconciled-source-health.json"
        self._seed_raw_dir(raw_dir)
        original_text = json.dumps(
            {
                "generated_at": "2026-08-24T00:00:00Z",
                "sources": [self._failed_row(self.DEAD_FILENAME, "https://dead.example/list")],
            }
        )
        report_path.write_text(original_text, encoding="utf-8")

        fills = _reconcile_source_health_for_freeze(report_path, raw_dir, output_path)

        loaded = json.loads(output_path.read_text(encoding="utf-8"))

        assert fills == 1
        assert output_path.is_file()
        assert loaded["generated_at"] == "2026-08-24T00:00:00Z"
        assert list(tmp_path.glob("*.tmp")) == []
        # The ORIGINAL report file is never mutated in place.
        assert report_path.read_text(encoding="utf-8") == original_text


def _derive_proposed_guards(
    *,
    off_rule_count: int,
    on_rule_count: int,
    removed_count: int,
) -> dict[str, object]:
    """Derive the NON-BINDING proposed_guards draft from measured population.

    Pure arithmetic over three ints (D-17-09/D-17-10): every
    flip-trippable release_validator threshold appears with its CURRENT
    imported value plus the expectation the flip implies, while policy
    judgments stay ``None`` because Phase 18 wires values atomically with
    the flip (SAFE-04). The ON leg IS the deterministic post-flip
    preview, so ``minimum_output_rules.proposed`` is simply the ON rule
    count. Near-zero removal populations are healthy calibration facts:
    the headroom window uses a symmetric ``max(R // 2, 1)`` band with a
    zero-clamped low bound (collapses to [0, 1] at R=0), and nothing
    divides by zero (drop ratio guarded on ``off > 0``). Non-flippable
    source-health guards are excluded by construction.

    Asserts NOTHING here -- twins own the arithmetic pins and the corpus
    gate owns the corpus-scale claims.
    """
    headroom_band = max(removed_count // 2, 1)
    first_flip_drop_ratio = round(removed_count / off_rule_count, 6) if off_rule_count > 0 else 0.0
    return {
        "binding": False,
        "note": (
            "data-only draft for Phase 18 review (D-17-09/D-17-10); "
            "values derive from measured population plus headroom and bind nothing"
        ),
        "minimum_output_rules": {
            "current": DEFAULT_MINIMUM_OUTPUT_RULES,
            "proposed": on_rule_count,
            "basis": (
                "the ON leg IS the deterministic post-flip preview; "
                "expected floor = off_rule_count - removed_count"
            ),
        },
        "previous_extreme_drop_ratio": {
            "current": DEFAULT_PREVIOUS_EXTREME_DROP_RATIO,
            "expected_first_post_flip_drop": first_flip_drop_ratio,
            "proposed": None,
        },
        "previous_extreme_increase_ratio": {
            "current": DEFAULT_PREVIOUS_EXTREME_INCREASE_RATIO,
            "expected_first_post_flip_increase": 0.0,
            "proposed": None,
        },
        "previous_moderate_delta_ratio": {
            "current": DEFAULT_PREVIOUS_MODERATE_DELTA_RATIO,
            "observed_first_flip_relative_delta": first_flip_drop_ratio,
            "proposed": None,
        },
        "previous_extreme_absolute_delta": {
            "current": DEFAULT_PREVIOUS_EXTREME_ABSOLUTE_DELTA,
            "observed_first_flip_absolute_rule_delta": removed_count,
            "proposed": None,
        },
        "removal_count_window": {
            "expected_apex_covered_wildcard_pruned": removed_count,
            "headroom_low": max(removed_count - headroom_band, 0),
            "headroom_high": removed_count + headroom_band,
        },
        "counter_ledger_equality": {
            "expected": "tally == counter == removed, both directions",
        },
        "uncertain_keeps_stasis": {
            "expected_delta": 0,
        },
    }


TIMING_BAR_FLOOR_PERCENT: Final[float] = -10.0
"""Inclusive D-17-11 floor on the improvement-form overhead quotient.

Mirrors benchmark.meets_floor(improvement, -10.0) exactly (17-02's
pinned contract in reciprocal form): passes iff raw >= -10.0, i.e.
ON-leg wall-clock <= OFF-leg x 1.10.
"""


def _overhead_percent(off_median: float, on_median: float) -> float:
    """Return the unrounded OFF-to-ON relative quotient (improvement form).

    Sign convention mirrors scripts/benchmark.improvement_percent
    verbatim -- negative means the ON leg is slower -- so the D-17-11
    <=10% overhead bar reads INCLUSIVELY as
    ``value >= TIMING_BAR_FLOOR_PERCENT``, the same predicate as 17-02's
    pinned ``improvement >= -10.0`` floor in reciprocal form. Callers
    MUST evaluate the bar on this RAW value; rounding is display-only
    and can never flip a verdict (TestTimingMergeContract pins the
    hazard direction).

    Raises:
        ValueError: When ``off_median`` is not strictly positive, since
            no relative percent is definable over a zero baseline.
    """
    if off_median <= 0:
        raise ValueError(f"off_median must be > 0 to compute overhead percent (got {off_median!r})")
    return (off_median - on_median) / off_median * 100


def _timing_block_from_reports(
    off_doc: Mapping[str, object],
    on_doc: Mapping[str, object],
    *,
    frozen_digest: str,
    off_sha: str,
    on_sha: str,
) -> dict[str, object]:
    """Merge the canonical timing reports into the manifest timing slot.

    Contract (T-17-03-B): merge proceeds only when BOTH documents carry
    the required fields (ValueError naming the first missing field
    otherwise -- malformed reports fail closed instead of merging
    partially) and BOTH corpus digests equal ``frozen_digest``
    (foreign-corpus evidence forces ``same_corpus False`` AND
    ``passes False`` regardless of medians; overhead stays None). The
    <=10% bar computes on the RAW unrounded improvement-form quotient;
    ``relative_overhead_percent`` stores the display-only 2dp rounding.
    Cross-tie booleans bind each timing leg to THIS gate run's output
    files by comparing the reports' FINAL per_run ``output_sha256``
    against the supplied equivalence-leg digests (absent/empty per_run
    records honestly False). On-leg provenance echoes through
    ``on_compile_flags`` so an OFF report can never masquerade as ON.
    """
    leg_blocks: dict[str, dict[str, object]] = {}
    same_corpus = True
    for leg_name, report in (("off", off_doc), ("on", on_doc)):
        for required_field in ("runs", "durations_seconds", "output_sha256_stable"):
            if required_field not in report:
                raise ValueError(f"timing report missing required field {required_field!r}")
        summary = report.get("summary")
        if not isinstance(summary, Mapping) or "median_seconds" not in summary:
            raise ValueError("timing report missing required field 'summary.median_seconds'")
        corpus = report.get("corpus")
        if not isinstance(corpus, Mapping) or "manifest_sha256" not in corpus:
            raise ValueError("timing report missing required field 'corpus.manifest_sha256'")

        # Typed malformations must take the same named-field ValueError
        # path as missing keys (T-17-03-B): JSON null/dict/string shapes
        # would otherwise raise TypeError inside list()/float(), escaping
        # the gate's ``except ValueError`` and crashing before
        # _evaluate_and_write_manifest lands forensics (D-17-08). The
        # bool rejection mirrors benchmark.py's numeric extraction.
        durations = report["durations_seconds"]
        median_value = summary["median_seconds"]
        if not isinstance(durations, list):
            raise ValueError("timing report field 'durations_seconds' must be a list")
        if isinstance(median_value, bool) or not isinstance(median_value, (int, float)):
            raise ValueError("timing report field 'summary.median_seconds' must be numeric")
        leg_blocks[leg_name] = {
            "runs": report["runs"],
            # Verbatim passthrough keeps absolute seconds for CI budget
            # context (D-17-11); no rounding on this field.
            "durations_seconds": list(durations),
            "median_seconds": round(float(summary["median_seconds"]), 2),
            "output_sha256_stable": report["output_sha256_stable"],
        }
        if corpus["manifest_sha256"] != frozen_digest:
            same_corpus = False

    def _cross_tie(report: Mapping[str, object], expected_sha: str) -> bool:
        """True when the report's final per-run digest equals the gate leg's."""
        per_run = report.get("per_run")
        if not isinstance(per_run, list) or not per_run:
            return False
        last_entry = per_run[-1]
        if not isinstance(last_entry, Mapping):
            return False
        return bool(last_entry.get("output_sha256") == expected_sha)

    raw_overhead_percent: float | None = None
    passes = False
    if same_corpus:
        off_median = float(off_doc["summary"]["median_seconds"])
        on_median = float(on_doc["summary"]["median_seconds"])
        raw_overhead_percent = _overhead_percent(off_median, on_median)
        # Inclusive <=10% overhead bar evaluated ONLY on the raw quotient.
        passes = raw_overhead_percent >= TIMING_BAR_FLOOR_PERCENT

    return {
        "methodology": "median-of-3 per leg, one kind per invocation",
        "off": leg_blocks["off"],
        "on": leg_blocks["on"],
        "relative_overhead_percent": (
            round(raw_overhead_percent, 2) if raw_overhead_percent is not None else None
        ),
        "bar_percent": 10.0,
        "passes": passes,
        "same_corpus": same_corpus,
        "cross_tie_off": _cross_tie(off_doc, off_sha),
        "cross_tie_on": _cross_tie(on_doc, on_sha),
        "on_compile_flags": on_doc.get("compile_flags"),
    }


# ----------------------------------------------------------------------
# Proposed-guards derivation + timing-merge contract (Phase 17, D-17-09
# / D-17-10 / D-17-11 / FA-2 / FA-3).
#
# _derive_proposed_guards is pure arithmetic over three ints producing
# the E2-shaped NON-BINDING draft over exactly the five flip-trippable
# release_validator thresholds (source-health guards are NOT
# flip-trippable and must never appear). _timing_block_from_reports
# merges the canonical benchmark timing reports with precision
# boundaries pinned here: the <=10% bar evaluates INCLUSIVELY on the
# RAW unrounded quotient (mirroring 17-02's pinned improvement >= -10.0
# floor in reciprocal form), rounding is display-only and can never
# flip a verdict, foreign-corpus evidence can never bless the run, and
# malformed reports fail closed naming the missing field instead of
# merging partially.
# ----------------------------------------------------------------------


class TestProposedGuardsDraft:
    """Arithmetic pins for the headroom-banded proposed_guards draft."""

    def test_representative_population_derives_window_and_ratios(self):
        """off=1000/on=970/removed=30 pins every derived field."""
        guards = _derive_proposed_guards(
            off_rule_count=1000,
            on_rule_count=970,
            removed_count=30,
        )

        minimum = guards["minimum_output_rules"]
        drop = guards["previous_extreme_drop_ratio"]
        absolute = guards["previous_extreme_absolute_delta"]
        window = guards["removal_count_window"]

        assert minimum["proposed"] == 970
        assert drop["expected_first_post_flip_drop"] == 0.03
        assert absolute["observed_first_flip_absolute_rule_delta"] == 30
        assert window["expected_apex_covered_wildcard_pruned"] == 30
        assert window["headroom_low"] == 15
        assert window["headroom_high"] == 45

    def test_near_zero_population_collapses_window_to_zero_one(self):
        """R=0 is a healthy calibration fact: clamped low, unit-high band."""
        guards = _derive_proposed_guards(
            off_rule_count=1000,
            on_rule_count=1000,
            removed_count=0,
        )

        window = guards["removal_count_window"]

        assert window["headroom_low"] == 0
        assert window["headroom_high"] == 1
        assert guards["previous_extreme_drop_ratio"]["expected_first_post_flip_drop"] == 0.0

    def test_single_removal_clamps_low_bound_at_zero(self):
        """R=1 keeps the max(R//2, 1) band without going negative."""
        guards = _derive_proposed_guards(
            off_rule_count=1000,
            on_rule_count=999,
            removed_count=1,
        )

        window = guards["removal_count_window"]

        assert window["headroom_low"] == 0
        assert window["headroom_high"] == 2

    def test_block_is_explicitly_non_binding_data_only(self):
        """D-17-09: binding False + note deferring policy to Phase 18."""
        guards = _derive_proposed_guards(
            off_rule_count=10,
            on_rule_count=9,
            removed_count=1,
        )

        assert guards["binding"] is False
        assert "data-only" in str(guards["note"])
        assert "Phase 18" in str(guards["note"])

    def test_all_five_release_validator_thresholds_carry_current_values(self):
        """Every flip-trippable constant appears via the imported name."""
        guards = _derive_proposed_guards(
            off_rule_count=10,
            on_rule_count=9,
            removed_count=1,
        )

        assert guards["minimum_output_rules"]["current"] == DEFAULT_MINIMUM_OUTPUT_RULES
        assert (
            guards["previous_extreme_drop_ratio"]["current"] == DEFAULT_PREVIOUS_EXTREME_DROP_RATIO
        )
        assert (
            guards["previous_extreme_increase_ratio"]["current"]
            == DEFAULT_PREVIOUS_EXTREME_INCREASE_RATIO
        )
        assert (
            guards["previous_moderate_delta_ratio"]["current"]
            == DEFAULT_PREVIOUS_MODERATE_DELTA_RATIO
        )
        assert (
            guards["previous_extreme_absolute_delta"]["current"]
            == DEFAULT_PREVIOUS_EXTREME_ABSOLUTE_DELTA
        )

    def test_no_non_flippable_source_health_guards_appear(self):
        """Source-health guards are not flip-trippable; they never surface."""
        guards = _derive_proposed_guards(
            off_rule_count=10,
            on_rule_count=9,
            removed_count=1,
        )
        serialized = json.dumps(guards)

        assert "source_failed_stale_minimum" not in serialized
        assert "source_fallback_stale_minimum" not in serialized
        assert "source_hard_ratio" not in serialized

    def test_counter_ledger_equality_and_uncertain_stasis_expectations(self):
        """Equality/stasis expectation texts ride the draft verbatim."""
        guards = _derive_proposed_guards(
            off_rule_count=10,
            on_rule_count=9,
            removed_count=1,
        )
        equality_expectation = guards["counter_ledger_equality"]["expected"]

        assert equality_expectation == "tally == counter == removed, both directions"
        assert guards["uncertain_keeps_stasis"]["expected_delta"] == 0


class TestTimingMergeContract:
    """Precision-boundary twins for the timing-report merge contract."""

    FROZEN_DIGEST = "f" * 64
    OFF_FINAL_SHA = "a" * 64
    ON_FINAL_SHA = "b" * 64

    @staticmethod
    def _timing_document(
        *,
        median: float,
        final_sha: str,
        digest: str,
        compile_flags: dict[str, object] | None = None,
    ) -> dict[str, object]:
        """Build one synthetic benchmark timing report document."""
        per_run: list[dict[str, object]] = [
            {
                "index": index + 1,
                "elapsed_seconds": median,
                "output_byte_size": 43_000_000,
                "output_sha256": final_sha,
            }
            for index in range(3)
        ]
        document: dict[str, object] = {
            "schema_version": 1,
            "report_type": "corpus_benchmark",
            "mode": "timing",
            "created_at": "2026-08-24T00:00:00Z",
            "corpus": {
                "dir": "reports/benchmarks/frozen/apex-shadow-v1/raw",
                "manifest_sha256": digest,
            },
            "runs": 3,
            "durations_seconds": [median - 0.5, median, median + 0.5],
            "summary": {
                "min_seconds": median - 0.5,
                "median_seconds": median,
                "max_seconds": median + 0.5,
            },
            "output_sha256_stable": True,
            "per_run": per_run,
        }
        if compile_flags is not None:
            document["compile_flags"] = compile_flags
        return document

    def _merged_block(
        self,
        *,
        off_median: float,
        on_median: float,
        off_digest: str | None = None,
        on_digest: str | None = None,
    ) -> dict[str, object]:
        """Merge two synthetic reports through the contract under test."""
        off_doc = self._timing_document(
            median=off_median,
            final_sha=self.OFF_FINAL_SHA,
            digest=off_digest or self.FROZEN_DIGEST,
        )
        on_doc = self._timing_document(
            median=on_median,
            final_sha=self.ON_FINAL_SHA,
            digest=on_digest or self.FROZEN_DIGEST,
            compile_flags={"wildcard_apex_pruning": True},
        )
        return _timing_block_from_reports(
            off_doc,
            on_doc,
            frozen_digest=self.FROZEN_DIGEST,
            off_sha=self.OFF_FINAL_SHA,
            on_sha=self.ON_FINAL_SHA,
        )

    def test_overhead_percent_is_reciprocal_of_improvement_form(self):
        """ON slower by 10% reads as -10.0 (benchmark.improvement_percent mirror)."""
        assert _overhead_percent(100.0, 110.0) == pytest.approx(-10.0, abs=1e-9)

    def test_overhead_percent_positive_when_on_leg_faster(self):
        """ON faster by 10% reads as +10.0 -- reciprocal direction preserved."""
        assert _overhead_percent(100.0, 90.0) == pytest.approx(10.0, abs=1e-9)

    def test_non_positive_off_median_raises_divide_by_zero_guard(self):
        """Zero/negative OFF medians have no definable overhead percent."""
        with pytest.raises(ValueError):
            _overhead_percent(0.0, 110.0)
        with pytest.raises(ValueError):
            _overhead_percent(-5.0, 90.0)

    def test_inclusive_boundary_evaluates_on_raw_unrounded_value(self):
        """Raw -10.0 passes INCLUSIVELY (D-17-11 / 17-02 floor mirror)."""
        at_bar = self._merged_block(off_median=100.0, on_median=110.0)

        assert at_bar["passes"] is True
        assert at_bar["relative_overhead_percent"] == -10.0

    def test_rounding_can_never_flip_verdict_direction(self):
        """FA-2 hazard pin: raw -10.004 fails while DISPLAY rounds to -10.0."""
        over_bar = self._merged_block(off_median=100.0, on_median=110.004)

        assert over_bar["passes"] is False
        assert over_bar["relative_overhead_percent"] == -10.0

    def test_foreign_corpus_digest_never_blesses_the_run(self):
        """A mismatched corpus digest voids overhead AND the pass verdict."""
        block = self._merged_block(
            off_median=100.0,
            on_median=105.0,
            on_digest="e" * 64,
        )

        assert block["same_corpus"] is False
        assert block["passes"] is False
        assert block["relative_overhead_percent"] is None

    @pytest.mark.parametrize(
        ("key_path", "label"),
        [
            pytest.param(("runs",), "runs", id="missing-runs"),
            pytest.param(("durations_seconds",), "durations_seconds", id="missing-durations"),
            pytest.param(
                ("summary", "median_seconds"), "median_seconds", id="missing-summary-median"
            ),
            pytest.param(
                ("output_sha256_stable",), "output_sha256_stable", id="missing-stable-flag"
            ),
            pytest.param(
                ("corpus", "manifest_sha256"), "manifest_sha256", id="missing-corpus-digest"
            ),
        ],
    )
    def test_missing_required_keys_fail_closed_naming_the_field(self, key_path, label):
        """Malformed reports fail closed naming the first missing field."""
        off_doc = self._timing_document(
            median=100.0,
            final_sha=self.OFF_FINAL_SHA,
            digest=self.FROZEN_DIGEST,
        )
        on_doc = self._timing_document(
            median=105.0,
            final_sha=self.ON_FINAL_SHA,
            digest=self.FROZEN_DIGEST,
            compile_flags={"wildcard_apex_pruning": True},
        )
        if len(key_path) == 1:
            del off_doc[key_path[0]]
        else:
            del off_doc[key_path[0]][key_path[1]]

        with pytest.raises(ValueError) as excinfo:
            _timing_block_from_reports(
                off_doc,
                on_doc,
                frozen_digest=self.FROZEN_DIGEST,
                off_sha=self.OFF_FINAL_SHA,
                on_sha=self.ON_FINAL_SHA,
            )

        assert label in str(excinfo.value)

    def test_missing_required_key_in_on_report_also_fails_closed(self):
        """Both documents are validated, not just the OFF leg."""
        off_doc = self._timing_document(
            median=100.0,
            final_sha=self.OFF_FINAL_SHA,
            digest=self.FROZEN_DIGEST,
        )
        on_doc = self._timing_document(
            median=105.0,
            final_sha=self.ON_FINAL_SHA,
            digest=self.FROZEN_DIGEST,
        )
        del on_doc["output_sha256_stable"]

        with pytest.raises(ValueError) as excinfo:
            _timing_block_from_reports(
                off_doc,
                on_doc,
                frozen_digest=self.FROZEN_DIGEST,
                off_sha=self.OFF_FINAL_SHA,
                on_sha=self.ON_FINAL_SHA,
            )

        assert "output_sha256_stable" in str(excinfo.value)

    @pytest.mark.parametrize(
        ("leg", "key_path", "bad_value", "label"),
        [
            pytest.param(
                "off",
                ("durations_seconds",),
                None,
                "durations_seconds",
                id="off-null-durations",
            ),
            pytest.param(
                "on",
                ("durations_seconds",),
                {"run-1": 99.0},
                "durations_seconds",
                id="on-object-durations",
            ),
            pytest.param(
                "off",
                ("summary", "median_seconds"),
                None,
                "median_seconds",
                id="off-null-median",
            ),
            pytest.param(
                "on",
                ("summary", "median_seconds"),
                "fast",
                "median_seconds",
                id="on-string-median",
            ),
            pytest.param(
                "off",
                ("summary", "median_seconds"),
                True,
                "median_seconds",
                id="off-bool-median",
            ),
        ],
    )
    def test_mistyped_required_values_fail_closed_naming_the_field(
        self,
        leg: str,
        key_path: tuple[str, ...],
        bad_value: object,
        label: str,
    ) -> None:
        """Typed malformations raise the named-field ValueError, never TypeError.

        JSON-shaped null/object/string values would raise TypeError inside
        list()/float(); that escapes the gate's ``except ValueError`` and
        crashes before _evaluate_and_write_manifest writes forensics --
        exactly the red-run-without-manifest failure D-17-08 forbids.
        Both legs are validated, not just OFF.
        """
        off_doc = self._timing_document(
            median=100.0,
            final_sha=self.OFF_FINAL_SHA,
            digest=self.FROZEN_DIGEST,
        )
        on_doc = self._timing_document(
            median=105.0,
            final_sha=self.ON_FINAL_SHA,
            digest=self.FROZEN_DIGEST,
            compile_flags={"wildcard_apex_pruning": True},
        )
        mutated = off_doc if leg == "off" else on_doc
        if len(key_path) == 1:
            mutated[key_path[0]] = bad_value
        else:
            mutated[key_path[0]][key_path[1]] = bad_value

        with pytest.raises(ValueError) as excinfo:
            _timing_block_from_reports(
                off_doc,
                on_doc,
                frozen_digest=self.FROZEN_DIGEST,
                off_sha=self.OFF_FINAL_SHA,
                on_sha=self.ON_FINAL_SHA,
            )

        assert label in str(excinfo.value)

    def test_cross_tie_booleans_bind_to_equivalence_leg_outputs(self):
        """Cross-ties compare each report's FINAL per_run sha to gate legs."""
        matching = self._merged_block(off_median=100.0, on_median=110.0)

        assert matching["cross_tie_off"] is True
        assert matching["cross_tie_on"] is True

        off_mismatched = self._timing_document(
            median=100.0,
            final_sha="c" * 64,
            digest=self.FROZEN_DIGEST,
        )
        on_doc = self._timing_document(
            median=110.0,
            final_sha=self.ON_FINAL_SHA,
            digest=self.FROZEN_DIGEST,
            compile_flags={"wildcard_apex_pruning": True},
        )
        mismatched_block = _timing_block_from_reports(
            off_mismatched,
            on_doc,
            frozen_digest=self.FROZEN_DIGEST,
            off_sha=self.OFF_FINAL_SHA,
            on_sha=self.ON_FINAL_SHA,
        )

        assert mismatched_block["cross_tie_off"] is False
        assert mismatched_block["cross_tie_on"] is True

    def test_absent_per_run_records_cross_tie_false_honestly(self):
        """Absent per-run evidence records cross-tie False, never True-ish."""
        off_doc = self._timing_document(
            median=100.0,
            final_sha=self.OFF_FINAL_SHA,
            digest=self.FROZEN_DIGEST,
        )
        del off_doc["per_run"]
        on_doc = self._timing_document(
            median=110.0,
            final_sha=self.ON_FINAL_SHA,
            digest=self.FROZEN_DIGEST,
            compile_flags={"wildcard_apex_pruning": True},
        )
        block = _timing_block_from_reports(
            off_doc,
            on_doc,
            frozen_digest=self.FROZEN_DIGEST,
            off_sha=self.OFF_FINAL_SHA,
            on_sha=self.ON_FINAL_SHA,
        )

        assert block["cross_tie_off"] is False
        assert block["cross_tie_on"] is True

    def test_block_assembly_carries_methodology_passthrough_and_provenance(self):
        """E2 inventory fields assemble verbatim from the source reports."""
        off_doc = self._timing_document(
            median=123.456789,
            final_sha=self.OFF_FINAL_SHA,
            digest=self.FROZEN_DIGEST,
        )
        on_doc = self._timing_document(
            median=130.0,
            final_sha=self.ON_FINAL_SHA,
            digest=self.FROZEN_DIGEST,
            compile_flags={"wildcard_apex_pruning": True},
        )
        block = _timing_block_from_reports(
            off_doc,
            on_doc,
            frozen_digest=self.FROZEN_DIGEST,
            off_sha=self.OFF_FINAL_SHA,
            on_sha=self.ON_FINAL_SHA,
        )

        assert "median-of-3" in str(block["methodology"])
        assert block["bar_percent"] == 10.0
        assert block["off"]["runs"] == 3
        # durations_seconds pass through VERBATIM (absolute seconds kept).
        assert block["off"]["durations_seconds"] == off_doc["durations_seconds"]
        # Median display rounding is 2dp at assembly time (FA-2).
        assert block["off"]["median_seconds"] == 123.46
        assert block["on"]["median_seconds"] == 130.0
        assert block["off"]["output_sha256_stable"] is True
        assert block["on_compile_flags"] == {"wildcard_apex_pruning": True}


# ----------------------------------------------------------------------
# Apex full-corpus shadow gate over the FROZEN dataset (Phase 17,
# SAFE-03).
#
# THE production-flip instrument: streams ONLY the frozen hash-pinned
# dataset (reports/benchmarks/frozen/<id>/raw/) -- never lists/_raw --
# so corpus.manifest_sha256 in the emitted manifest pins exactly what
# ran (research Pitfall 4). Asserts the placement-specific signature
# S1-S9 one-claim-per-assert with the DELTA direction on ledger totals
# (16-RESEARCH Derived Implication 3: a to-be-pruned wildcard has no
# OFF-leg record) and uncertain-keeps EQUALITY stasis (Derived
# Implication 4), then emits the versioned verdict-bearing manifest
# BEFORE any claim is checked (D-17-08 write-before-assert) so even a
# red run leaves named-check forensics Phase 18 can read.
#
# Timing merges from the canonical benchmark reports ONLY when both
# parse AND their corpus digests match this frozen dataset; otherwise a
# NAMED FAILING timing_evidence_present check enters the verdict inputs
# -- a pass verdict is structurally unreachable without merged green
# timing (checker W-2: never silently passing). The ~25-minute corpus
# execution belongs to 17-04's canonical run; scheduled CI never sees
# it thanks to the slow marker + --run-slow double gate (D-17-01).
# ----------------------------------------------------------------------

APEX_SHADOW_DATASET_ID: Final[str] = os.environ.get("APEX_SHADOW_DATASET_ID", "apex-shadow-v1")
"""Versioned frozen-dataset id (D-17-07): env-overridable so Phase 18's
flip-day re-run writes -v2 manifests without editing this gate."""

REPO_ROOT: Final[Path] = Path(__file__).resolve().parent.parent

FROZEN_CORPUS_DIR: Final[Path] = (
    REPO_ROOT / "reports" / "benchmarks" / "frozen" / APEX_SHADOW_DATASET_ID / "raw"
)
FROZEN_MANIFEST_PATH: Final[Path] = (
    REPO_ROOT / "reports" / "benchmarks" / "frozen" / APEX_SHADOW_DATASET_ID / "manifest.json"
)
SHADOW_GATE_OUTPUT_DIR: Final[Path] = REPO_ROOT / "reports" / "shadow-gate"
TIMING_OFF_REPORT_PATH: Final[Path] = (
    REPO_ROOT / "reports" / "benchmarks" / "runs" / "apex-off.json"
)
TIMING_ON_REPORT_PATH: Final[Path] = REPO_ROOT / "reports" / "benchmarks" / "runs" / "apex-on.json"

FROZEN_CORPUS_PRESENT: Final[bool] = FROZEN_CORPUS_DIR.is_dir() and any(
    FROZEN_CORPUS_DIR.glob("*.txt")
)

_FROZEN_SKIP_REASON: Final[str] = (
    f"frozen dataset reports/benchmarks/frozen/{APEX_SHADOW_DATASET_ID}/raw is absent; "
    "Stage-A it first: py -3.14 -m scripts.downloader --sources config/sources.txt "
    "--outdir lists/_raw --cache .cache --health-report reports/source-health.json && "
    "py -3.14 -m scripts.benchmark_pipeline freeze --input-dir lists/_raw "
    "--source-health-report reports/source-health.json "
    f"--dataset-id {APEX_SHADOW_DATASET_ID}"
)

DIRB_SHADOW_DATASET_ID: Final[str] = os.environ.get("DIRB_SHADOW_DATASET_ID", "dirb-shadow-v1")
"""Versioned frozen-dataset id (D-17-07 pattern): env-overridable so a
flip-day re-run writes -v2 manifests without editing this gate. The set
stays natural-only per D-21-09 (no seeded pairs); dirb code paths never
import apex path symbols and never write under the apex frozen dir
(T-21-06)."""

DIRB_FROZEN_CORPUS_DIR: Final[Path] = (
    REPO_ROOT / "reports" / "benchmarks" / "frozen" / DIRB_SHADOW_DATASET_ID / "raw"
)
DIRB_FROZEN_MANIFEST_PATH: Final[Path] = (
    REPO_ROOT / "reports" / "benchmarks" / "frozen" / DIRB_SHADOW_DATASET_ID / "manifest.json"
)
DIRB_TIMING_OFF_REPORT_PATH: Final[Path] = (
    REPO_ROOT / "reports" / "benchmarks" / "runs" / "dirb-off.json"
)
DIRB_TIMING_ON_REPORT_PATH: Final[Path] = (
    REPO_ROOT / "reports" / "benchmarks" / "runs" / "dirb-on.json"
)

DIRB_FROZEN_CORPUS_PRESENT: Final[bool] = DIRB_FROZEN_CORPUS_DIR.is_dir() and any(
    DIRB_FROZEN_CORPUS_DIR.glob("*.txt")
)

DIRB_FROZEN_SKIP_REASON: Final[str] = (
    f"frozen dataset reports/benchmarks/frozen/{DIRB_SHADOW_DATASET_ID}/raw is absent; "
    "Stage-A it first: py -3.14 -m scripts.downloader --sources config/sources.txt "
    "--outdir lists/_raw --cache .cache --health-report reports/source-health.json && "
    "py -3.14 -m scripts.benchmark_pipeline freeze --input-dir lists/_raw "
    "--source-health-report reports/source-health.json "
    f"--dataset-id {DIRB_SHADOW_DATASET_ID}"
)

DIRB_SHADOW_FLAGS: Final[dict[str, object]] = {
    "denyallow_pruning": True,
    "wildcard_apex_pruning": False,
    "wildcard_covers_subs_pruning_off": False,
    "wildcard_covers_subs_pruning_on": True,
}
"""Manifest flag-provenance block for the dirb gate (21-02 emission).

Mirrors the RESEARCH dirb manifest skeleton: both legs run production
defaults except the ON leg adding only wildcard_covers_subs_pruning, so
the dirb flag is the sole mover. Passed as the writer's ``flags`` arg;
apex callers omit it and keep the legacy apex block byte-identical."""

DEGRADED_SOURCE_STATUSES: Final[frozenset[str]] = frozenset(
    {"failed", "stale_cache", "fallback_cache"}
)


def _load_frozen_corpus_summary(manifest_path: Path) -> dict[str, object]:
    """Summarize the frozen-dataset manifest for source-health evidence.

    Tallies per-source ``source_health_status`` values (D-17-13 honesty:
    degradation stays visible in the manifest), computes
    ``degraded_sources`` as the failed + stale_cache + fallback_cache
    sum, and derives file_count/total_bytes from per-source sums. A
    missing manifest degrades gracefully to a ``present: False`` summary
    (the slow gate's skipif independently requires the raw dir); a
    manifest that EXISTS must parse -- malformed frozen state raises
    instead of silently weakening provenance.
    """
    if not manifest_path.is_file():
        return {
            "present": False,
            "file_count": 0,
            "total_bytes": 0,
            "totals_by_status": {},
            "degraded_sources": 0,
        }
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    sources = document.get("sources")
    if not isinstance(sources, list):
        raise ValueError(f"frozen manifest has no sources list: {manifest_path}")
    totals_by_status: dict[str, int] = {}
    file_count = 0
    total_bytes = 0
    for source in sources:
        if not isinstance(source, dict):
            continue
        file_count += 1
        byte_size = source.get("byte_size")
        if isinstance(byte_size, int) and not isinstance(byte_size, bool):
            total_bytes += byte_size
        status = str(source.get("source_health_status", "unknown"))
        totals_by_status[status] = totals_by_status.get(status, 0) + 1
    return {
        "present": True,
        "file_count": file_count,
        "total_bytes": total_bytes,
        "totals_by_status": totals_by_status,
        "degraded_sources": sum(
            totals_by_status.get(status_name, 0) for status_name in DEGRADED_SOURCE_STATUSES
        ),
    }


class ApexCorpusLegs(NamedTuple):
    """Paired apex-flag legs over the FROZEN dataset plus output digests.

    off_output_sha256/on_output_sha256 capture each leg's real output
    FILE digest BEFORE the temporary workdir tears down, giving S9 the
    cross-process comparand that the benchmark timing reports'
    per_run[].output_sha256 values must equal (SC3/S9 cross-tie without
    extra compiles).
    """

    off_lines: list[str]
    on_lines: list[str]
    off_stats: CompileStats
    on_stats: CompileStats
    off_ledger: ApexTallyingLedger
    on_ledger: ApexTallyingLedger
    off_seconds: float
    on_seconds: float
    off_output_sha256: str
    on_output_sha256: str


class DirbCorpusLegs(NamedTuple):
    """Paired dirb-flag legs over fixture or frozen lines plus digests.

    Same 10-field shape as ApexCorpusLegs, typed to WcsTallyingLedger so
    the uncapped ``wcs_candidates``/``wcs_pairs`` witnesses travel with
    each leg. The shas hash each leg's real output FILE before teardown
    for the determinism cross-tie. Fresh-iterator discipline rides
    _compile_shadow_leg via _shadow_line_factory.
    """

    off_lines: list[str]
    on_lines: list[str]
    off_stats: CompileStats
    on_stats: CompileStats
    off_ledger: WcsTallyingLedger
    on_ledger: WcsTallyingLedger
    off_seconds: float
    on_seconds: float
    off_output_sha256: str
    on_output_sha256: str


def _run_apex_corpus_legs(
    line_source: Callable[[], Iterable[str]],
    workdir: Path,
) -> ApexCorpusLegs:
    """Run the apex OFF/ON shadow legs over the frozen dataset in-process.

    The OFF leg passes NO extra compile kwargs (production defaults:
    denyallow_pruning=True, wildcard_apex_pruning=False); the ON leg adds
    ONLY ``wildcard_apex_pruning=True`` so the apex flag is the sole
    moving part (D-16-01). compiler.clear_caches() runs BETWEEN legs
    because the module LRU caches are process-global and conftest only
    clears between tests (research Pitfall 6). Each leg's output FILE is
    hashed BEFORE ``workdir`` teardown so both digests survive for the
    S9 cross-tie assertions. Fresh-iterator discipline rides
    _compile_shadow_leg via _shadow_line_factory.
    """
    off_output = workdir / "apex_off.txt"
    off_stats, off_ledger, off_seconds = _compile_shadow_leg(
        line_source,
        off_output,
        ledger_factory=ApexTallyingLedger,
    )
    off_lines = _read_output_lines(off_output)
    off_output_sha256 = _streaming_sha256(off_output)

    # Cache hygiene between legs: the ON leg must not inherit warmed
    # domain/TLD caches from the OFF leg.
    clear_caches()

    on_output = workdir / "apex_on.txt"
    on_stats, on_ledger, on_seconds = _compile_shadow_leg(
        line_source,
        on_output,
        ledger_factory=ApexTallyingLedger,
        wildcard_apex_pruning=True,
    )
    on_lines = _read_output_lines(on_output)
    on_output_sha256 = _streaming_sha256(on_output)

    return ApexCorpusLegs(
        off_lines=off_lines,
        on_lines=on_lines,
        off_stats=off_stats,
        on_stats=on_stats,
        off_ledger=off_ledger,
        on_ledger=on_ledger,
        off_seconds=off_seconds,
        on_seconds=on_seconds,
        off_output_sha256=off_output_sha256,
        on_output_sha256=on_output_sha256,
    )


def _run_dirb_corpus_legs(
    line_source: Callable[[], Iterable[str]],
    workdir: Path,
) -> DirbCorpusLegs:
    """Run the dirb OFF/ON shadow legs over caller-supplied lines in-process.

    The OFF leg passes NO extra compile kwargs (production defaults:
    denyallow_pruning=True, wildcard_apex_pruning=False,
    wildcard_covers_subs_pruning=False); the ON leg adds ONLY
    ``wildcard_covers_subs_pruning=True`` so the dirb flag is the sole
    moving part (D-21-02 substrate staging). compiler.clear_caches() runs
    BETWEEN legs because the module LRU caches are process-global and
    conftest only clears between tests (research Pitfall 6). Each leg's
    output FILE is hashed BEFORE ``workdir`` teardown so both digests
    survive for the determinism cross-tie. Fresh-iterator discipline rides
    _compile_shadow_leg via _shadow_line_factory; both legs tally through
    WcsTallyingLedger with the shared 10,000-entry sample cap.
    """
    off_output = workdir / "dirb_off.txt"
    off_stats, off_ledger, off_seconds = _compile_shadow_leg(
        line_source,
        off_output,
        ledger_factory=WcsTallyingLedger,
    )
    off_lines = _read_output_lines(off_output)
    off_output_sha256 = _streaming_sha256(off_output)

    # Cache hygiene between legs: the ON leg must not inherit warmed
    # domain/TLD caches from the OFF leg.
    clear_caches()

    on_output = workdir / "dirb_on.txt"
    on_stats, on_ledger, on_seconds = _compile_shadow_leg(
        line_source,
        on_output,
        ledger_factory=WcsTallyingLedger,
        wildcard_covers_subs_pruning=True,
    )
    on_lines = _read_output_lines(on_output)
    on_output_sha256 = _streaming_sha256(on_output)

    return DirbCorpusLegs(
        off_lines=off_lines,
        on_lines=on_lines,
        off_stats=off_stats,
        on_stats=on_stats,
        off_ledger=off_ledger,
        on_ledger=on_ledger,
        off_seconds=off_seconds,
        on_seconds=on_seconds,
        off_output_sha256=off_output_sha256,
        on_output_sha256=on_output_sha256,
    )


def _audit_dirb_expectation(off_lines: list[str]) -> tuple[int, list[str]]:
    """Derive the live wcs removal expectation from OFF-leg output (D-21-02).

    Dedicated scan over the OFF-leg output universe, replicating
    production ordering exactly: the OFF output IS the post-legacy
    post-survivorship universe (phase 3 ate first, only shipped
    wildcards witness, plain-only scope holds), so partitioning its
    surviving TLD-form wildcards versus surviving plains and probing
    every surviving plain with the real _wildcard_covers_sub
    candidate-witness-tld triple counts exactly what the ON leg could
    remove -- no second logic path (D-19-05). A wildcard is admitted as
    a witness only when its domain equals its own get_tld result;
    wildcard-form plains are skipped per plain-only scope. Output lines
    that fail production parsing are handled by shape: ABP-shaped rows
    (``||``/``@@||`` prefix) must always re-parse -- production only
    writes those from parsed records, so a failure raises loudly;
    non-ABP rows are skipped WITH record -- production preserves them
    verbatim via other_rules (regex, decorative comments carrying ``|``
    or ``*``), the write-time probe iterates parsed plain records only
    and can never see them, so skipping replicates production ordering
    exactly while the skip summary in divergences keeps the drop
    auditable in committed forensics. audit-says-X is the live bar for
    the later R1 reconciliation owned by 21-02 (never a constant, never
    the inherited context magnitude).
    """
    survivors: dict[str, list] = {}
    plains: list = []
    skipped_unparsable: list[str] = []
    for line in off_lines:
        record = _parse_abp_rule(line)
        if record is None:
            if line.startswith(("||", "@@||")):
                raise ValueError(f"audit input failed production parse: {line!r}")
            skipped_unparsable.append(line)
            continue
        if record.is_wildcard and record.domain == get_tld(record.domain):
            survivors.setdefault(record.domain, []).append(record)
        elif not record.is_wildcard:
            plains.append(record)
    expected = 0
    divergences: list[str] = []
    for candidate in plains:
        tld = get_tld(candidate.domain)
        witnesses = survivors.get(tld) if tld is not None else None
        if witnesses and _wildcard_covers_sub(candidate, witnesses, tld) is not None:
            expected += 1
            divergences.append(candidate.rule)
    if skipped_unparsable:
        samples = "; ".join(skipped_unparsable[:10])
        divergences.append(
            f"UNPARSABLE_SKIPPED total={len(skipped_unparsable)} samples=[{samples}]"
        )
    return expected, divergences


@pytest.mark.slow
class TestApexShadowEquivalence:
    """SAFE-03 production-flip gate over the FROZEN apex-shadow dataset.

    Component correctness is twin-proven (Tasks 1-2 plus 17-01); this
    class wires the corpus-scale consumer with one-claim-per-assert
    discipline and D-17-08 write-before-assert manifest emission.
    """

    def _frozen_corpus_lines(self):
        """Stream frozen dataset rows lazily (denyallow-gate glob idiom)."""
        for corpus_file in sorted(FROZEN_CORPUS_DIR.glob("*.txt")):
            with open(corpus_file, encoding="utf-8-sig", errors="replace") as handle:
                yield from handle

    @pytest.mark.skipif(not FROZEN_CORPUS_PRESENT, reason=_FROZEN_SKIP_REASON)
    def test_apex_full_corpus_shadow_equivalence(self):
        """Prove flag ON removes ONLY the apex-proven population at scale.

        Signature elements S1-S8 assert from computed values; S9 rides
        the timing reports' output_sha256_stable plus the cross-tie
        against THIS run's leg-output digests. The manifest is written
        before any claim is checked so a red run leaves forensics.
        """
        corpus_summary = _load_frozen_corpus_summary(FROZEN_MANIFEST_PATH)
        corpus_entries = build_corpus_manifest(FROZEN_CORPUS_DIR)
        frozen_digest = manifest_digest(corpus_entries)

        with tempfile.TemporaryDirectory() as tmpdir:
            legs = _run_apex_corpus_legs(self._frozen_corpus_lines, Path(tmpdir))

        removed = set(legs.off_lines) - set(legs.on_lines)
        added = set(legs.on_lines) - set(legs.off_lines)
        on_line_set = set(legs.on_lines)

        off_total_records = legs.off_ledger.summary()["total_records"]
        on_total_records = legs.on_ledger.summary()["total_records"]
        off_by_reason = legs.off_ledger.summary()["by_reason"]
        on_by_reason = legs.on_ledger.summary()["by_reason"]

        whitelist_off = off_by_reason.get(REASON_EXCEPTION_COVERED, 0)
        whitelist_on = on_by_reason.get(REASON_EXCEPTION_COVERED, 0)
        denyallow_off = off_by_reason.get(REASON_DENYALLOW_COVERED, 0)
        denyallow_on = on_by_reason.get(REASON_DENYALLOW_COVERED, 0)
        kept_before = off_by_reason[REASON_KEPT_BECAUSE_UNCERTAIN]
        kept_after = on_by_reason[REASON_KEPT_BECAUSE_UNCERTAIN]

        # S7 scan: skip EXACTLY {apex reason, uncertain reason}; whitelist
        # and denyallow ride their own dedicated equality claims below and
        # trivially double-cover inside these loops.
        skipped_reasons = {REASON_APEX_COVERS_TLD_WILDCARD, REASON_KEPT_BECAUSE_UNCERTAIN}
        mismatches_other_buckets: list[tuple[str, str]] = []
        for reason, off_count in off_by_reason.items():
            if reason in skipped_reasons:
                continue
            if on_by_reason.get(reason, 0) != off_count:
                mismatches_other_buckets.append(("off-to-on", reason))
        for reason, on_count in on_by_reason.items():
            if reason in skipped_reasons:
                continue
            if off_by_reason.get(reason, 0) != on_count:
                mismatches_other_buckets.append(("on-to-off", reason))

        # S8 uses the UNCAPPED pairs set -- never capped samples.
        pairs = legs.on_ledger.apex_pairs
        uncovered_pairs = [
            (candidate_rule, covering_rule)
            for candidate_rule, covering_rule in pairs
            if candidate_rule not in removed or covering_rule not in on_line_set
        ]

        population = _summarize_population(
            legs.on_ledger.apex_candidates,
            legs.on_ledger.apex_pairs,
            capped_samples=[
                _capped_sample_record(record)
                for record in legs.on_ledger.records
                if record.reason == REASON_APEX_COVERS_TLD_WILDCARD
            ],
        )

        checks: dict[str, tuple[object, object]] = {
            "input_identity": (
                legs.off_stats.total_input == legs.on_stats.total_input,
                True,
            ),
            "input_rows_sanity": (legs.off_stats.total_input > 1_000_000, True),
            "added_empty": (added == set(), True),
            "removed_equals_uncapped_tally": (
                legs.on_ledger.apex_candidates == removed,
                True,
            ),
            "removed_equals_counter": (
                legs.on_stats.apex_covered_wildcard_pruned == len(removed),
                True,
            ),
            "total_records_delta_equals_removed": (
                on_total_records - off_total_records == len(removed),
                True,
            ),
            "whitelist_bucket_identical": (
                (
                    whitelist_off == whitelist_on
                    and whitelist_off == legs.off_stats.whitelist_conflict_pruned
                    and whitelist_on == legs.on_stats.whitelist_conflict_pruned
                ),
                True,
            ),
            "denyallow_bucket_identical": (denyallow_off == denyallow_on, True),
            "uncertain_keeps_stasis": (kept_before == kept_after, True),
            "other_buckets_stable_both_directions": (
                mismatches_other_buckets == [],
                True,
            ),
            "coverer_membership_complete": (
                len(pairs) == len(removed) and not uncovered_pairs,
                True,
            ),
            "buckets_partition_total": (population["buckets_partition_total"], True),
        }

        # Timing merge: only when BOTH canonical reports parse AND match
        # this frozen dataset's digest does the timing slot carry data;
        # every other path feeds a NAMED FAILING timing_evidence_present
        # check so a pass verdict stays structurally unreachable (W-2).
        timing_notes: list[str] = []
        timing_docs: dict[str, dict[str, object]] = {}
        for label, timing_path in (
            ("apex-off.json", TIMING_OFF_REPORT_PATH),
            ("apex-on.json", TIMING_ON_REPORT_PATH),
        ):
            try:
                timing_docs[label] = json.loads(timing_path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                timing_notes.append(f"{label}: not loadable ({exc})")

        timing_block: dict[str, object] | None = None
        if len(timing_docs) == 2:
            try:
                merged_block = _timing_block_from_reports(
                    timing_docs["apex-off.json"],
                    timing_docs["apex-on.json"],
                    frozen_digest=frozen_digest,
                    off_sha=legs.off_output_sha256,
                    on_sha=legs.on_output_sha256,
                )
            except ValueError as exc:
                timing_notes.append(f"timing merge rejected: {exc}")
            else:
                if merged_block.get("same_corpus") is True:
                    timing_block = merged_block
                else:
                    timing_notes.append(
                        "timing reports parsed but their corpus digest differs "
                        "from the frozen dataset (foreign evidence)"
                    )

        if timing_block is not None:
            checks["timing_same_corpus"] = (timing_block["same_corpus"], True)
            checks["timing_output_stable_both_legs"] = (
                bool(timing_block["off"]["output_sha256_stable"])
                and bool(timing_block["on"]["output_sha256_stable"]),
                True,
            )
            checks["timing_within_bar"] = (timing_block["passes"], True)
            checks["timing_cross_tie_off"] = (timing_block["cross_tie_off"], True)
            checks["timing_cross_tie_on"] = (timing_block["cross_tie_on"], True)
            checks["timing_on_compile_flags_echo"] = (
                timing_block["on_compile_flags"],
                {"wildcard_apex_pruning": True},
            )
        else:
            # Stage-3 remedy: run the benchmark timing legs (median-of-3
            # per leg) into reports/benchmarks/runs/apex-off.json and
            # apex-on.json over THIS frozen corpus, then re-run the gate.
            checks["timing_evidence_present"] = (
                "; ".join(timing_notes) or "neither timing report parsed",
                "both timing reports parseable and same-corpus",
            )

        evidence: dict[str, object] = {
            "input_rows": legs.off_stats.total_input,
            "added_count": len(added),
            "removed_count": len(removed),
            "ledger": {
                "off_total_records": off_total_records,
                "on_total_records": on_total_records,
                "delta_equals_removed": on_total_records - off_total_records == len(removed),
            },
            "whitelist_conflict_pruned": {"off": whitelist_off, "on": whitelist_on},
            "kept_because_uncertain": {"off": kept_before, "on": kept_after},
            "other_buckets_stable": not mismatches_other_buckets,
            "off_output_sha256": legs.off_output_sha256,
            "on_output_sha256": legs.on_output_sha256,
            "leg_seconds": {"off": legs.off_seconds, "on": legs.on_seconds},
        }

        proposed_guards = _derive_proposed_guards(
            off_rule_count=len(legs.off_lines),
            on_rule_count=len(legs.on_lines),
            removed_count=len(removed),
        )

        corpus_block = {
            "dir": FROZEN_CORPUS_DIR.relative_to(REPO_ROOT).as_posix(),
            "file_count": len(corpus_entries),
            "total_bytes": sum(entry.byte_size for entry in corpus_entries),
            "manifest_sha256": frozen_digest,
            "frozen": True,
        }

        # D-17-08 WRITE-BEFORE-ASSERT: forensics land on disk first; every
        # claim below runs only after the versioned manifest exists.
        verdict, manifest = _evaluate_and_write_manifest(
            checks=checks,
            evidence=evidence,
            population=population,
            output_dir=SHADOW_GATE_OUTPUT_DIR,
            filename_stem=APEX_SHADOW_DATASET_ID,
            identity=_python_identity(),
            corpus=corpus_block,
            timing=timing_block,
            source_health=corpus_summary,
            proposed_guards=proposed_guards,
        )

        assert verdict == "pass"

        # S1: input identity across legs (standalone claim).
        assert legs.off_stats.total_input == legs.on_stats.total_input
        # S1: input sanity at corpus scale (a silently-empty frozen
        # dataset can never masquerade as a clean gate).
        assert legs.off_stats.total_input > 1_000_000
        # S2: added-lines empty -- wildcards can only vanish.
        assert not added
        # S3a: removed set equals the UNCAPPED ledger witness by identity.
        assert legs.on_ledger.apex_candidates == removed
        # S3b: removed count equals the paired stats counter.
        assert legs.on_stats.apex_covered_wildcard_pruned == len(removed)
        # S4: ON total exceeds OFF by EXACTLY the removal count -- a
        # to-be-pruned wildcard has NO OFF-leg record (write-time keeps
        # emit nothing; 16-RESEARCH Derived Implication 3). Never claim
        # totals equality across these legs.
        assert on_total_records - off_total_records == len(removed)
        # S5a: whitelist bucket identical across legs AND equal to each
        # leg's own counter (three standalone claims).
        assert whitelist_off == whitelist_on
        assert whitelist_off == legs.off_stats.whitelist_conflict_pruned
        assert whitelist_on == legs.on_stats.whitelist_conflict_pruned
        # S5b: denyallow bucket identical -- both legs run production
        # default denyallow pruning; the apex flag is the only mover.
        assert denyallow_off == denyallow_on
        # S6: uncertain-keeps EQUALITY stasis (Derived Implication 4 --
        # deliberately unlike the denyallow drop-by-prune-count).
        assert kept_before == kept_after
        # S7: every other attribution bucket byte-stable, both directions.
        assert not mismatches_other_buckets
        # S8a: pairing completeness -- one uncapped pair per removal.
        assert len(pairs) == len(removed)
        # S8b: survivor-coverer membership -- every covering member lives
        # in the ON output set (PRUNE-02 survivor-only witnessing).
        assert not uncovered_pairs
        # D-17-05/D-17-06 partition: the two apex-form buckets sum to the
        # removal total exactly (no double-counting; Pitfall 9).
        assert population["buckets_partition_total"]
        # OFF-side witnessing stays empty: flag-OFF emits nothing.
        assert legs.off_ledger.apex_candidates == set()
        assert legs.off_ledger.apex_pairs == set()

        if timing_block is not None:
            assert timing_block["passes"] is True
            assert timing_block["same_corpus"] is True
            assert timing_block["cross_tie_off"] is True
            assert timing_block["cross_tie_on"] is True
            assert timing_block["on_compile_flags"] == {"wildcard_apex_pruning": True}
            assert timing_block["off"]["output_sha256_stable"] is True
            assert timing_block["on"]["output_sha256_stable"] is True

        # Informational evidence block (magnitudes are calibration facts,
        # never verdict inputs -- Pitfall 11).
        single_bucket = population["buckets"][BUCKET_SINGLE_LABEL_SUFFIX_APEX]
        multipart_bucket = population["buckets"][BUCKET_MULTIPART_SUFFIX_APEX]
        print(f"\n[APEX SHADOW] total_input={legs.off_stats.total_input:,}")
        print(f"[APEX SHADOW] removed={len(removed):,}")
        print(
            f"[APEX SHADOW] {BUCKET_SINGLE_LABEL_SUFFIX_APEX}="
            f"{single_bucket['count']:,} ({single_bucket['share_percent']}%)"
        )
        print(
            f"[APEX SHADOW] {BUCKET_MULTIPART_SUFFIX_APEX}="
            f"{multipart_bucket['count']:,} ({multipart_bucket['share_percent']}%)"
        )
        print(
            f"[APEX SHADOW] pure_tld_share={population['pure_tld_share_percent']}% "
            f"split_bar={population['split_bar_percent']}% "
            f"triggered={population['reason_split_triggered']} "
            "(mechanical D-17-06 answer; magnitude never gates)"
        )
        print(f"[APEX SHADOW] off_output_sha256={legs.off_output_sha256[:16]}")
        print(f"[APEX SHADOW] on_output_sha256={legs.on_output_sha256[:16]}")
        print(
            f"[APEX SHADOW] off_leg_seconds={legs.off_seconds:.1f} "
            f"on_leg_seconds={legs.on_seconds:.1f}"
        )
        manifest_path = SHADOW_GATE_OUTPUT_DIR / f"{APEX_SHADOW_DATASET_ID}.json"
        print(f"[APEX SHADOW] verdict={verdict} manifest={manifest_path}")
        if timing_block is not None:
            print(
                f"[APEX SHADOW] timing medians off="
                f"{timing_block['off']['median_seconds']}s "
                f"on={timing_block['on']['median_seconds']}s "
                f"passes={timing_block['passes']}"
            )
        else:
            failed_timing = checks["timing_evidence_present"]
            print(f"[APEX SHADOW] timing_evidence_present FAILED: {failed_timing[0]}")


# ----------------------------------------------------------------------
# Direction-B shadow machinery unit layer (Phase 21, EVID-03 tracer).
#
# Fixture-scale twin layer for the dirb OFF/ON legs that 21-02 feeds the
# frozen corpus. Proves the leg-runner shape, the uncapped-witnessing
# WcsTallyingLedger, the HONEST-ZERO B-signature spelling, and the
# flag-threading plus cache-hygiene structural contracts BEFORE any
# corpus-scale execution exists.
#
# Honest-zero note (superset theorem, Phase-20 header): phase 3's TLD
# branch runs the same scope oracle over a strict superset of any
# write-time survivor pool, so full-compile yield is structurally zero --
# every wcs-provable pair is already owned by phase 3 under
# tld_wildcard_covered. These twins pin EXACTLY that shape at fixture
# scale (tally == counter == removed == 0, OFF-identical-to-ON bytes,
# OFF-side witnessing empty) rather than a nonzero yield no input could
# produce through compile_rules(). See D1 in 21-01-SUMMARY.
# ----------------------------------------------------------------------


class TestDirbShadowMachinery:
    """Unit-proven dirb two-leg shadow comparison over synthetic lines.

    Fixture vocabulary mirrors the Phase-20 direct-drive golden
    (``autos`` TLD-form wildcard plus covered sub, D-19-06) with one
    unrelated same-file plain so the OFF universe carries both a
    phase-3-owned pair and an uncoverable control.
    """

    DIRB_FIXTURE_LINES = [
        "||*.autos^",
        "||sub.autos^",
        "||unrelated.xyz^",
    ]

    DIRB_WILDCARD_ONLY_LINES = ["||*.autos^"]

    def _result(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            return _run_dirb_corpus_legs(
                _shadow_line_factory(list(self.DIRB_FIXTURE_LINES)),
                Path(tmpdir),
            )

    def test_shadow_leg_typing_preserves_ledger_subclass(self):
        """The shadow-leg helper signature preserves ledger subclasses (21-IN-01).

        DirbCorpusLegs/ApexCorpusLegs access subclass-only tally
        attributes, so the helper return annotation must name the ledger
        type variable instead of the erased CappedProofLedger base.
        """
        assert "LedgerT" in str(_compile_shadow_leg.__annotations__["return"])

    def test_dirb_legs_keep_honest_zero_signature_on_fixture_lines(self):
        """OFF/ON legs agree exactly with zero wcs accounting either side.

        Pins the honest-zero B-signature spelling (tally == counter ==
        removed == 0) with one claim per assert and exact equality only.
        The covered sub never reaches the write-time probe: phase 3 owns
        it first under tld_wildcard_covered, so both legs emit the same
        bytes and both ledgers stay empty of the wcs family.
        """
        legs = self._result()

        removed = set(legs.off_lines) - set(legs.on_lines)
        added = set(legs.on_lines) - set(legs.off_lines)

        # OFF output pins the phase-3-owned population
        # (capture-not-predict under py -3.14 at authoring time).
        assert legs.off_lines == ["||*.autos^", "||unrelated.xyz^"]
        # OFF-identical-to-ON bytes: the flag moves nothing here.
        assert legs.on_lines == legs.off_lines
        # Empty diff sets, exact equality.
        assert removed == set()
        assert added == set()
        # Counter pins 0 in BOTH legs.
        assert legs.off_stats.wildcard_covered_sub_pruned == 0
        assert legs.on_stats.wildcard_covered_sub_pruned == 0
        # Tally == counter == removed (B3a/B3b honest-zero form).
        assert legs.on_ledger.wcs_candidates == removed
        assert legs.off_ledger.wcs_candidates == set()
        assert legs.on_ledger.wcs_pairs == set()
        assert legs.off_ledger.wcs_pairs == set()
        on_tally = legs.on_ledger.summary()["by_reason"].get(REASON_WILDCARD_COVERS_SUB, 0)
        assert on_tally == legs.on_stats.wildcard_covered_sub_pruned
        off_tally = legs.off_ledger.summary()["by_reason"].get(REASON_WILDCARD_COVERS_SUB, 0)
        assert off_tally == legs.off_stats.wildcard_covered_sub_pruned

    def test_dirb_off_side_witnessing_empty_on_wildcard_only_fixture(self):
        """A wildcard-only universe witnesses nothing on the OFF side."""
        with tempfile.TemporaryDirectory() as tmpdir:
            legs = _run_dirb_corpus_legs(
                _shadow_line_factory(list(self.DIRB_WILDCARD_ONLY_LINES)),
                Path(tmpdir),
            )

        assert legs.off_ledger.wcs_candidates == set()
        assert legs.off_ledger.wcs_pairs == set()

    def test_dirb_legs_clear_caches_between_legs_and_thread_the_flag(self, monkeypatch):
        """Pin the two structural contracts no yield assert can carry.

        With honest-zero fixture yield the OFF/ON outputs are identical
        whether the flag threads or is dropped (the D-21-09 fear), so
        this twin spies the mechanism directly: ``clear_caches`` must
        fire exactly once per run (between the legs, never inside one),
        and the ON leg must forward ``wildcard_covers_subs_pruning=True``
        into compile_rules while the OFF leg passes production defaults
        with no extra kwargs. Both spies call through so behavior is
        unperturbed.
        """
        module = sys.modules[__name__]
        real_clear_caches = module.clear_caches
        real_compile_rules = module.compile_rules
        clear_calls: list[None] = []
        forwarded_kwargs: list[dict[str, object]] = []

        def recording_clear_caches() -> None:
            clear_calls.append(None)
            real_clear_caches()

        def recording_compile_rules(lines, output_file, *args, **kwargs):
            forwarded_kwargs.append(dict(kwargs))
            return real_compile_rules(lines, output_file, *args, **kwargs)

        monkeypatch.setattr(module, "clear_caches", recording_clear_caches)
        monkeypatch.setattr(module, "compile_rules", recording_compile_rules)

        with tempfile.TemporaryDirectory() as tmpdir:
            legs = _run_dirb_corpus_legs(
                _shadow_line_factory(list(self.DIRB_FIXTURE_LINES)),
                Path(tmpdir),
            )

        assert len(clear_calls) == 1
        assert len(forwarded_kwargs) == 2
        assert "wildcard_covers_subs_pruning" not in forwarded_kwargs[0]
        assert forwarded_kwargs[1].get("wildcard_covers_subs_pruning") is True
        assert legs.on_lines == legs.off_lines

    def test_dirb_dataset_paths_never_reference_apex_frozen_dir(self):
        """Dirb evidence paths stay out of the apex frozen dir (T-21-06)."""
        assert DIRB_SHADOW_DATASET_ID == "dirb-shadow-v1" or "DIRB_SHADOW_DATASET_ID" in os.environ
        assert "apex" not in str(DIRB_FROZEN_CORPUS_DIR)
        assert "apex" not in str(DIRB_FROZEN_MANIFEST_PATH)
        assert "apex" not in str(DIRB_TIMING_OFF_REPORT_PATH)
        assert "apex" not in str(DIRB_TIMING_ON_REPORT_PATH)


class TestDirbAuditExpectation:
    """Fast unit twins for the audit-first expectation helper (D-21-02).

    The helper derives its count from the OFF-leg output universe with
    the production oracle, so these twins feed it hand-built universes
    (capture-not-predict literals under py -3.14 at authoring time) and
    pin exact counts plus divergence texts -- never ranges, never a
    hardcoded yield constant.
    """

    AUDIT_SINGLE_PROOF_LINES = [
        "||*.autos^",
        "||sub.autos^",
        "||unrelated.xyz^",
    ]

    AUDIT_KNOWN_ZERO_LINES = [
        "||*.autos^",
        "||*.sub.autos^",
        "||lonely.buzz^",
    ]

    def test_audit_counts_single_covered_plain_with_divergence_text(self):
        """One surviving witness plus one covered plain yields 1."""
        expected, divergences = _audit_dirb_expectation(list(self.AUDIT_SINGLE_PROOF_LINES))
        assert expected == 1
        assert divergences == ["||sub.autos^"]

    def test_audit_zero_universe_yields_zero_with_empty_divergences(self):
        """Wildcards without same-key plains plus skipped forms yield 0."""
        expected, divergences = _audit_dirb_expectation(list(self.AUDIT_KNOWN_ZERO_LINES))
        assert expected == 0
        assert divergences == []

    def test_audit_raises_loudly_on_unparsable_abp_shaped_line(self):
        """ABP-shaped output that fails production parsing never skips."""
        with pytest.raises(ValueError):
            _audit_dirb_expectation(["||*.autos^", "||"])

    def test_audit_skips_other_rules_lines_with_recorded_forensics(self):
        """Non-ABP rows production preserves verbatim skip WITH record."""
        expected, divergences = _audit_dirb_expectation(
            ["||*.autos^", "||sub.autos^", "!  |", "/^regex$/"]
        )
        assert expected == 1
        assert divergences[0] == "||sub.autos^"
        assert divergences[1] == ("UNPARSABLE_SKIPPED total=2 samples=[!  |; /^regex$/]")


class TestDirbStasisAndWriterReuse:
    """Uncertain STASIS twin plus staged writer-reuse proof (21-01 Task 3).

    RED rationale (no implementation surface exists in this task -- both
    twins pin behavior over Task-1 machinery, so the RED state is the
    twins' absence): the STASIS spelling below is asserted as strict
    equality because the stale minus-N delta cannot be produced by the
    code -- _record_uncertain_keep is reachable only from the
    flag-independent phase-3 site -- and a minus-N twin would fail for
    that mechanism reason (21-RESEARCH OQ2, D-21-10).
    """

    DIRB_UNCERTAIN_LINES = [
        "||*.com^",
        "||foo.com^$important",
    ]

    def _legs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            return _run_dirb_corpus_legs(
                _shadow_line_factory(list(self.DIRB_UNCERTAIN_LINES)),
                Path(tmpdir),
            )

    # 21-02 S7 shape note: the slow gate's other-buckets stability scan
    # skips EXACTLY {REASON_WILDCARD_COVERS_SUB,
    # REASON_KEPT_BECAUSE_UNCERTAIN}; whitelist and denyallow ride their
    # own dedicated equality claims below (no slow gate is built here).
    def test_dirb_uncertain_keeps_hold_stasis_across_legs(self):
        """Uncertain keeps are identical across OFF/ON legs (D-21-10).

        Asserts strict equality, never a minus-N delta (the stale v1.4
        spec spelling refused per 21-RESEARCH OQ2). The fixture
        exercises the uncertain path with exactly one uncertain keep per
        leg (capture-not-predict under py -3.14 at authoring time).
        """
        legs = self._legs()
        off_uncertain = legs.off_ledger.summary()["by_reason"].get(REASON_KEPT_BECAUSE_UNCERTAIN, 0)
        on_uncertain = legs.on_ledger.summary()["by_reason"].get(REASON_KEPT_BECAUSE_UNCERTAIN, 0)
        assert off_uncertain == 1
        assert on_uncertain == off_uncertain

    def test_dirb_manifest_writer_round_trip_under_dirb_stem(self):
        """Reused writer emits dirb-stem JSON plus MD with a verdict FIELD.

        Calls the existing _evaluate_and_write_manifest verbatim (no new
        writer logic, staged D-17-08): all-ok checks round-trip
        identically through JSON and MD with observed-expected-ok
        entries. Staging note: the shared writer stamps its own
        report_type/title values, so this twin pins FIELD presence (not
        the dirb-specific strings) -- the dirb report_type
        parameterization belongs to 21-02's gate emission, which may
        extend the writer then.
        """
        checks: dict[str, tuple[object, object]] = {
            "input_identity": (3 == 3, True),
            "added_empty": (set() == set(), True),
        }
        evidence: dict[str, object] = {"input_rows": 3, "removed_count": 0}
        population: dict[str, object] = {
            "total": 0,
            "audit_expected": 0,
            "audit_divergences": [],
        }
        corpus: dict[str, object] = {
            "dir": "reports/benchmarks/frozen/dirb-shadow-v1/raw",
            "manifest_sha256": "0" * 64,
            "frozen": True,
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            verdict, manifest = _evaluate_and_write_manifest(
                checks=checks,
                evidence=evidence,
                population=population,
                output_dir=output_dir,
                filename_stem="dirb-shadow-v1",
                corpus=corpus,
            )
            json_path = output_dir / "dirb-shadow-v1.json"
            md_path = output_dir / "dirb-shadow-v1.md"
            assert json_path.is_file()
            assert md_path.is_file()
            assert verdict == "pass"
            assert manifest["verdict"] == "pass"
            assert manifest["schema_version"] == SHADOW_REPORT_SCHEMA_VERSION
            assert "report_type" in manifest
            assert manifest["corpus"] == corpus
            assert manifest["checks"]["input_identity"] == {
                "observed": True,
                "expected": True,
                "ok": True,
            }
            with open(json_path, encoding="utf-8") as handle:
                assert json.load(handle) == manifest
            assert "- Verdict: pass" in md_path.read_text(encoding="utf-8")

    def test_dirb_manifest_writer_leaves_forensics_on_failing_check(self):
        """A forced failing check yields verdict fail with files on disk."""
        checks: dict[str, tuple[object, object]] = {
            "input_identity": (3, 3),
            "population_nonzero": (0, 1),
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            verdict, manifest = _evaluate_and_write_manifest(
                checks=checks,
                evidence={},
                population={},
                output_dir=output_dir,
                filename_stem="dirb-shadow-v1",
            )
            assert verdict == "fail"
            assert manifest["verdict"] == "fail"
            assert manifest["checks"]["population_nonzero"] == {
                "observed": 0,
                "expected": 1,
                "ok": False,
            }
            assert (output_dir / "dirb-shadow-v1.json").is_file()
            assert (output_dir / "dirb-shadow-v1.md").is_file()


# ----------------------------------------------------------------------
# Direction-B positive controls (Phase 21 plan 21-02, D-21-09).
#
# Seeds-as-legs form (NOT the superseded D-21-07 corpus-embedded form):
# corpus-embedded seeds are unimplementable through compile_rules() --
# phase 3 proves coverage with the bare oracle over a strict superset of
# any write-time survivor pool, so any seed the probe would accept is
# eaten by phase 3 first under tld_wildcard_covered and never reaches the
# probe (21-01 D1, superset theorem). The 2-3 seeds below therefore live
# as direct-drive _write_output() legs built through production
# _parse_abp_rule plus production get_tld key derivation over real public
# suffixes (autos vocabulary, D-19-06), with clearly marked synthetic ids:
# s1 bare wildcard-plus-plain, s2 scoped-modifier pair exercising the
# modifier_scope_covers oracle path, s3 deep-sub depth proof. OFF keeps
# both lines with counter 0 and empty wcs sets; ON removes exactly the
# seed plain with counter 1, uncapped tally equality, single-family ledger
# EXACT, and paired totals. The frozen set stays natural-only (guard
# below); the corpus-leg kwargs spy proves flag threading at compile
# level where outputs are identical.
# ----------------------------------------------------------------------


class DirbSeedDrive(NamedTuple):
    """One direct-drive seed pair outcome under both flag states."""

    off_lines: list[str]
    on_lines: list[str]
    off_stats: CompileStats
    on_stats: CompileStats
    off_ledger: WcsTallyingLedger
    on_ledger: WcsTallyingLedger


def _dirb_seed_storages(
    wildcard_text: str,
    plain_text: str,
) -> tuple[dict[str, list], dict[str, list]]:
    """Build builder-contract storages for one seed pair.

    Records come strictly from production _parse_abp_rule; the wildcard
    storage key derives from production get_tld with TLD-form admission
    (mirroring the audit helper), and the plain key is the record's own
    domain (the write-time probe re-derives the witness key itself, so
    the plain key never influences coverage).
    """
    witness = _parse_abp_rule(wildcard_text)
    candidate = _parse_abp_rule(plain_text)
    if witness is None or candidate is None:
        raise ValueError(f"seed inputs must parse: {wildcard_text!r} {plain_text!r}")
    witness_key = get_tld(witness.domain)
    if witness_key is None or witness.domain != witness_key:
        raise ValueError(f"seed witness must be TLD-form: {wildcard_text!r}")
    if not witness.is_wildcard or candidate.is_wildcard:
        raise ValueError(f"seed pair must be wildcard-plus-plain: {wildcard_text!r} {plain_text!r}")
    return ({witness_key: [witness]}, {candidate.domain: [candidate]})


def _drive_dirb_seed(wildcard_text: str, plain_text: str) -> DirbSeedDrive:
    """Drive one seed pair through _write_output() under both flag states.

    Direct-drive form per D-21-09 (NOT the superseded corpus-embedded
    form): compile_rules() cannot yield nonzero wcs removals (phase-3
    superset), so the mechanism proof drives the wired site directly with
    WcsTallyingLedger witnesses. clear_caches() runs between drives
    because the module LRU caches are process-global (Pitfall 6).
    """
    abp_wildcards, pruned_abp = _dirb_seed_storages(wildcard_text, plain_text)

    clear_caches()
    off_stats = CompileStats()
    off_ledger = WcsTallyingLedger()
    with tempfile.TemporaryDirectory() as tmpdir:
        off_output = Path(tmpdir) / "seed_off.txt"
        _write_output(
            str(off_output),
            off_stats,
            abp_wildcards,
            pruned_abp,
            [],
            set(),
            off_ledger,
        )
        off_lines = _read_output_lines(off_output)

    clear_caches()
    on_stats = CompileStats()
    on_ledger = WcsTallyingLedger()
    with tempfile.TemporaryDirectory() as tmpdir:
        on_output = Path(tmpdir) / "seed_on.txt"
        _write_output(
            str(on_output),
            on_stats,
            abp_wildcards,
            pruned_abp,
            [],
            set(),
            on_ledger,
            wildcard_covers_subs_pruning=True,
        )
        on_lines = _read_output_lines(on_output)

    return DirbSeedDrive(
        off_lines=off_lines,
        on_lines=on_lines,
        off_stats=off_stats,
        on_stats=on_stats,
        off_ledger=off_ledger,
        on_ledger=on_ledger,
    )


class TestDirbPositiveControls:
    """Direct-drive seed legs proving the probe fires, plus threading spy.

    Corpus-scale threading distinguisher for the 21-03 close: seed legs
    green plus audit zero plus R1 match resolves to honest zero for the
    21-03 close, seed legs green plus audit nonzero plus R1 mismatch
    resolves to mechanism divergence for investigation, seed legs red
    resolves to harness break requiring fix and re-run.
    """

    # Seed ids are synthetic by construction (clearly marked); the frozen
    # set stays natural-only (see the natural-only guard below).
    S1_WILDCARD = "||*.autos^"  # synthetic seed s1 witness (bare)
    S1_PLAIN = "||sub.autos^"  # synthetic seed s1 candidate (bare)
    S2_WILDCARD = "||*.autos^$client=10.0.0.1"  # synthetic s2 witness (scoped)
    S2_PLAIN = "||sub.autos^$client=10.0.0.1"  # synthetic s2 candidate (scoped)
    S3_WILDCARD = "||*.autos^"  # synthetic seed s3 witness (bare)
    S3_PLAIN = "||b.a.autos^"  # synthetic seed s3 candidate (deep sub)

    def test_s1_bare_pair_off_keeps_both_with_zero_accounting(self):
        """OFF leg writes both seed lines with zero wcs accounting."""
        drive = _drive_dirb_seed(self.S1_WILDCARD, self.S1_PLAIN)
        assert drive.off_lines == [self.S1_WILDCARD, self.S1_PLAIN]
        assert drive.off_stats.wildcard_covered_sub_pruned == 0
        assert drive.off_ledger.wcs_candidates == set()
        assert drive.off_ledger.wcs_pairs == set()
        assert drive.off_ledger.summary()["by_reason"] == {}

    def test_s1_bare_pair_on_removes_plain_with_exact_single_family(self):
        """ON leg removes exactly the seed plain with 1:1 ledger exactness."""
        drive = _drive_dirb_seed(self.S1_WILDCARD, self.S1_PLAIN)
        assert drive.on_lines == [self.S1_WILDCARD]
        assert drive.on_stats.wildcard_covered_sub_pruned == 1
        assert drive.on_ledger.wcs_candidates == {self.S1_PLAIN}
        assert drive.on_ledger.wcs_pairs == {(self.S1_PLAIN, self.S1_WILDCARD)}
        on_tally = drive.on_ledger.summary()["by_reason"].get(REASON_WILDCARD_COVERS_SUB, 0)
        assert on_tally == drive.on_stats.wildcard_covered_sub_pruned
        assert drive.on_ledger.summary()["by_reason"] == {REASON_WILDCARD_COVERS_SUB: 1}
        assert drive.on_stats.total_output == drive.on_stats.abp_kept + drive.on_stats.other_kept
        assert drive.on_stats.total_output == 1

    def test_s2_scoped_modifier_pair_proves_oracle_path_at_direct_drive_scale(self):
        """Scoped witness plus matching scoped plain exercises the oracle path."""
        drive = _drive_dirb_seed(self.S2_WILDCARD, self.S2_PLAIN)
        assert drive.off_lines == [self.S2_WILDCARD, self.S2_PLAIN]
        assert drive.off_stats.wildcard_covered_sub_pruned == 0
        assert drive.on_lines == [self.S2_WILDCARD]
        assert drive.on_stats.wildcard_covered_sub_pruned == 1
        assert drive.on_ledger.wcs_candidates == {self.S2_PLAIN}
        assert drive.on_ledger.wcs_pairs == {(self.S2_PLAIN, self.S2_WILDCARD)}
        assert drive.on_ledger.summary()["by_reason"] == {REASON_WILDCARD_COVERS_SUB: 1}
        assert drive.on_stats.total_output == 1

    def test_s3_deep_sub_pair_removes_on_with_exact_pairing(self):
        """Depth does not shield a plain from a same-key TLD witness."""
        drive = _drive_dirb_seed(self.S3_WILDCARD, self.S3_PLAIN)
        assert drive.off_lines == [self.S3_WILDCARD, self.S3_PLAIN]
        assert drive.off_stats.wildcard_covered_sub_pruned == 0
        assert drive.on_lines == [self.S3_WILDCARD]
        assert drive.on_stats.wildcard_covered_sub_pruned == 1
        assert drive.on_ledger.wcs_candidates == {self.S3_PLAIN}
        assert drive.on_ledger.wcs_pairs == {(self.S3_PLAIN, self.S3_WILDCARD)}
        assert drive.on_ledger.summary()["by_reason"] == {REASON_WILDCARD_COVERS_SUB: 1}
        assert drive.on_stats.total_output == 1

    def test_corpus_leg_forwards_flag_kwarg_into_compile_rules(self, monkeypatch):
        """Spy proving the ON corpus leg threads the flag (D-21-09 fear).

        With honest-zero fixture yield the OFF/ON outputs are identical
        whether the flag threads or is dropped, so only a kwargs spy can
        distinguish threaded from dropped: the OFF leg must pass
        production defaults with no extra kwarg (negative control) while
        the ON leg must forward wildcard_covers_subs_pruning=True. A
        dropped kwarg turns the second claim red.
        """
        module = sys.modules[__name__]
        real_compile_rules = module.compile_rules
        forwarded_kwargs: list[dict[str, object]] = []

        def recording_compile_rules(lines, output_file, *args, **kwargs):
            forwarded_kwargs.append(dict(kwargs))
            return real_compile_rules(lines, output_file, *args, **kwargs)

        monkeypatch.setattr(module, "compile_rules", recording_compile_rules)

        with tempfile.TemporaryDirectory() as tmpdir:
            _run_dirb_corpus_legs(
                _shadow_line_factory([self.S1_WILDCARD, self.S1_PLAIN]),
                Path(tmpdir),
            )

        assert len(forwarded_kwargs) == 2
        assert "wildcard_covers_subs_pruning" not in forwarded_kwargs[0]
        assert forwarded_kwargs[1].get("wildcard_covers_subs_pruning") is True

    def test_frozen_set_stays_natural_only_with_no_seed_files(self):
        """No seed text file exists under any dirb frozen path (T-21-07).

        Pre-freeze this pins the empty dir; post-freeze (the 21-03
        canonical run) the dir legitimately holds the 86 fetched natural
        files, so the claim becomes manifest parity -- every frozen file
        is provenance-pinned by the freezer, and any hand-planted seed
        file would break parity (or fail validate_manifest's
        unexpected-file check).
        """
        frozen_names = sorted(path.name for path in DIRB_FROZEN_CORPUS_DIR.glob("*.txt"))
        if not DIRB_FROZEN_MANIFEST_PATH.is_file():
            assert frozen_names == []
        else:
            manifest = json.loads(DIRB_FROZEN_MANIFEST_PATH.read_text(encoding="utf-8"))
            manifest_names = sorted(source["filename"] for source in manifest["sources"])
            assert frozen_names == manifest_names
        assert DIRB_FROZEN_CORPUS_DIR != FROZEN_CORPUS_DIR
        assert "apex" not in DIRB_SHADOW_DATASET_ID


# ----------------------------------------------------------------------
# Direction-B slow gate plus fixture-scale spelling twins (Phase 21 plan
# 21-02, D-21-01 plus D-21-10 plus carried-forward D-17-08).
#
# TestDirbShadowEquivalence clones the apex slow-gate skeleton as a
# sibling class with dirb deltas and executes zero corpus legs in this
# plan: without a freeze the corpus method skips with the dirb skip
# reason. The B1-B10 plus R1 plus literal R2 spellings live in
# _dirb_gate_checks (exact RESEARCH spellings, no ranges or thresholds,
# uncertain STASIS per D-21-10 refusing the stale minus-N), exercised at
# fixture scale by the spelling twins below and at corpus scale by the
# slow gate in the 21-03 canonical run. Manifest emission reuses the
# shared writer under the dirb-shadow-v1 stem with report type
# dirb_shadow_gate, verdict as FIELD, and omitted proposed_guards,
# writing before any assert so red runs leave forensics.
# ----------------------------------------------------------------------


def _dirb_gate_checks(
    legs: DirbCorpusLegs,
    *,
    audit_expected: int,
) -> tuple[dict[str, tuple[object, object]], dict[str, object]]:
    """Evaluate the B1-B10 plus R1 plus literal R2 signature spellings.

    Exact RESEARCH spellings with one claim per key and no ranges or
    thresholds anywhere: input identity plus input rows sanity over one
    million, added empty, removed equals uncapped tally, removed equals
    wildcard_covered_sub_pruned counter, total_records delta equals
    removed, whitelist identical across legs and equal to each leg's
    by_reason tally, denyallow identical, uncertain STASIS, other-buckets
    stable both directions skipping exactly the wcs plus uncertain
    reasons, coverer membership complete over uncapped wcs_pairs,
    OFF-side witnessing empty, R1 reconciliation of removed count against
    the live audit expectation (D-21-02, never a constant), R2
    population_nonzero literal (D-21-01 -- a zero corpus reading fails
    reconciliation by design). B10 determinism rides the timing block's
    sha-stability plus the evidence shas, deliberately NOT a checks key:
    timing never gates per D-21-04. Shared by the fixture-scale spelling
    twins and the corpus-scale slow gate so both pin one signature.

    Returns:
        ``(checks, details)`` where checks drives the verdict FIELD and
        details carries the SAME computed objects (removed/added/ledger
        tallies/mismatches/pairs) so evidence and asserts reuse them
        without recomputation (WR-06 single-computation).
    """
    removed = set(legs.off_lines) - set(legs.on_lines)
    added = set(legs.on_lines) - set(legs.off_lines)
    on_line_set = set(legs.on_lines)

    off_total_records = legs.off_ledger.summary()["total_records"]
    on_total_records = legs.on_ledger.summary()["total_records"]
    off_by_reason = legs.off_ledger.summary()["by_reason"]
    on_by_reason = legs.on_ledger.summary()["by_reason"]

    whitelist_off = off_by_reason.get(REASON_EXCEPTION_COVERED, 0)
    whitelist_on = on_by_reason.get(REASON_EXCEPTION_COVERED, 0)
    denyallow_off = off_by_reason.get(REASON_DENYALLOW_COVERED, 0)
    denyallow_on = on_by_reason.get(REASON_DENYALLOW_COVERED, 0)
    kept_before = off_by_reason.get(REASON_KEPT_BECAUSE_UNCERTAIN, 0)
    kept_after = on_by_reason.get(REASON_KEPT_BECAUSE_UNCERTAIN, 0)

    skipped_reasons = {REASON_WILDCARD_COVERS_SUB, REASON_KEPT_BECAUSE_UNCERTAIN}
    mismatches_other_buckets: list[tuple[str, str]] = []
    for reason, off_count in off_by_reason.items():
        if reason in skipped_reasons:
            continue
        if on_by_reason.get(reason, 0) != off_count:
            mismatches_other_buckets.append(("off-to-on", reason))
    for reason, on_count in on_by_reason.items():
        if reason in skipped_reasons:
            continue
        if off_by_reason.get(reason, 0) != on_count:
            mismatches_other_buckets.append(("on-to-off", reason))

    pairs = legs.on_ledger.wcs_pairs
    uncovered_pairs = [
        (candidate_rule, covering_rule)
        for candidate_rule, covering_rule in pairs
        if candidate_rule not in removed or covering_rule not in on_line_set
    ]

    checks: dict[str, tuple[object, object]] = {
        "input_identity": (
            legs.off_stats.total_input == legs.on_stats.total_input,
            True,
        ),
        "input_rows_sanity": (legs.off_stats.total_input > 1_000_000, True),
        "added_empty": (added == set(), True),
        "removed_equals_uncapped_tally": (
            legs.on_ledger.wcs_candidates == removed,
            True,
        ),
        "removed_equals_counter": (
            legs.on_stats.wildcard_covered_sub_pruned == len(removed),
            True,
        ),
        "total_records_delta_equals_removed": (
            on_total_records - off_total_records == len(removed),
            True,
        ),
        "whitelist_bucket_identical": (
            (
                whitelist_off == whitelist_on
                and whitelist_off == legs.off_stats.whitelist_conflict_pruned
                and whitelist_on == legs.on_stats.whitelist_conflict_pruned
            ),
            True,
        ),
        "denyallow_bucket_identical": (denyallow_off == denyallow_on, True),
        # B6 STASIS per D-21-10: the uncertain recorder is reachable only
        # from the flag-independent phase-3 site, so tallies are identical
        # across legs. The stale v1.4 "uncertain delta == -N" spelling is
        # explicitly refused (21-RESEARCH OQ2): it asserts a delta the code
        # cannot produce.
        "uncertain_keeps_stasis": (kept_before == kept_after, True),
        "other_buckets_stable_both_directions": (
            mismatches_other_buckets == [],
            True,
        ),
        "coverer_membership_complete": (
            len(pairs) == len(removed) and not uncovered_pairs,
            True,
        ),
        "off_side_witnessing_empty": (
            legs.off_ledger.wcs_candidates == set() and legs.off_ledger.wcs_pairs == set(),
            True,
        ),
        "reconciliation_matches_audit": (len(removed) == audit_expected, True),
        "population_nonzero": (len(removed) > 0, True),
    }
    details: dict[str, object] = {
        "removed": removed,
        "added": added,
        "on_line_set": on_line_set,
        "off_total_records": off_total_records,
        "on_total_records": on_total_records,
        "off_by_reason": off_by_reason,
        "on_by_reason": on_by_reason,
        "whitelist_off": whitelist_off,
        "whitelist_on": whitelist_on,
        "denyallow_off": denyallow_off,
        "denyallow_on": denyallow_on,
        "kept_before": kept_before,
        "kept_after": kept_after,
        "mismatches_other_buckets": mismatches_other_buckets,
        "pairs": pairs,
        "uncovered_pairs": uncovered_pairs,
    }
    return checks, details


@pytest.mark.slow
class TestDirbShadowEquivalence:
    """Corpus-scale dirb shadow-equivalence gate over the FROZEN dataset.

    Sibling to TestApexShadowEquivalence with dirb deltas: frozen-corpus
    line streamer over DIRB_FROZEN_CORPUS_DIR in sorted order,
    manifest-digest pin before legs, _run_dirb_corpus_legs inside a
    temporary workdir, removed versus added set-diff opening, exact
    B1-B10 plus R1 plus literal R2 evaluation, live-audit R1
    reconciliation (D-21-02), always-write manifest emission under the
    dirb-shadow-v1 stem BEFORE any assert (D-17-08), one claim per
    assert, and informational DIRB SHADOW prints. Timing merges here via
    _dirb_timing_medians as informational-only evidence (D-21-04, never a
    checks input). Zero corpus legs execute outside the canonical 21-03
    run: without a freeze this method skips.
    """

    def _frozen_corpus_lines(self):
        """Stream frozen dataset rows lazily (denyallow-gate glob idiom)."""
        for corpus_file in sorted(DIRB_FROZEN_CORPUS_DIR.glob("*.txt")):
            with open(corpus_file, encoding="utf-8-sig", errors="replace") as handle:
                yield from handle

    @pytest.mark.skipif(not DIRB_FROZEN_CORPUS_PRESENT, reason=DIRB_FROZEN_SKIP_REASON)
    def test_dirb_full_corpus_shadow_equivalence(self):
        """Prove flag ON removes ONLY the audit-expected population at scale.

        Signature elements B1-B10 assert from computed values; R1
        reconciles the removal count against the live audit expectation
        (D-21-02, never a constant); R2 population_nonzero is literal per
        D-21-01 (a zero corpus reading fails reconciliation by design and
        routes to the D-21-05 stop-and-present). The manifest is written
        before any claim is checked so a red run leaves forensics.
        """
        corpus_summary = _load_frozen_corpus_summary(DIRB_FROZEN_MANIFEST_PATH)
        corpus_entries = build_corpus_manifest(DIRB_FROZEN_CORPUS_DIR)
        frozen_digest = manifest_digest(corpus_entries)

        with tempfile.TemporaryDirectory() as tmpdir:
            legs = _run_dirb_corpus_legs(self._frozen_corpus_lines, Path(tmpdir))

        audit_expected, audit_divergences = _audit_dirb_expectation(list(legs.off_lines))
        # WR-06 single-computation: checks and evidence share the helper's
        # objects -- no inline recomputation that could drift from the gate.
        checks, details = _dirb_gate_checks(legs, audit_expected=audit_expected)

        removed = details["removed"]
        added = details["added"]
        off_total_records = details["off_total_records"]
        on_total_records = details["on_total_records"]
        whitelist_off = details["whitelist_off"]
        whitelist_on = details["whitelist_on"]
        denyallow_off = details["denyallow_off"]
        denyallow_on = details["denyallow_on"]
        kept_before = details["kept_before"]
        kept_after = details["kept_after"]
        mismatches_other_buckets = details["mismatches_other_buckets"]
        pairs = details["pairs"]
        uncovered_pairs = details["uncovered_pairs"]

        evidence: dict[str, object] = {
            "input_rows": legs.off_stats.total_input,
            "added_count": len(added),
            "removed_count": len(removed),
            "ledger": {
                "off_total_records": off_total_records,
                "on_total_records": on_total_records,
                "delta_equals_removed": on_total_records - off_total_records == len(removed),
            },
            "whitelist_conflict_pruned": {"off": whitelist_off, "on": whitelist_on},
            "kept_because_uncertain": {"off": kept_before, "on": kept_after},
            "other_buckets_stable": not mismatches_other_buckets,
            "off_output_sha256": legs.off_output_sha256,
            "on_output_sha256": legs.on_output_sha256,
            "leg_seconds": {"off": legs.off_seconds, "on": legs.on_seconds},
        }

        population: dict[str, object] = {
            "total": len(removed),
            "audit_expected": audit_expected,
            "audit_divergences": list(audit_divergences),
            "samples": [
                _capped_sample_record(record)
                for record in legs.on_ledger.records
                if record.reason == REASON_WILDCARD_COVERS_SUB
            ],
        }

        corpus_block = {
            "dir": DIRB_FROZEN_CORPUS_DIR.relative_to(REPO_ROOT).as_posix(),
            "file_count": len(corpus_entries),
            "total_bytes": sum(entry.byte_size for entry in corpus_entries),
            "manifest_sha256": frozen_digest,
            "frozen": True,
        }

        # D-17-08 WRITE-BEFORE-ASSERT: forensics land on disk first; every
        # claim below runs only after the versioned manifest exists.
        # proposed_guards omitted (no flip pends for B; FLIP-01 is v1.5+)
        # so the writer emits the reserved non-binding stub. Timing merges
        # here via _dirb_timing_medians over the same frozen dir with
        # digest-pinned same_corpus plus determinism cross-ties plus leg
        # seconds -- informational only, never a checks input (D-21-04).
        timing_block = _dirb_timing_medians(
            self._frozen_corpus_lines,
            frozen_digest=frozen_digest,
            corpus_dir=DIRB_FROZEN_CORPUS_DIR,
        )
        timing_block["cross_tie_off"] = (
            timing_block["off"]["output_sha256"] == legs.off_output_sha256
        )
        timing_block["cross_tie_on"] = timing_block["on"]["output_sha256"] == legs.on_output_sha256
        timing_block["leg_seconds"] = {"off": legs.off_seconds, "on": legs.on_seconds}
        verdict, manifest = _evaluate_and_write_manifest(
            checks=checks,
            evidence=evidence,
            population=population,
            output_dir=SHADOW_GATE_OUTPUT_DIR,
            filename_stem=DIRB_SHADOW_DATASET_ID,
            report_type="dirb_shadow_gate",
            flags=DIRB_SHADOW_FLAGS,
            identity=_python_identity(),
            corpus=corpus_block,
            timing=timing_block,
            source_health=corpus_summary,
        )

        assert verdict == "pass"

        # B1: input identity across legs (standalone claim).
        assert legs.off_stats.total_input == legs.on_stats.total_input
        # B1: input sanity at corpus scale (a silently-empty frozen
        # dataset can never masquerade as a clean gate).
        assert legs.off_stats.total_input > 1_000_000
        # B2: added-lines empty -- write-time prunes can only vanish.
        assert not added
        # B3a: removed set equals the UNCAPPED ledger witness by identity.
        assert legs.on_ledger.wcs_candidates == removed
        # B3b: removed count equals the paired stats counter.
        assert legs.on_stats.wildcard_covered_sub_pruned == len(removed)
        # B4: ON total exceeds OFF by EXACTLY the removal count -- an
        # ON-side proven removal adds exactly one record while OFF-side
        # write-time keeps emit nothing. Never claim totals equality.
        assert on_total_records - off_total_records == len(removed)
        # B5a: whitelist bucket identical across legs AND equal to each
        # leg's own counter (three standalone claims).
        assert whitelist_off == whitelist_on
        assert whitelist_off == legs.off_stats.whitelist_conflict_pruned
        assert whitelist_on == legs.on_stats.whitelist_conflict_pruned
        # B5b: denyallow bucket identical -- both legs run production
        # default denyallow pruning; the dirb flag is the only mover.
        assert denyallow_off == denyallow_on
        # B6: uncertain-keeps EQUALITY stasis (D-21-10 -- deliberately
        # unlike a drop-by-prune-count; the stale minus-N spelling is
        # refused per 21-RESEARCH OQ2).
        assert kept_before == kept_after
        # B7: every other attribution bucket byte-stable, both directions.
        assert not mismatches_other_buckets
        # B8a: pairing completeness -- one uncapped pair per removal.
        assert len(pairs) == len(removed)
        # B8b: survivor-coverer membership -- every covering member lives
        # in the ON output set (PRUNE-02 survivor-only witnessing).
        assert not uncovered_pairs
        # B9: OFF-side witnessing stays empty: flag-OFF emits nothing.
        assert legs.off_ledger.wcs_candidates == set()
        assert legs.off_ledger.wcs_pairs == set()
        # R1: reconciliation matches the live audit (D-21-02).
        assert len(removed) == audit_expected
        # R2: population nonzero (D-21-01 literal -- a zero corpus reading
        # fails here by design and routes to stop-and-present).
        assert len(removed) > 0

        # Informational evidence block (magnitudes are calibration facts,
        # never verdict inputs -- Pitfall 11).
        print(f"\n[DIRB SHADOW] total_input={legs.off_stats.total_input:,}")
        print(f"[DIRB SHADOW] removed={len(removed):,}")
        print(f"[DIRB SHADOW] audit_expected={audit_expected} divergences={len(audit_divergences)}")
        for divergence in audit_divergences[:10]:
            print(f"[DIRB SHADOW] divergence: {divergence}")
        print(f"[DIRB SHADOW] off_output_sha256={legs.off_output_sha256[:16]}")
        print(f"[DIRB SHADOW] on_output_sha256={legs.on_output_sha256[:16]}")
        print(
            f"[DIRB SHADOW] off_leg_seconds={legs.off_seconds:.1f} "
            f"on_leg_seconds={legs.on_seconds:.1f}"
        )
        manifest_path = SHADOW_GATE_OUTPUT_DIR / f"{DIRB_SHADOW_DATASET_ID}.json"
        print(f"[DIRB SHADOW] verdict={verdict} manifest={manifest_path}")
        print(
            f"[DIRB SHADOW] timing medians off={timing_block['off']['median_seconds']}s "
            f"on={timing_block['on']['median_seconds']}s "
            f"same_corpus={timing_block['same_corpus']}"
        )


class TestDirbShadowGateChecksSpelling:
    """Fixture-scale twins pinning the B1-B10 plus R1 plus literal R2 spellings.

    RED-first: FAILS before _dirb_gate_checks exists, PASSES after. Runs
    the 21-01 _run_dirb_corpus_legs over the honest-zero fixture plus the
    live _audit_dirb_expectation, then pins every checks-dict spelling
    with exact equality. Scale-dependent keys read False here by
    construction (3-row fixture, zero removals); the slow gate asserts
    them True at corpus scale.
    """

    def _fixture_checks(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            legs = _run_dirb_corpus_legs(
                _shadow_line_factory(list(TestDirbShadowMachinery.DIRB_FIXTURE_LINES)),
                Path(tmpdir),
            )
        audit_expected, audit_divergences = _audit_dirb_expectation(list(legs.off_lines))
        checks, _ = _dirb_gate_checks(legs, audit_expected=audit_expected)
        return (
            legs,
            audit_expected,
            audit_divergences,
            checks,
        )

    def test_b_spellings_hold_exact_at_fixture_scale(self):
        """Every checks-dict spelling carries exact-equality form."""
        _, audit_expected, audit_divergences, checks = self._fixture_checks()
        assert audit_expected == 0
        assert audit_divergences == []
        assert checks["input_identity"] == (True, True)
        assert checks["input_rows_sanity"] == (False, True)
        assert checks["added_empty"] == (True, True)
        assert checks["removed_equals_uncapped_tally"] == (True, True)
        assert checks["removed_equals_counter"] == (True, True)
        assert checks["total_records_delta_equals_removed"] == (True, True)
        assert checks["whitelist_bucket_identical"] == (True, True)
        assert checks["denyallow_bucket_identical"] == (True, True)
        assert checks["uncertain_keeps_stasis"] == (True, True)
        assert checks["other_buckets_stable_both_directions"] == (True, True)
        assert checks["coverer_membership_complete"] == (True, True)
        assert checks["off_side_witnessing_empty"] == (True, True)
        assert checks["reconciliation_matches_audit"] == (True, True)
        assert checks["population_nonzero"] == (False, True)

    def test_r2_literal_fails_verdict_with_forensics_on_zero_removal(self):
        """A zero-removal fixture run yields verdict fail, never silent pass."""
        _, _, _, checks = self._fixture_checks()
        assert checks["population_nonzero"] == (False, True)
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            verdict, manifest = _evaluate_and_write_manifest(
                checks=checks,
                evidence={"input_rows": 3, "removed_count": 0},
                population={"total": 0, "audit_expected": 0, "audit_divergences": []},
                output_dir=output_dir,
                filename_stem="dirb-shadow-v1",
                report_type="dirb_shadow_gate",
                flags=DIRB_SHADOW_FLAGS,
            )
            assert verdict == "fail"
            assert manifest["verdict"] == "fail"
            assert manifest["checks"]["population_nonzero"] == {
                "observed": False,
                "expected": True,
                "ok": False,
            }
            assert (output_dir / "dirb-shadow-v1.json").is_file()
            assert (output_dir / "dirb-shadow-v1.md").is_file()

    def test_write_before_assert_leaves_dirb_forensics_on_forced_fail(self):
        """A forced failing check yields verdict fail with dirb siblings on disk."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            verdict, manifest = _evaluate_and_write_manifest(
                checks={"input_identity": (1, 2)},
                evidence={},
                population={},
                output_dir=output_dir,
                filename_stem="dirb-shadow-v1",
                report_type="dirb_shadow_gate",
                flags=DIRB_SHADOW_FLAGS,
            )
            assert verdict == "fail"
            assert manifest["verdict"] == "fail"
            assert manifest["report_type"] == "dirb_shadow_gate"
            assert manifest["flags"] == DIRB_SHADOW_FLAGS
            assert (output_dir / "dirb-shadow-v1.json").is_file()
            assert (output_dir / "dirb-shadow-v1.md").is_file()
            md_text = (output_dir / "dirb-shadow-v1.md").read_text(encoding="utf-8")
            assert "Dirb Shadow Gate: FAIL" in md_text
            assert "- Verdict: fail" in md_text

    def test_corpus_gate_stays_gated_without_freeze(self):
        """The corpus method stays slow-gated on the dirb present-flag.

        The class-level slow mark lives on the class object while the
        skipif mark lives on the method, so both owners are pinned: the
        skip reason must name the dirb dataset id.
        """
        class_marks = {mark.name for mark in getattr(TestDirbShadowEquivalence, "pytestmark", [])}
        method_marks = {
            mark.name
            for mark in (
                TestDirbShadowEquivalence.test_dirb_full_corpus_shadow_equivalence.pytestmark
            )
        }
        assert "slow" in class_marks
        assert "skipif" in method_marks
        assert DIRB_SHADOW_DATASET_ID in DIRB_FROZEN_SKIP_REASON


# ----------------------------------------------------------------------
# In-gate median-of-3 timing helper (Phase 21 plan 21-02, D-21-04 plus
# D-21-08 plus carried-forward D-20-04).
#
# Records cost informationally with benchmark-grade hygiene
# (gc.collect plus clear_caches between every run, perf_counter walls,
# per-run output sha, statistics median) and digest-pinned merge, never
# gating the verdict and never touching benchmark.py or any
# compile_flags surface. Drives compile_rules directly over a
# caller-supplied line factory; the slow gate passes its frozen corpus
# factory plus the pinned digest at canonical-run time.
# ----------------------------------------------------------------------


# D-20-04 binding: any future benchmark-CLI stamping for the wcs flag
# belongs to the flip milestone only -- this helper must never grow a
# benchmark surface or a compile_flags echo.
def _dirb_timing_medians(
    line_factory: Callable[[], Iterable[str]],
    *,
    frozen_digest: str,
    corpus_dir: Path | None = None,
    runs: int = 3,
) -> dict[str, object]:
    """Measure median-of-N compile cost per flag state, informational only.

    Per D-21-04 plus D-21-08 plus carried-forward D-20-04: reuses the
    median-leg hygiene (gc.collect plus clear_caches between every run,
    perf_counter walls, per-run output sha via _streaming_sha256,
    statistics median rounded to six decimals) with zero benchmark
    surface -- drives compile_rules directly, never the benchmark CLI,
    and emits no passes, bar percent, or compile-flags echo fields, so no
    consumer can mistake timing for a gate. OFF runs at production
    defaults; ON adds only wildcard_covers_subs_pruning=True, so the dirb
    flag is the sole mover. Digest-pinned merge: timing_corpus_digest
    recomputes from corpus_dir when given, else echoes frozen_digest at
    fixture scale; same_corpus is False on any mismatch so foreign-corpus
    evidence can never bless a manifest. Each leg's output_sha256 is the
    LAST run's digest for the gate's determinism cross-tie.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        workdir = Path(tmpdir)

        def _measure(extra_kwargs: dict[str, object]) -> tuple[list[float], list[str]]:
            durations: list[float] = []
            shas: list[str] = []
            for index in range(runs):
                gc.collect()
                clear_caches()
                output_path = workdir / f"dirb_timing_{index}.txt"
                start_ns = time.perf_counter_ns()
                compile_rules(line_factory(), str(output_path), **extra_kwargs)
                elapsed = round((time.perf_counter_ns() - start_ns) / 1_000_000_000, 6)
                durations.append(elapsed)
                shas.append(_streaming_sha256(output_path))
            return durations, shas

        off_durations, off_shas = _measure({})
        on_durations, on_shas = _measure({"wildcard_covers_subs_pruning": True})

    off_median = round(statistics.median(off_durations), 6)
    on_median = round(statistics.median(on_durations), 6)
    if off_median > 0:
        relative_overhead: float | None = round(_overhead_percent(off_median, on_median), 2)
    else:
        # Zero baseline over a tiny fixture: no relative percent is
        # definable, so the informational slot stays honestly null.
        relative_overhead = None

    if corpus_dir is not None:
        timing_digest = manifest_digest(build_corpus_manifest(corpus_dir))
    else:
        timing_digest = frozen_digest

    def _leg_block(durations: list[float], shas: list[str], median: float) -> dict[str, object]:
        return {
            "runs": runs,
            "durations_seconds": list(durations),
            "median_seconds": median,
            "output_sha256_stable": len(set(shas)) == 1,
            "output_sha256": shas[-1],
        }

    return {
        "methodology": (
            "in-gate median-of-N per leg over caller-supplied lines with "
            "gc.collect plus clear_caches between every run; informational "
            "only, never gating"
        ),
        "runs": runs,
        "off": _leg_block(off_durations, off_shas, off_median),
        "on": _leg_block(on_durations, on_shas, on_median),
        "relative_overhead_percent": relative_overhead,
        "timing_corpus_digest": timing_digest,
        "same_corpus": timing_digest == frozen_digest,
    }


class TestDirbTimingMedians:
    """Median-of-3 helper twins: hygiene, digest refusal, zero surface."""

    TIMING_FIXTURE_LINES = [
        "||*.autos^",
        "||sub.autos^",
        "||unrelated.xyz^",
    ]

    def _factory(self):
        return _shadow_line_factory(list(self.TIMING_FIXTURE_LINES))

    def test_median_helper_returns_three_runs_with_middle_median_and_stable_sha(self):
        """Three durations per leg with the median equal to the middle value."""
        block = _dirb_timing_medians(self._factory(), frozen_digest="fixture-scale")
        assert block["runs"] == 3
        assert len(block["off"]["durations_seconds"]) == 3
        assert len(block["on"]["durations_seconds"]) == 3
        assert block["off"]["median_seconds"] == sorted(block["off"]["durations_seconds"])[1]
        assert block["on"]["median_seconds"] == sorted(block["on"]["durations_seconds"])[1]
        assert block["off"]["output_sha256_stable"] is True
        assert block["on"]["output_sha256_stable"] is True
        assert block["same_corpus"] is True

    def test_digest_mismatch_refuses_merge_with_same_corpus_false(self):
        """Timing evidence against a foreign digest never blesses a manifest."""
        with tempfile.TemporaryDirectory() as tmpdir:
            corpus_dir = Path(tmpdir)
            (corpus_dir / "a.txt").write_text("||*.autos^\n", encoding="utf-8")
            block = _dirb_timing_medians(
                self._factory(),
                frozen_digest="0" * 64,
                corpus_dir=corpus_dir,
            )
        assert block["same_corpus"] is False
        assert block["timing_corpus_digest"] != "0" * 64

    def test_timing_block_carries_no_gate_or_benchmark_surface(self):
        """No passes, bar, or compile-flags echo anywhere in dirb timing."""
        block = _dirb_timing_medians(self._factory(), frozen_digest="fixture-scale")
        assert "passes" not in block
        assert "bar_percent" not in block
        assert "compile_flags" not in block
        assert "on_compile_flags" not in block
        assert "compile_flags" not in block["off"]
        assert "compile_flags" not in block["on"]

    def test_timing_keys_never_enter_the_verdict_checks_dict(self):
        """A slow run can only go red via R2, never via wall-clock spread."""
        with tempfile.TemporaryDirectory() as tmpdir:
            legs = _run_dirb_corpus_legs(
                _shadow_line_factory(list(self.TIMING_FIXTURE_LINES)),
                Path(tmpdir),
            )
        checks, _ = _dirb_gate_checks(legs, audit_expected=0)
        block = _dirb_timing_medians(self._factory(), frozen_digest="fixture-scale")
        assert not [name for name in checks if "timing" in name]
        assert not (set(block) & set(checks))
        failing = sorted(
            name for name, (observed, expected) in checks.items() if observed != expected
        )
        assert failing == ["input_rows_sanity", "population_nonzero"]
