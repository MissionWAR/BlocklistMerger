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

import pytest

import scripts.pruning_proof
from scripts.compiler import (
    CompileStats,
    _parse_abp_rule,
    _record_proven_pruning,
    _rule_storage_key,
    _wildcard_covers_sub,
    _write_output,
    compile_rules,
    get_tld,
    normalize_domain,
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
        tally = summary["by_reason"].get(REASON_WILDCARD_COVERS_SUB, 0)
        assert tally == stats.wildcard_covered_sub_pruned

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
        tally = summary["by_reason"].get(REASON_WILDCARD_COVERS_SUB, 0)
        assert tally == stats.wildcard_covered_sub_pruned


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

        assert stats_off.wildcard_covered_sub_pruned == 0
        assert summaries[COMPILER_STAGE_PRUNE]["reasons"] == {}
        assert "wcs_covered" not in summaries[COMPILER_STAGE_PRUNE]["reasons"]

    def test_missing_key_mapping_projection_stays_zero_safe(self):
        """An empty Mapping source projects cleanly with empty prune reasons.

        Direct evidence for the missing-key-safe projection this phase's
        ``wcs_covered`` mapping entry rides on (D-19-07 OFF side).
        """
        summaries = compiler_stage_summaries_from_stats({})

        assert summaries[COMPILER_STAGE_PRUNE]["reasons"] == {}


# ----------------------------------------------------------------------
# Builder-contract unit pins (Phase 19 plan 19-02, Tasks 1-2).
#
# These legs call _wildcard_covers_sub() DIRECTLY. Storages and
# candidates are built ONLY through production derivations --
# _parse_abp_rule for parsing and the parse-time get_tld bucketing for
# the wildcard side -- so no pin ever exercises hand-invented keys
# (D-19-06). Every fixture domain comes from the real-public-suffix
# closed vocabulary (autos / co.uk / com / example.com); synthetic TLD
# strings never reach the wildcard buckets, so they would prove nothing.
# ----------------------------------------------------------------------


class TestWcsCoveragePredicate:
    """Direct unit pins on _wildcard_covers_sub(): verdicts + determinism."""

    @staticmethod
    def _witness(texts):
        """Parse wildcard texts into a witness list preserving the given order."""
        records = []
        for text in texts:
            record = _parse_abp_rule(text)
            assert record is not None
            records.append(record)
        return records

    @staticmethod
    def _witness_tld(text):
        """Parse one wildcard and derive its parse-time TLD bucket key."""
        record = _parse_abp_rule(text)
        assert record is not None
        tld = get_tld(record.domain)
        assert tld is not None
        assert record.domain == tld  # fixture discipline: TLD-form wildcards only
        return record, tld

    @staticmethod
    def _candidate(text):
        """Parse one plain blocking rule into a candidate record."""
        record = _parse_abp_rule(text)
        assert record is not None
        return record

    @pytest.mark.parametrize(
        ("candidate_text",),
        [
            pytest.param("||sub.autos^", id="shallow-sub"),
            pytest.param("||deep.sub.autos^", id="deep-sub"),
        ],
    )
    def test_same_key_sub_is_covered_by_sole_witness(self, candidate_text):
        """Strict same-key subs at any depth resolve to the single covering witness.

        All three legs pass together: the domain leg admits same-key subs,
        the scope oracle proves empty-modifier coverage, and the denyallow
        leg imposes nothing without an admissible allow-set.
        """
        witness, tld = self._witness_tld("||*.autos^")

        covered = _wildcard_covers_sub(self._candidate(candidate_text), [witness], tld)

        assert covered is witness

    def test_apex_candidate_is_never_covered_by_its_own_wildcard(self):
        """AGH HasSuffix direction safety: the apex equals the key and is refused.

        PRUNE-03 leg 1: ``||*.autos^`` matches ``".autos"`` suffixes, so the
        apex ``autos`` itself can never be its own wildcard's coverage
        target; the domain-leg carve-out encodes this at the boundary.
        """
        witness, tld = self._witness_tld("||*.autos^")
        candidate = self._candidate("||autos^")

        covered = _wildcard_covers_sub(candidate, [witness], tld)

        assert covered is None

    def test_cross_key_candidate_is_structurally_uncoverable(self):
        """A candidate outside the key refuses even against supplied witnesses.

        D-16-02 lineage: strict same-key eligibility holds at the predicate
        boundary, so a buggy caller handing same-list cross-key witnesses
        cannot smuggle a coverage verdict.
        """
        witness, tld = self._witness_tld("||*.co.uk^")
        candidate = self._candidate("||example.com^")

        covered = _wildcard_covers_sub(candidate, [witness], tld)

        assert covered is None

    def test_mis_keyed_witness_object_is_never_trusted_as_coverage(self):
        """A witness failing its own TLD-form check cannot prove coverage.

        WR-01 mirror of test_cross_key_candidate_is_structurally_uncoverable,
        flipped to the witness side: the candidate sits strictly under the
        key and the mis-keyed ``||*.other.com^`` record carries no rejecting
        modifiers, so absent the eligibility leg the scope oracle would
        admit it and hand back an unsound "covered" verdict. The guard must
        skip such records instead of trusting caller bucket discipline --
        Phase 20 wires this predicate into write-time emission, where one
        mis-keyed bucket silently deletes blocking rules.
        """
        _, tld = self._witness_tld("||*.autos^")
        mis_keyed = self._witness(["||*.other.com^"])[0]
        candidate = self._candidate("||sub.autos^")

        covered = _wildcard_covers_sub(candidate, [mis_keyed], tld)

        assert covered is None

    def test_badfilter_carrier_witness_never_proves_coverage(self):
        """The oracle wholesale-rejects NO_COVERAGE carriers (:673-674).

        A ``$badfilter``-carrying wildcard is a disabling hint, not a
        blocking rule, so it must never prove coverage regardless of
        domain eligibility.
        """
        witness, tld = self._witness_tld("||*.autos^$badfilter")
        candidate = self._candidate("||sub.autos^")

        covered = _wildcard_covers_sub(candidate, [witness], tld)

        assert covered is None

    def test_denyallow_divergent_pairing_keeps_the_sub(self):
        """Denyallow divergence forces None through BOTH guarding mechanisms.

        Honest double-guard statement: the candidate's subtree intersects
        the witness's admissible allow-set (the reused _denyallow_allow_set +
        _domain_disjoint_from_all truth tables force KEEP), AND the scope
        oracle additionally rejects every denyallow carrier outright today
        via NO_COVERAGE_MODIFIERS membership. Neither mechanism may be
        weakened independently of the other.
        """
        witness, tld = self._witness_tld("||*.autos^$denyallow=a.autos^")
        candidate = self._candidate("||a.autos^")

        covered = _wildcard_covers_sub(candidate, [witness], tld)

        assert covered is None

    def test_denyallow_disjointness_alone_admits_nothing(self):
        """Disjointness is necessary-but-not-sufficient: carriers stay rejected.

        Pins that nobody may later assume the divergence leg alone admits
        denyallow witnesses: this pairing IS subtree-disjoint, yet carrier
        admission is governed by NO_COVERAGE_MODIFIERS, so the verdict is
        still None.
        """
        witness, tld = self._witness_tld("||*.autos^$denyallow=safe.autos^")
        candidate = self._candidate("||sub.autos^")

        covered = _wildcard_covers_sub(candidate, [witness], tld)

        assert covered is None

    def test_empty_witness_list_returns_none(self):
        """None-contract: no witnesses means no coverage verdict, ever."""
        _, tld = self._witness_tld("||*.autos^")
        candidate = self._candidate("||sub.autos^")

        covered = _wildcard_covers_sub(candidate, [], tld)

        assert covered is None

    def test_multi_coverer_returns_first_witness_in_storage_order(self):
        """Two simultaneously-covering witnesses resolve to exactly one: the first.

        D-19-04/D-19-09b forward-pin half: the scoped witness covers via the
        matching narrow-scope value-signature branch, the plain witness via
        the parent-absent narrow-scope skip -- storage order picks the winner.
        """
        scoped, tld = self._witness_tld("||*.autos^$client=10.0.0.1")
        plain = self._witness(["||*.autos^"])[0]
        candidate = self._candidate("||sub.autos^$client=10.0.0.1")

        covered = _wildcard_covers_sub(candidate, [scoped, plain], tld)

        assert covered is scoped

    def test_multi_coverer_flips_with_reversed_storage_order(self):
        """Reversing the list flips the winner: selection follows storage order.

        Companion to the forward-ordering pin proving iteration is
        first-match over the given order, never arbitrary preference.
        """
        scoped, tld = self._witness_tld("||*.autos^$client=10.0.0.1")
        plain = self._witness(["||*.autos^"])[0]
        candidate = self._candidate("||sub.autos^$client=10.0.0.1")

        covered = _wildcard_covers_sub(candidate, [plain, scoped], tld)

        assert covered is plain


# ----------------------------------------------------------------------
# PRUNE-03 conservative-keep matrix (Phase 19 plan 19-04).
#
# Tuple layout: (id, input lines, expected OFF output, expected ON output,
# expected OFF counter, expected ON counter). Output write order everywhere:
# abp_wildcards loop first, pruned_abp second. Every expectation below was
# captured from real compile_rules() under py -3.14 on 2026-08-26 and
# re-verified by a fresh capture run at authoring time (capture-not-predict);
# verdicts derive solely from _wildcard_covers_sub() legs and the
# pre-existing legacy prune families -- never copied from Direction-A
# verdicts. Counters are the wcs family counter, silent everywhere here.
# ----------------------------------------------------------------------

ROWS = (
    (
        "apex-exclusion-com-apex",
        ["||com^", "||*.com^"],
        ["||*.com^", "||com^"],
        ["||*.com^", "||com^"],
        0,
        0,
    ),
    (
        "apex-exclusion-com-sub",
        ["||a.com^", "||*.com^"],
        ["||*.com^"],
        ["||*.com^"],
        0,
        0,
    ),
    (
        "apex-exclusion-com-deep-sub",
        ["||b.a.com^", "||*.com^"],
        ["||*.com^"],
        ["||*.com^"],
        0,
        0,
    ),
    (
        "badfilter-carrier-witness-keep",
        ["||*.autos^$badfilter", "||sub.autos^"],
        ["||sub.autos^"],
        ["||sub.autos^"],
        0,
        0,
    ),
    (
        "important-presence-asymmetry-keep",
        ["||*.autos^", "||sub.autos^$important"],
        ["||*.autos^", "||sub.autos^$important"],
        ["||*.autos^", "||sub.autos^$important"],
        0,
        0,
    ),
    (
        "dnstype-narrower-value-signature-keep",
        ["||*.autos^$dnstype=AAAA", "||sub.autos^$dnstype=A|AAAA"],
        ["||*.autos^$dnstype=AAAA", "||sub.autos^$dnstype=A|AAAA"],
        ["||*.autos^$dnstype=AAAA", "||sub.autos^$dnstype=A|AAAA"],
        0,
        0,
    ),
    (
        "denyallow-divergent-subtree-keep",
        ["||*.autos^$denyallow=a.autos^", "||a.autos^"],
        ["||*.autos^$denyallow=a.autos^", "||a.autos^"],
        ["||*.autos^$denyallow=a.autos^", "||a.autos^"],
        0,
        0,
    ),
    (
        "cross-key-impossibility-co-uk",
        ["||*.co.uk^$client=10.0.0.1", "||example.co.uk^"],
        ["||*.co.uk^$client=10.0.0.1", "||example.co.uk^"],
        ["||*.co.uk^$client=10.0.0.1", "||example.co.uk^"],
        0,
        0,
    ),
)


class TestWcsKeepMatrix:
    """PRUNE-03 conservative-keep matrix asserted in BOTH flag states, plus dives."""

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
    def test_wcs_keep_matrix_rows_verdicts_both_flag_states(
        self,
        lines,
        expected_off_output,
        expected_on_output,
        expected_off_counter,
        expected_on_counter,
    ):
        """Eight conservative-keep rows in both flag states through the real compiler.

        Per-row oracle map (roles swapped vs Direction-A; branches of
        modifier_scope_covers(), rule_semantics.py:650-700, reached through
        _find_covering_parent_record() or refused by _wildcard_covers_sub()):
        - apex-exclusion-com-apex: the _wildcard_covers_sub() domain-leg apex
          carve-out encodes AGH HasSuffix direction safety -- ``||*.com^``
          suffix-matches dot-com hosts and can never cover the apex ``com``
          itself. No wcs emission site exists yet, so today the keep is
          structural; the row forward-pins Phase-20 direction safety.
        - apex-exclusion-com-sub / -deep-sub: pruned TODAY by the LEGACY
          tld-wildcard family (increment+record adjacency at
          compiler.py:1569-1575) while the wcs predicate would likewise admit
          coverage (strict same-key domain leg + the empty-modifier scope
          branch at :660-661). The rows pin wcs-zero pre-emission plus
          single-family attribution: one rule => one reason => one counter,
          which Phase 20's D-19-04 precedence must preserve.
        - badfilter-carrier-witness-keep: the $badfilter wildcard is
          discarded upstream at parse classification (rule_effect_disable),
          and the oracle NO_COVERAGE_MODIFIERS wholesale reject (:673-674)
          is the backstop if a disabled rule ever leaked into storage.
        - important-presence-asymmetry-keep: presence asymmetry rejects --
          the parent lacks $important while the child carries it (:679-687).
        - dnstype-narrower-value-signature-keep: a narrower witness
          value-signature cannot cover a broader child (:697-698).
        - denyallow-divergent-subtree-keep: honest dual guard -- the oracle
          wholesale-rejects denyallow carriers (:673-674), AND the divergence
          leg via _denyallow_allow_set / _domain_disjoint_from_all finds the
          candidate subtree intersecting the admissible allow-set, so the
          keep holds even if carrier rejection were ever relaxed.
        - cross-key-impossibility-co-uk: strict same-key projection
          structurally forbids witnessing (D-16-02 lineage); the secondary
          guard is the narrow-scope parent-without-child reject (:693-698),
          which also keeps the LEGACY family silent on this pairing.

        Anchors drift -- re-grep before citing. Every leg runs on a fresh
        CappedProofLedger; one claim per assert.
        """
        ledger_off = CappedProofLedger()
        ledger_on = CappedProofLedger()

        rules_off, stats_off = _compile(lines, proof_ledger=ledger_off)

        assert rules_off == expected_off_output
        assert stats_off.wildcard_covered_sub_pruned == expected_off_counter
        summary_off = ledger_off.summary()
        assert REASON_WILDCARD_COVERS_SUB not in summary_off["by_reason"]

        rules_on, stats_on = _compile(
            lines,
            proof_ledger=ledger_on,
            wildcard_covers_subs_pruning=True,
        )

        assert rules_on == expected_on_output
        assert stats_on.wildcard_covered_sub_pruned == expected_on_counter
        summary_on = ledger_on.summary()
        assert REASON_WILDCARD_COVERS_SUB not in summary_on["by_reason"]

    def test_wcs_matrix_legacy_attribution_is_single_family(self):
        """Sub-prune fixture: exactly ONE legacy reason family fires, in both legs.

        The legacy tld-wildcard removal records under REASON_TLD_WILDCARD_COVERED
        and bumps its own counter; the wcs family stays silent (counter 0, no
        ledger entry) even though the same pairing would be wcs-eligible once
        Phase 20 wires emission. Exact-dict equality proves no other reason
        fired alongside.
        """
        lines = ["||a.com^", "||*.com^"]

        ledger_off = CappedProofLedger()
        _, stats_off = _compile(lines, proof_ledger=ledger_off)

        assert stats_off.tld_wildcard_pruned == 1
        assert ledger_off.summary()["by_reason"] == {REASON_TLD_WILDCARD_COVERED: 1}
        assert stats_off.wildcard_covered_sub_pruned == 0

        ledger_on = CappedProofLedger()
        _, stats_on = _compile(
            lines,
            proof_ledger=ledger_on,
            wildcard_covers_subs_pruning=True,
        )

        assert stats_on.tld_wildcard_pruned == 1
        assert ledger_on.summary()["by_reason"] == {REASON_TLD_WILDCARD_COVERED: 1}
        assert stats_on.wildcard_covered_sub_pruned == 0

    def test_wcs_matrix_badfilter_discard_evidence_pinned_in_both_legs(self):
        """Badfilter row evidence pin: upstream discard counted in both legs.

        Mirrors the apex sibling row5 dive: rule_effect_disable counts the
        classification regardless of flag state, and the disabled rule never
        reaches either output list.
        """
        lines = ["||*.autos^$badfilter", "||sub.autos^"]

        rules_off, stats_off = _compile(lines)

        assert stats_off.rule_effect_disable == 1
        assert "||*.autos^$badfilter" not in rules_off

        rules_on, stats_on = _compile(lines, wildcard_covers_subs_pruning=True)

        assert stats_on.rule_effect_disable == 1
        assert "||*.autos^$badfilter" not in rules_on


# ----------------------------------------------------------------------
# Forward-pinned Phase-20 traps + EVID-02 normalization round-trips
# (Phase 19 plan 19-04). Fixture expectations below were captured from
# real compile_rules() under py -3.14 on 2026-08-26 and re-verified by a
# fresh capture run at authoring time (capture-not-predict).
# ----------------------------------------------------------------------


class TestWcsForwardPinnedTraps:
    """D-19-09 executable spec: fixtures Phase 20's emission wiring keeps green.

    These traps carry hard observable claims driven through the REAL
    compiler in both flag states. Phase 20 adds wcs attribution teeth on
    top of today's behavior; any emission change that breaks survivorship
    ordering or double-counts a removal fails here loudly first.
    """

    def test_self_exceptiond_wildcard_survivorship_keeps_sub_both_states(self):
        """A wildcard failing its OWN exception screen leaves its bare sub alive.

        Survivorship ordering (research Pitfall 1): the wildcard is removed at
        the whitelist-conflict stage, upstream of any witnessing -- a dead
        wildcard must never witness. The exact-signature exception
        ``@@||*.autos^$client=10.0.0.1`` screens only the identical blocker;
        the bare sub survives in both flag states with the wcs family silent.
        Phase 20 keeps this green while adding attribution teeth.
        """
        lines = [
            "@@||*.autos^$client=10.0.0.1",
            "||*.autos^$client=10.0.0.1",
            "||sub.autos^",
        ]

        ledger_off = CappedProofLedger()
        rules_off, stats_off = _compile(lines, proof_ledger=ledger_off)

        assert rules_off == ["||sub.autos^"]
        assert stats_off.whitelist_conflict_pruned == 1
        assert stats_off.wildcard_covered_sub_pruned == 0
        assert REASON_WILDCARD_COVERS_SUB not in ledger_off.summary()["by_reason"]
        assert "||sub.autos^" in rules_off

        ledger_on = CappedProofLedger()
        rules_on, stats_on = _compile(
            lines,
            proof_ledger=ledger_on,
            wildcard_covers_subs_pruning=True,
        )

        assert rules_on == ["||sub.autos^"]
        assert stats_on.whitelist_conflict_pruned == 1
        assert stats_on.wildcard_covered_sub_pruned == 0
        assert REASON_WILDCARD_COVERS_SUB not in ledger_on.summary()["by_reason"]
        assert "||sub.autos^" in rules_on

    def test_multi_coverer_removal_recorded_exactly_once_compile_level(self):
        """Two candidate coverers yield exactly ONE removal record (D-19-04/09b).

        Compile-level completion of the D-19-04 no-double-count contract
        (19-02 pinned the predicate half): the sub removal records under the
        legacy tld-wildcard family exactly once -- by_reason equals
        {REASON_TLD_WILDCARD_COVERED: 1} as an EXACT dict -- both wildcards
        survive, and the wcs family stays silent in both flag states. Phase
        20's precedence rule must keep exactly-one-record-per-removal.
        """
        lines = [
            "||*.autos^",
            "||*.autos^$client=10.0.0.1",
            "||sub.autos^$client=10.0.0.1",
        ]

        ledger_off = CappedProofLedger()
        rules_off, stats_off = _compile(lines, proof_ledger=ledger_off)

        assert rules_off == ["||*.autos^", "||*.autos^$client=10.0.0.1"]
        assert stats_off.tld_wildcard_pruned == 1
        assert ledger_off.summary()["by_reason"] == {REASON_TLD_WILDCARD_COVERED: 1}
        assert stats_off.wildcard_covered_sub_pruned == 0
        assert REASON_WILDCARD_COVERS_SUB not in ledger_off.summary()["by_reason"]

        ledger_on = CappedProofLedger()
        rules_on, stats_on = _compile(
            lines,
            proof_ledger=ledger_on,
            wildcard_covers_subs_pruning=True,
        )

        assert rules_on == ["||*.autos^", "||*.autos^$client=10.0.0.1"]
        assert stats_on.tld_wildcard_pruned == 1
        assert ledger_on.summary()["by_reason"] == {REASON_TLD_WILDCARD_COVERED: 1}
        assert stats_on.wildcard_covered_sub_pruned == 0
        assert REASON_WILDCARD_COVERS_SUB not in ledger_on.summary()["by_reason"]


class TestWcsNormalizationRoundTrips:
    """EVID-02: exactly ONE canonical key path exists and variants resolve through it.

    The canonical path is normalize_domain -> get_tld -> _rule_storage_key.
    These pins prove case and trailing-dot variants collapse THROUGH that
    single path, that punycode labels stay DISTINCT opaque keys (no folding
    beyond the canonical path is claimed), and that the path's unit behavior
    matches production derivations only.
    """

    def test_case_variant_pair_collapses_via_canonical_path(self):
        """Case-variant ABP pair collapses to one rule; first-seen text survives.

        The storage key collapsed (duplicate_pruned == 1) while the SURVIVING
        TEXT keeps first-seen casing -- captured from real output.
        """
        rules, stats = _compile(["||ADS.Example.COM^", "||ads.example.com^"])

        assert len(rules) == 1
        assert rules == ["||ADS.Example.COM^"]
        assert stats.duplicate_pruned == 1

    def test_hosts_form_case_and_trailing_dot_roundtrip_collapses(self):
        """Hosts hostname lands on an identical signature to the explicit rule.

        The hosts-form entry passes through the same canonical path (case
        folding plus trailing-dot trim via normalize_domain) BEFORE
        compression, so it collapses onto the explicit lowercase ABP rule.
        """
        rules, stats = _compile(["0.0.0.0 ADS.Example.COM.", "||ads.example.com^"])

        assert rules == ["||ads.example.com^"]
        assert stats.duplicate_pruned == 1

    def test_punycode_labels_stay_distinct_opaque_keys(self):
        """Punycode and unicode-label twins survive as TWO distinct rules.

        Honesty contract: a repo-wide search finds NO IDNA/punycode
        conversion anywhere in scripts/ (verified again at authoring capture,
        2026-08-26); xn-- labels are opaque keys and the unicode label parses
        and stores verbatim. NO unicode-equivalence is claimed -- these two
        rules are distinct keys by design, and duplicate_pruned reads 0. Any
        future folding change MUST consciously revisit this pin.
        """
        rules, stats = _compile(["||xn--e1afmkfd.xn--p1ai^", "||пример.рф^"])

        assert len(rules) == 2
        assert "||xn--e1afmkfd.xn--p1ai^" in rules
        assert "||пример.рф^" in rules
        assert stats.duplicate_pruned == 0

    def test_canonical_path_unit_pins(self):
        """Direct pins over production derivations only (no hand-invented keys).

        Pins the canonical path end to end: normalize_domain folds case and
        trailing dots (reaching punycode LABELS too -- they are plain
        strings), storage keys equal for case variants, unicode labels parse
        opaquely untransformed, and get_tld("com") proves com reaches the
        real wildcard buckets (D-19-06 bucket discipline).
        """
        record_mixed_case = _parse_abp_rule("||ADS.Example.COM^")
        record_lower_case = _parse_abp_rule("||ads.example.com^")
        assert record_mixed_case is not None
        assert record_lower_case is not None

        assert normalize_domain("ADS.Example.COM.") == "ads.example.com"
        assert normalize_domain("XN--E1AFMKFD.XN--P1AI.") == "xn--e1afmkfd.xn--p1ai"

        mixed_key = _rule_storage_key(record_mixed_case)
        lower_key = _rule_storage_key(record_lower_case)
        assert mixed_key == lower_key

        unicode_record = _parse_abp_rule("||пример.рф^")
        assert unicode_record is not None
        assert unicode_record.domain == "пример.рф"

        assert get_tld("com") == "com"
        wildcard_record = _parse_abp_rule("||*.com^")
        assert wildcard_record is not None
        assert wildcard_record.domain == get_tld(wildcard_record.domain)


class TestWcsEmissionGolden:
    """Direct-drive both-state emission golden against _write_output() (PRUNE-02).

    Compile-level emission is provably zero-yield today (phase 3's TLD
    branch runs the same scope oracle over a strict superset of any
    write-time survivor pool), so nonzero emission behavior is exercisable
    ONLY by driving _write_output() directly with builder-contract
    storages. This golden pins BOTH flag states at the wired site:

    - OFF (kwarg omitted): legacy path instruction-for-instruction --
      both lines written in loop order (wildcard loop first, then the
      plain loop), counter 0, ledger empty, paired total.
    - ON: exactly the witnessed sub pruned -- output keeps only the
      wildcard line, counter 1, exactly ONE canonical ledger record,
      tally == counter 1:1 (D-19-04), paired total.

    Every literal below was captured from real runs under py -3.14 at
    authoring time (capture-not-predict); records are built strictly via
    _parse_abp_rule over the real-public-suffix vocabulary (autos,
    D-19-06). compile_rules() is deliberately NEVER called here --
    compile-level identity legs belong to later plans.
    """

    def test_flag_off_keeps_legacy_emission_with_zero_counter_and_empty_ledger(
        self,
        tmp_path,
    ):
        """OFF leg: both lines written in loop order; counter 0; ledger empty.

        Mirrors the apex_survivor_index OFF contract ("None keeps the
        legacy emission path instruction-for-instruction"): omitting the
        kwarg entirely must write BOTH storages' lines with zero wcs
        accounting anywhere.
        """
        witness = _parse_abp_rule("||*.autos^")
        candidate = _parse_abp_rule("||sub.autos^")
        assert witness is not None
        assert witness.is_wildcard and witness.domain == "autos"  # TLD-form fixture
        assert candidate is not None
        assert not candidate.is_wildcard

        stats = CompileStats()
        ledger = CappedProofLedger()
        output_path = tmp_path / "off.txt"
        _write_output(
            str(output_path),
            stats,
            {"autos": [witness]},
            {"sub.autos": [candidate]},
            [],
            set(),
            ledger,
        )

        with open(output_path, encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]

        assert lines == ["||*.autos^", "||sub.autos^"]
        assert stats.wildcard_covered_sub_pruned == 0
        summary = ledger.summary()
        assert REASON_WILDCARD_COVERS_SUB not in summary["by_reason"]
        assert stats.total_output == stats.abp_kept + stats.other_kept
        assert stats.total_output == 2

    def test_flag_on_prunes_only_the_witnessed_sub_with_single_proven_record(
        self,
        tmp_path,
    ):
        """ON leg: witnessed sub skipped with 1:1 counter+ledger accounting.

        The sole surviving same-key wildcard witnesses at its actual-write
        point, so the plain sub is proven-covered by _wildcard_covers_sub()
        and skipped: output keeps only the wildcard line, the counter bumps
        exactly once, and exactly ONE canonical record lands carrying the
        full sample shape (D-19-02) with tally == counter (D-19-04).
        """
        witness = _parse_abp_rule("||*.autos^")
        candidate = _parse_abp_rule("||sub.autos^")
        assert witness is not None
        assert witness.is_wildcard and witness.domain == "autos"  # TLD-form fixture
        assert candidate is not None
        assert not candidate.is_wildcard

        stats = CompileStats()
        ledger = CappedProofLedger()
        output_path = tmp_path / "on.txt"
        _write_output(
            str(output_path),
            stats,
            {"autos": [witness]},
            {"sub.autos": [candidate]},
            [],
            set(),
            ledger,
            wildcard_covers_subs_pruning=True,
        )

        with open(output_path, encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]

        assert lines == ["||*.autos^"]
        assert stats.wildcard_covered_sub_pruned == 1
        matches = [
            record for record in ledger.records if record.reason == REASON_WILDCARD_COVERS_SUB
        ]
        assert len(matches) == 1
        sample = matches[0].sample
        assert sample["candidate_rule"] == "||sub.autos^"
        assert sample["covering_rule"] == "||*.autos^"
        assert sample["modifier_scope_proven"] is True
        tally = ledger.summary()["by_reason"][REASON_WILDCARD_COVERS_SUB]
        assert tally == 1
        assert stats.wildcard_covered_sub_pruned == tally
        assert stats.total_output == stats.abp_kept + stats.other_kept
        assert stats.total_output == 1
