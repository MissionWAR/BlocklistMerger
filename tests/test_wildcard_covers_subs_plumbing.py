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
    REASON_APEX_COVERS_TLD_WILDCARD,
    REASON_KEPT_BECAUSE_UNCERTAIN,
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


# Posture note (2026-08-26, plan 20-02): flagged emission went live behind
# wildcard_covers_subs_pruning in 20-01; the module-header zero-behavior
# paragraphs above describe the Phase-19 baseline era; classes below prove
# post-emission semantics (D-20-01 / D-20-02 / SC2 / SC3).

# ----------------------------------------------------------------------
# Phase 20 plan 20-02 appended region: post-emission SEMANTICS legs.
#
# Everything below drives _write_output() DIRECTLY -- research
# consequence C1 holds that nonzero emission is invisible through
# compile_rules(). Storages are builder-contract only (_parse_abp_rule
# records over production key derivations; real public suffixes per
# D-19-06); every literal was scratch-captured under py -3.14 before
# being pasted (capture-not-predict).
# ----------------------------------------------------------------------


def _drive_emission(
    abp_wildcards,
    pruned_abp,
    proof_ledger,
    wildcard_covers_subs_pruning=False,
    apex_survivor_index=None,
):
    """One canonical direct-drive invocation of _write_output() (20-02).

    Mirrors the module's _compile body (tempfile + stripped-nonempty
    utf-8 read-back) at the write seam: positional arguments follow the
    pre-wiring signature order (output_file, stats, abp_wildcards,
    pruned_abp, exceptions, other_rules, proof_ledger); the flag-era
    kwargs ride keyword-only. Returns (rules, stats) with a fresh
    CompileStats per call; the caller owns the ledger so by_reason
    evidence stays inspectable after the drive.
    """
    stats = CompileStats()
    with tempfile.TemporaryDirectory() as tmpdir:
        output = os.path.join(tmpdir, "output.txt")
        _write_output(
            output,
            stats,
            abp_wildcards,
            pruned_abp,
            [],
            set(),
            proof_ledger,
            wildcard_covers_subs_pruning=wildcard_covers_subs_pruning,
            apex_survivor_index=apex_survivor_index,
        )
        with open(output, encoding="utf-8") as f:
            rules = [line.strip() for line in f if line.strip()]
    return rules, stats


class TestWcsMisKeyedWitnessSilentSkip:
    """D-20-01 FINAL call: ineligible witnesses skip SILENTLY (WR-01).

    Confirms the 19-REVIEW-FIX WR-01 skip semantics through the REAL
    Loop-A population + Loop-B probe path wired in 20-01 -- not by
    calling the predicate directly: hand-placed ineligible occupants in
    a wildcard bucket reach the predicate exactly as production records
    would. Every leg demands: candidate survives, counter 0, EXACT-
    equality empty ledger, no exception. Teeth-proven non-vacuous by the
    WR-01 mutation cycle documented in 20-02-SUMMARY.md (leg A1 alone
    goes red when the skip is mutated into a return).
    """

    @staticmethod
    def _candidate():
        """Parse the plain same-key subdomain candidate."""
        record = _parse_abp_rule("||sub.autos^")
        assert record is not None
        assert not record.is_wildcard
        assert record.domain == "sub.autos"
        assert get_tld(record.domain) == "autos"
        return record

    def test_a1_nonwildcard_occupant_is_skipped_silently(self):
        """An apex-shaped occupant witnesses nothing: keep, counter 0, silence.

        The hand-placed ``||autos^`` record (is_wildcard False) survives
        Loop A, lands in index["autos"] via the real population, and is
        fetched by the real probe -- then the WR-01 leg refuses it. The
        publish path must not crash and the ledger must not hear about it.
        """
        witness = _parse_abp_rule("||autos^")
        assert witness is not None
        assert not witness.is_wildcard  # deliberately ineligible occupant
        assert witness.domain == "autos"
        ledger = CappedProofLedger()

        rules, stats = _drive_emission(
            {"autos": [witness]},
            {"sub.autos": [self._candidate()]},
            ledger,
            wildcard_covers_subs_pruning=True,
        )

        assert rules == ["||autos^", "||sub.autos^"]
        assert stats.wildcard_covered_sub_pruned == 0
        assert ledger.summary()["by_reason"] == {}
        assert stats.total_output == 2

    def test_a2_foreign_keyed_wildcard_never_reaches_the_autos_probe(self):
        """A cross-key wildcard lands in its OWN bucket: the probe finds nothing.

        Population keys survivors by record.domain, so the foreign
        ``other.com`` wildcard is unreachable from the same-key "autos"
        probe regardless of which bucket it was hand-placed into: the
        candidate keeps with zero counter movement and an empty ledger.
        """
        mis_keyed = _parse_abp_rule("||*.other.com^")
        assert mis_keyed is not None
        assert mis_keyed.is_wildcard
        assert mis_keyed.domain == "other.com"  # foreign suffix: own bucket
        ledger = CappedProofLedger()

        rules, stats = _drive_emission(
            {"autos": [mis_keyed]},
            {"sub.autos": [self._candidate()]},
            ledger,
            wildcard_covers_subs_pruning=True,
        )

        assert rules == ["||*.other.com^", "||sub.autos^"]
        assert stats.wildcard_covered_sub_pruned == 0
        assert ledger.summary()["by_reason"] == {}

    def test_a3_mis_keyed_neighbor_leaves_genuine_attribution_exact(self):
        """One polluted bucket still yields EXACTLY ONE record (D-19-04).

        The mis-keyed neighbor corrupts nothing: it is written by Loop A
        but keyed into its own foreign bucket, so the genuine TLD-form
        witness prunes the candidate exactly once -- by_reason equals
        {REASON_WILDCARD_COVERS_SUB: 1} EXACT, the sample cites the
        genuine covering rule, and the candidate line is absent.
        """
        mis_keyed = _parse_abp_rule("||*.other.com^")
        assert mis_keyed is not None
        assert mis_keyed.is_wildcard
        assert mis_keyed.domain == "other.com"  # foreign suffix: own bucket
        genuine = _parse_abp_rule("||*.autos^")
        assert genuine is not None
        assert genuine.is_wildcard and genuine.domain == "autos"  # TLD-form fixture
        ledger = CappedProofLedger()

        rules, stats = _drive_emission(
            {"autos": [mis_keyed, genuine]},
            {"sub.autos": [self._candidate()]},
            ledger,
            wildcard_covers_subs_pruning=True,
        )

        assert rules == ["||*.other.com^", "||*.autos^"]
        assert "||sub.autos^" not in rules
        assert stats.wildcard_covered_sub_pruned == 1
        assert ledger.summary()["by_reason"] == {REASON_WILDCARD_COVERS_SUB: 1}
        matches = [
            record for record in ledger.records
            if record.reason == REASON_WILDCARD_COVERS_SUB
        ]
        assert len(matches) == 1
        sample = matches[0].sample
        assert sample["candidate_rule"] == "||sub.autos^"
        assert sample["covering_rule"] == "||*.autos^"
        assert sample["modifier_scope_proven"] is True
        assert stats.total_output == 2


class TestWcsWildcardCandidateKeep:
    """Loop-B probes PLAIN candidates only -- wildcard candidates keep untouched.

    The flag docstring promises "every plain subdomain record is additionally
    proven" and the helper types its candidate as a plain blocking rule, so a
    non-TLD wildcard sitting in pruned_abp (here ``||*.sub.autos^`` keyed via
    the production ``_rule_storage_key``) must keep via write+bump with no
    probe: both lines written, counter 0, by_reason exactly empty under flag
    ON. Without the guard the same-key probe would fire and prune it.
    """

    def test_wildcard_candidate_survives_probe_untouched_flag_on(self):
        """Non-TLD wildcard candidate keeps with zero counter/ledger movement."""
        witness = _parse_abp_rule("||*.autos^")
        assert witness is not None
        assert witness.is_wildcard and witness.domain == "autos"  # TLD-form fixture
        candidate = _parse_abp_rule("||*.sub.autos^")
        assert candidate is not None
        assert candidate.is_wildcard  # non-TLD wildcard: out of probe scope
        assert get_tld(candidate.domain) == "autos"  # same key: probe fires unguarded
        ledger = CappedProofLedger()

        rules, stats = _drive_emission(
            {"autos": [witness]},
            {_rule_storage_key(candidate): [candidate]},
            ledger,
            wildcard_covers_subs_pruning=True,
        )

        assert rules == ["||*.autos^", "||*.sub.autos^"]
        assert stats.wildcard_covered_sub_pruned == 0
        assert ledger.summary()["by_reason"] == {}
        assert stats.total_output == stats.abp_kept + stats.other_kept
        assert stats.total_output == 2


class TestWcsFailedProofSilentKeep:
    """D-20-02 FINAL call: failed proofs KEEP silently -- ZERO ledger noise.

    Phase 3 records uncertain keeps via _record_uncertain_keep(); the
    wired write-time site must NOT: a failed modifier-scope proof leaves
    no proven record AND no kept_because_uncertain entry, so the ON-OFF
    ledger delta outside the wcs family stays exactly zero and Phase-21's
    five-leg signature stays clean of flag-dependent bucket noise.
    """

    @staticmethod
    def _storages():
        """Build the narrower-witness/broader-candidate pairing."""
        witness = _parse_abp_rule("||*.autos^$dnstype=AAAA")
        assert witness is not None
        assert witness.is_wildcard and witness.domain == "autos"  # TLD-form fixture
        candidate = _parse_abp_rule("||sub.autos^")
        assert candidate is not None
        assert not candidate.modifiers  # broader scope: the oracle must refuse
        return {"autos": [witness]}, {"sub.autos": [candidate]}

    def test_b1_failed_scope_proof_keeps_candidate_without_any_record(self):
        """Narrower value-signature cannot cover: keep, counter 0, EMPTY ledger.

        The eligible same-key witness exists, so the probe fires -- but
        the scope oracle refuses the narrower $dnstype signature against
        the modifier-free child (the 19-04 dnstype row). The keep is
        UNRECORDED: by_reason equals {} EXACT, which subsumes both
        absence checks -- no wcs record AND no kept_because_uncertain
        entry ever reaches the ledger from this site.
        """
        wildcards, plains = self._storages()
        ledger = CappedProofLedger()

        rules, stats = _drive_emission(
            wildcards,
            plains,
            ledger,
            wildcard_covers_subs_pruning=True,
        )

        assert rules == ["||*.autos^$dnstype=AAAA", "||sub.autos^"]
        assert stats.wildcard_covered_sub_pruned == 0
        assert ledger.summary()["by_reason"] == {}
        assert stats.total_output == 2

    def test_b2_uncertain_tally_stasis_holds_in_both_flag_states(self):
        """Full by_reason equality OFF vs ON; uncertain tally 0 in both.

        Drives the identical storages twice with fresh ledgers: the wired
        site never calls the uncertain-keep recorder, so the whole ledger
        vocabulary is flag-invariant here (stasis per D-20-02).
        """
        wildcards, plains = self._storages()
        ledger_off = CappedProofLedger()
        ledger_on = CappedProofLedger()

        rules_off, _ = _drive_emission(wildcards, plains, ledger_off)
        rules_on, _ = _drive_emission(
            wildcards,
            plains,
            ledger_on,
            wildcard_covers_subs_pruning=True,
        )

        by_reason_off = ledger_off.summary()["by_reason"]
        by_reason_on = ledger_on.summary()["by_reason"]
        assert by_reason_off.get(REASON_KEPT_BECAUSE_UNCERTAIN, 0) == 0
        assert by_reason_on.get(REASON_KEPT_BECAUSE_UNCERTAIN, 0) == 0
        assert by_reason_off == by_reason_on
        assert rules_off == rules_on


class TestWcsSurvivorshipAcrossFlags:
    """SC2: an apex-killed wildcard never witnesses -- composition is correct.

    Research Pitfall 1 survivorship ordering made mechanical: Loop-A's
    apex-proof continue sits strictly BEFORE the wcs population point, so
    a wildcard killed by its own same-key apex never reaches the write
    point, never enters wcs_survivor_index, and can never witness. The
    nominally-covered sub therefore SURVIVES while the apex prune is
    recorded -- automatic flag-composition correctness proven through one
    direct drive with a hand-built apex_survivor_index. The index is
    lookup data only: the apex itself rides in pruned_abp so it still
    writes (only Loop A/B writes lines).
    """

    def test_apex_killed_wildcard_never_witnesses_and_the_sub_survives(self):
        """Apex-proof kill starves the witness pool: sub writes, counter 0.

        One drive, both flags composed ON: the apex prune records exactly
        once under its own reason family while the wcs family stays silent
        -- the candidate line is present despite its nominally-covering
        wildcard existing in the storages.
        """
        apex = _parse_abp_rule("||autos^")
        assert apex is not None
        assert not apex.is_wildcard
        assert apex.domain == "autos"
        witness = _parse_abp_rule("||*.autos^")
        assert witness is not None
        assert witness.is_wildcard and witness.domain == "autos"  # TLD-form fixture
        candidate = _parse_abp_rule("||sub.autos^")
        assert candidate is not None
        assert not candidate.is_wildcard and get_tld(candidate.domain) == "autos"
        ledger = CappedProofLedger()

        rules, stats = _drive_emission(
            {"autos": [witness]},
            {"autos": [apex], "sub.autos": [candidate]},
            ledger,
            wildcard_covers_subs_pruning=True,
            apex_survivor_index={"autos": [apex]},
        )

        assert rules == ["||autos^", "||sub.autos^"]
        assert stats.apex_covered_wildcard_pruned == 1
        assert stats.wildcard_covered_sub_pruned == 0
        assert ledger.summary()["by_reason"] == {REASON_APEX_COVERS_TLD_WILDCARD: 1}
        matches = [
            record for record in ledger.records
            if record.reason == REASON_APEX_COVERS_TLD_WILDCARD
        ]
        assert len(matches) == 1
        sample = matches[0].sample
        assert sample["candidate_rule"] == "||*.autos^"
        assert sample["covering_rule"] == "||autos^"
        assert stats.total_output == 2


class TestWcsPairedAccountingTotals:
    """SC3: skip accounting stays paired and total in BOTH flag states.

    ROADMAP SC3 + Anti-Pattern 5 (one continue guarding write AND bump,
    detected via total_output == written-line-count in both states): each
    leg independently pins the two identities, and the ON leg re-drives
    OFF for cross-leg stasis -- kept_because_uncertain unchanged (write-
    time removals come out of the written set, NOT out of the phase-3
    uncertain bucket per D-20-02; the corpus-level -N reconciliation is
    Phase 21's), non-wcs reason keys identical, multi-pair attribution
    exactly 1:1 (D-19-04).
    """

    @staticmethod
    def _storages():
        """Build two independent key pairs over distinct real suffixes."""
        w1 = _parse_abp_rule("||*.autos^")
        assert w1 is not None
        assert w1.is_wildcard and w1.domain == "autos"  # TLD-form fixture
        w2 = _parse_abp_rule("||*.com^")
        assert w2 is not None
        assert w2.is_wildcard and w2.domain == "com"  # TLD-form fixture
        c1 = _parse_abp_rule("||sub.autos^")
        assert c1 is not None
        assert not c1.is_wildcard and get_tld(c1.domain) == "autos"
        c2 = _parse_abp_rule("||ads.com^")
        assert c2 is not None
        assert not c2.is_wildcard and get_tld(c2.domain) == "com"
        return {"autos": [w1], "com": [w2]}, {"sub.autos": [c1], "ads.com": [c2]}

    def test_sc3_off_leg_writes_all_four_lines_with_zero_accounting(self):
        """Flag OFF: bucket insertion order output, counter 0, empty ledger."""
        wildcards, plains = self._storages()
        ledger = CappedProofLedger()

        rules, stats = _drive_emission(wildcards, plains, ledger)

        assert rules == ["||*.autos^", "||*.com^", "||sub.autos^", "||ads.com^"]
        assert stats.abp_kept == 4
        assert stats.other_kept == 0
        assert stats.wildcard_covered_sub_pruned == 0
        assert ledger.summary()["by_reason"] == {}
        assert stats.total_output == stats.abp_kept + stats.other_kept
        assert stats.total_output == len(rules)

    def test_sc3_on_leg_skips_exactly_two_subs_one_to_one_with_stasis(self):
        """Flag ON: exactly the witnessed subs skip; stasis holds across legs.

        Multi-pair attribution is EXACTLY {REASON_WILDCARD_COVERS_SUB: 2}
        -- one rule, one reason, one counter per pair, never aggregated.
        The OFF leg is re-driven first inside this method so the cross-leg
        stasis asserts compare fresh same-shape results.
        """
        wildcards, plains = self._storages()
        ledger_off = CappedProofLedger()
        rules_off, stats_off = _drive_emission(wildcards, plains, ledger_off)

        ledger_on = CappedProofLedger()
        rules_on, stats_on = _drive_emission(
            wildcards,
            plains,
            ledger_on,
            wildcard_covers_subs_pruning=True,
        )

        assert rules_on == ["||*.autos^", "||*.com^"]
        assert stats_on.wildcard_covered_sub_pruned == 2
        assert ledger_on.summary()["by_reason"] == {REASON_WILDCARD_COVERS_SUB: 2}
        assert stats_on.abp_kept == 2
        assert stats_on.other_kept == 0
        assert stats_on.total_output == stats_on.abp_kept + stats_on.other_kept
        assert stats_on.total_output == len(rules_on)

        by_reason_off = ledger_off.summary()["by_reason"]
        by_reason_on = ledger_on.summary()["by_reason"]
        assert by_reason_off.get(REASON_KEPT_BECAUSE_UNCERTAIN, 0) == 0
        assert by_reason_on.get(REASON_KEPT_BECAUSE_UNCERTAIN, 0) == 0
        non_wcs_keys_off = {key for key in by_reason_off if key != REASON_WILDCARD_COVERS_SUB}
        non_wcs_keys_on = {key for key in by_reason_on if key != REASON_WILDCARD_COVERS_SUB}
        assert non_wcs_keys_off == non_wcs_keys_on
        assert stats_off.total_output == stats_off.abp_kept + stats_off.other_kept
        assert stats_off.total_output == len(rules_off)


# ----------------------------------------------------------------------
# Phase 20 plan 20-03 appended region: compile-level IDENTITY plane
# (SC5/D-20-03 combo matrix), SC4 determinism, and D-19-07 fence-
# inclusion closure. Everything below runs through REAL compile_rules()
# (or projects real driven stats) and documents DETERMINISTIC outcomes
# scratch-captured under py -3.14 on 2026-08-26 before being pasted
# (capture-not-predict). Per the load-bearing research finding (C2):
# phase 3's TLD branch proves over a strict superset of any write-time
# survivor pool, so compile-level B yield is STRUCTURALLY ZERO today --
# these legs pin that stasis as positive claims, never shrinkage.
# Nonzero-emission proof lives in the direct-drive region above.
# ----------------------------------------------------------------------


# Tuple layout: (id, compile_kwargs, expected output lines, expected
# tld_wildcard_pruned, expected apex_covered_wildcard_pruned, expected
# whitelist_conflict_pruned). Every value captured from real
# compile_rules() runs under py -3.14 on 2026-08-26.
COMBO_ROWS = (
    (
        "b0_denyallow0_apex0",
        {"denyallow_pruning": False},
        ["||*.autos^", "||autos^", "||ads.example.com^"],
        1,
        0,
        0,
    ),
    (
        "b0_denyallow1_apex0_production_defaults",
        {},
        ["||*.autos^", "||autos^", "||ads.example.com^"],
        1,
        0,
        0,
    ),
    (
        "b1_denyallow0_apex0",
        {"wildcard_covers_subs_pruning": True, "denyallow_pruning": False},
        ["||*.autos^", "||autos^", "||ads.example.com^"],
        1,
        0,
        0,
    ),
    (
        "b1_denyallow1_apex0",
        {"wildcard_covers_subs_pruning": True},
        ["||*.autos^", "||autos^", "||ads.example.com^"],
        1,
        0,
        0,
    ),
    (
        "b1_denyallow1_apex1",
        {
            "wildcard_covers_subs_pruning": True,
            "wildcard_apex_pruning": True,
        },
        ["||autos^", "||ads.example.com^"],
        1,
        1,
        0,
    ),
)


class TestWcsComboMatrix:
    """D-20-03/SC5: four (B x denyallow) combos plus the apex-present stack row.

    Every configuration compiles FIXTURE_LINES through REAL compile_rules()
    with a fresh CappedProofLedger and carries its own scratch-captured
    deterministic outcome. In every row the sub dies to the LEGACY
    tld-wildcard family (FIXTURE_LINES carries no denyallow carriers), so
    the wcs family stays silent -- pinned as POSITIVE zeros (counter 0,
    reason absent, tally == counter), never shrinkage (research C2).
    The apex-present row reproduces the TL03 golden outcome at the compile
    seam: wildcard_apex_pruning=True removes ||*.autos^ against its
    surviving apex while the wcs family never fires (the killed wildcard
    never witnesses).
    """

    @pytest.mark.parametrize(
        (
            "compile_kwargs",
            "expected_output",
            "expected_tld_wildcard",
            "expected_apex_covered",
            "expected_whitelist_conflict",
        ),
        [pytest.param(*row[1:], id=row[0]) for row in COMBO_ROWS],
    )
    def test_combo_row_documented_outcome_through_real_compile_rules(
        self,
        compile_kwargs,
        expected_output,
        expected_tld_wildcard,
        expected_apex_covered,
        expected_whitelist_conflict,
    ):
        """One documented combo row: captured bytes, counters, wcs silence."""
        ledger = CappedProofLedger()

        rules, stats = _compile(FIXTURE_LINES, proof_ledger=ledger, **compile_kwargs)

        assert rules == expected_output
        assert stats.wildcard_covered_sub_pruned == 0
        assert stats.tld_wildcard_pruned == expected_tld_wildcard
        assert stats.apex_covered_wildcard_pruned == expected_apex_covered
        assert stats.whitelist_conflict_pruned == expected_whitelist_conflict
        summary = ledger.summary()
        assert REASON_WILDCARD_COVERS_SUB not in summary["by_reason"]
        tally = summary["by_reason"].get(REASON_WILDCARD_COVERS_SUB, 0)
        assert tally == stats.wildcard_covered_sub_pruned

    def test_b_flag_flip_alone_is_observationally_inert_compiled(self):
        """Flipping ONLY wildcard_covers_subs_pruning changes NOTHING observable.

        Mechanical C2 identity pairings (D-20-03): c1-vs-c3 and c2-vs-c4
        are compiled once each with fresh ledgers, then compared on rule
        bytes, FULL by_reason dicts (exact dict equality -- byte-level,
        not counter-only), and the tld-wildcard counter. Phase-3 superset
        proof behind the identity: the write-time witness pool is strictly
        contained in phase 3's proof pool (same keys, same oracle,
        survivorship only shrinks), so compile-level B yield is
        structurally zero today.
        """
        combos = {
            "c1": {"denyallow_pruning": False},
            "c2": {},
            "c3": {"wildcard_covers_subs_pruning": True, "denyallow_pruning": False},
            "c4": {"wildcard_covers_subs_pruning": True},
        }
        results = {}
        for name, kwargs in combos.items():
            ledger = CappedProofLedger()
            rules, stats = _compile(FIXTURE_LINES, proof_ledger=ledger, **kwargs)
            results[name] = (rules, stats, ledger.summary()["by_reason"])

        rules_c1, stats_c1, by_reason_c1 = results["c1"]
        rules_c3, stats_c3, by_reason_c3 = results["c3"]
        assert rules_c1 == rules_c3
        assert by_reason_c1 == by_reason_c3
        assert stats_c1.tld_wildcard_pruned == stats_c3.tld_wildcard_pruned

        rules_c2, stats_c2, by_reason_c2 = results["c2"]
        rules_c4, stats_c4, by_reason_c4 = results["c4"]
        assert rules_c2 == rules_c4
        assert by_reason_c2 == by_reason_c4
        assert stats_c2.tld_wildcard_pruned == stats_c4.tld_wildcard_pruned


class TestWcsDeterminismAcrossRuns:
    """SC4: repeated largest-flagged-stack compiles are byte-identical.

    Mirrors the apex sibling's determinism template
    (test_apex_wildcard_plumbing.py::test_flagged_compile_is_deterministic_across_runs):
    two same-process compiles of one composite fixture with a fresh ledger
    per run. The stack is the LARGEST flagged configuration --
    wildcard_covers_subs_pruning=True together with wildcard_apex_pruning=True
    (denyallow left at its True default) -- so scope refusals ($dnstype
    narrower witness, $important presence asymmetry), the exception screen,
    and the apex interplay all execute INSIDE each repeated run rather than
    being skipped vacuously. conftest.py's autouse _clear_lru_caches fixture
    provides LRU hygiene between tests; no manual clear_caches() call is
    needed here.
    """

    def test_largest_on_stack_compile_is_deterministic_across_runs(self):
        """Two same-process flagged compiles are byte-equal with identical evidence.

        Composite built wcs-flavored fresh for this family (per-TLD
        wildcard/sub pairs over sixteen distinct real-public-suffix keys,
        mirroring the apex sibling's construction-loop shape), plus a
        $dnstype-scoped variant, a $important-asymmetric child, and an
        exception-guarded domain. Literals captured under py -3.14 on
        2026-08-26: both runs wrote identical bytes with wcs counter 0,
        apex counter 2, tld-wildcard counter 17, and by_reason
        {apex_covers_tld_wildcard: 2, exception_covered: 1,
        kept_because_uncertain: 1, tld_wildcard_covered: 17}.
        """
        ledger_run1 = CappedProofLedger()
        ledger_run2 = CappedProofLedger()
        pair_tlds = [
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
        ]
        composite = []
        for tld in pair_tlds:
            composite.append(f"||*.{tld}^")
            composite.append(f"||sub.{tld}^")
        composite += [
            "||*.autos^$dnstype=AAAA",
            "||sub.autos^",
            "||autos^",
            "||*.autos^",
            "||*.com^",
            "||ads.com^$important",
            "@@||whi.test^",
            "||whi.test^",
        ]

        rules_run1, stats_run1 = _compile(
            composite,
            proof_ledger=ledger_run1,
            wildcard_covers_subs_pruning=True,
            wildcard_apex_pruning=True,
        )
        rules_run2, stats_run2 = _compile(
            composite,
            proof_ledger=ledger_run2,
            wildcard_covers_subs_pruning=True,
            wildcard_apex_pruning=True,
        )

        assert rules_run1 == rules_run2
        assert (
            stats_run1.wildcard_covered_sub_pruned
            == stats_run2.wildcard_covered_sub_pruned
        )
        assert stats_run1.wildcard_covered_sub_pruned == 0
        assert (
            stats_run1.apex_covered_wildcard_pruned
            == stats_run2.apex_covered_wildcard_pruned
        )
        assert stats_run1.tld_wildcard_pruned == stats_run2.tld_wildcard_pruned
        by_reason_run1 = ledger_run1.summary()["by_reason"]
        by_reason_run2 = ledger_run2.summary()["by_reason"]
        assert by_reason_run1 == by_reason_run2


class TestWcsFenceInclusionClosure:
    """D-19-07 fence-inclusion obligation closed in its TWO reachable forms.

    The compile-level form ("flagged-run reason sets contain the wcs
    reason") is unreachable per research C1 -- emission never fires through
    real compile_rules() today -- so a genuine DIRECT-DRIVEN ON run stands
    in. Form 1 (driven bucket): fired emission demonstrably reaches the
    stage-diagnostics surface -- summaries[COMPILER_STAGE_PRUNE]["reasons"]
    equals {"wcs_covered": 1} EXACT via compiler_stage_summaries_from_stats(),
    which auto-picks-up wildcard_covered_sub_pruned through the missing-key-
    safe ``_stat`` getter; scripts/stage_diagnostics.py is consumed READ-ONLY
    with zero module edits (D-20-04). Form 2 (ledger fence): the wired-site
    ledger carries single-family attribution -- summary()["by_reason"]
    equals {REASON_WILDCARD_COVERS_SUB: 1} EXACT with tally == counter
    (D-19-04 1:1 pairing). The injected-projection equality leg in
    test_apex_wildcard_plumbing.py
    (test_wildcard_covered_sub_counter_key_producer_consumer_equality)
    remains the standing projection fence and is deliberately NOT duplicated
    or edited here. Exact dict-equality asserts throughout -- never
    membership-only checks -- so flag-dependent bucket noise cannot reach
    Phase 21 silently. Both methods consume the module-level _drive_emission
    helper; no new drive plumbing.
    """

    @staticmethod
    def _storages():
        """Build the witness/candidate storages shared by both fence drives."""
        witness = _parse_abp_rule("||*.autos^")
        assert witness is not None
        assert witness.is_wildcard and witness.domain == "autos"  # TLD-form fixture
        candidate = _parse_abp_rule("||sub.autos^")
        assert candidate is not None
        assert not candidate.is_wildcard and get_tld(candidate.domain) == "autos"
        return {"autos": [witness]}, {"sub.autos": [candidate]}

    def test_driven_on_run_surfaces_wcs_bucket_in_prune_stage_exact(self):
        """Form 1: fired emission projects {"wcs_covered": 1} EXACT + coherence trio.

        Captured from the same drive under py -3.14 on 2026-08-26:
        emitted == total_output == 1, discarded == 1, processed == 2
        (processed = total_output + sum(pruned.values())).
        """
        wildcards, plains = self._storages()
        ledger = CappedProofLedger()

        rules, stats = _drive_emission(
            wildcards,
            plains,
            ledger,
            wildcard_covers_subs_pruning=True,
        )
        summaries = compiler_stage_summaries_from_stats(stats)
        prune_stage = summaries[COMPILER_STAGE_PRUNE]

        assert stats.wildcard_covered_sub_pruned == 1
        assert rules == ["||*.autos^"]
        assert prune_stage["reasons"] == {"wcs_covered": 1}
        assert prune_stage["emitted"] == stats.total_output
        assert prune_stage["emitted"] == 1
        assert prune_stage["discarded"] == 1
        assert prune_stage["processed"] == 2

    def test_driven_on_run_ledger_carries_single_family_attribution_exact(self):
        """Form 2: by_reason == {REASON_WILDCARD_COVERS_SUB: 1} EXACT; tally == counter."""
        wildcards, plains = self._storages()
        ledger = CappedProofLedger()

        _, stats = _drive_emission(
            wildcards,
            plains,
            ledger,
            wildcard_covers_subs_pruning=True,
        )

        assert ledger.summary()["by_reason"] == {REASON_WILDCARD_COVERS_SUB: 1}
        tally = ledger.summary()["by_reason"][REASON_WILDCARD_COVERS_SUB]
        assert tally == stats.wildcard_covered_sub_pruned
        assert stats.wildcard_covered_sub_pruned == 1
