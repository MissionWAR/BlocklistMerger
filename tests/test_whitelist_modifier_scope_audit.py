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

Pattern source: tests/test_cross_format_audit.py (Phase 12 audit suites).
"""

import os
import tempfile

import pytest

from scripts.compiler import compile_rules
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
]


class TestWhitelistModifierScopeAudit:
    """End-to-end whitelist/modifier-scope audit through compile_rules()."""

    def _compile(self, lines):
        """Compile lines through the full pipeline, returning output and stats."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "output.txt")
            stats = compile_rules(lines, output)
            with open(output) as f:
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
