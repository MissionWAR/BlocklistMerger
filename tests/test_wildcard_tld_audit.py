#!/usr/bin/env python3
"""
test_wildcard_tld_audit.py

Phase 12 audit suite for wildcard-to-apex pruning (AUD-02) and multi-part
TLD wildcard coverage (AUD-03).

These tests prove the full compile_rules() path: parsing, wildcard storage,
coverage lookup, modifier-scope comparison, and pruning. The E-06 finding
documents that TLD wildcards bypass Phase 3 apex-vs-wildcard redundancy
checks; Phase 14 FIX-01 owns the remediation.
"""
import os
import tempfile

from scripts.compiler import compile_rules, get_tld


class TestWildcardToApexAudit:
    """AUD-02: wildcard children are pruned only by equal-or-broader apexes."""

    def _compile(self, lines):
        """Helper to run compilation and return output rules plus stats."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "output.txt")
            stats = compile_rules(lines, output)
            with open(output, encoding="utf-8") as f:
                rules = [line.strip() for line in f if line.strip()]
            return rules, stats

    def test_wildcard_pruned_by_equivalent_apex(self):
        """WF-02: bare wildcard is pruned when bare apex exists."""
        lines = [
            "||*.example.com^",
            "||example.com^",
        ]
        rules, stats = self._compile(lines)

        assert rules == ["||example.com^"]
        assert stats.abp_subdomain_pruned == 1
        assert stats.tld_wildcard_pruned == 0

    def test_important_wildcard_not_pruned_by_bare_apex(self):
        """WF-01: important wildcard survives a non-important apex."""
        lines = [
            "||*.example.com^$important",
            "||example.com^",
        ]
        rules, stats = self._compile(lines)

        assert rules == [
            "||*.example.com^$important",
            "||example.com^",
        ]
        assert stats.abp_subdomain_pruned == 0

    def test_wildcard_not_pruned_by_important_apex(self):
        """WF-03: important apex cannot cover a non-important wildcard."""
        lines = [
            "||*.example.com^",
            "||example.com^$important",
        ]
        rules, stats = self._compile(lines)

        assert rules == [
            "||*.example.com^",
            "||example.com^$important",
        ]
        assert stats.abp_subdomain_pruned == 0

    def test_important_wildcard_pruned_by_important_apex(self):
        """Equal priority on both sides restores safe pruning."""
        lines = [
            "||*.example.com^$important",
            "||example.com^$important",
        ]
        rules, stats = self._compile(lines)

        assert rules == ["||example.com^$important"]
        assert stats.abp_subdomain_pruned == 1

    def test_denyallow_wildcard_never_pruned_by_matching_apex(self):
        """Special-behavior modifiers are never provably covered."""
        lines = [
            "||*.example.com^$denyallow=ok.example",
            "||example.com^$denyallow=ok.example",
        ]
        rules, stats = self._compile(lines)

        assert rules == [
            "||*.example.com^$denyallow=ok.example",
            "||example.com^$denyallow=ok.example",
        ]
        assert stats.abp_subdomain_pruned == 0


class TestTLDWildcardCoverageAudit:
    """AUD-03: multi-part TLD coverage and E-06 gap evidence."""

    def _compile(self, lines):
        """Helper to run compilation and return output rules plus stats."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "output.txt")
            stats = compile_rules(lines, output)
            with open(output, encoding="utf-8") as f:
                rules = [line.strip() for line in f if line.strip()]
            return rules, stats

    def test_co_uk_wildcard_prunes_deep_subdomain(self):
        """TL-01: .co.uk resolves as one multi-part TLD covering registrants."""
        lines = [
            "||*.co.uk^",
            "||deep.sub.example.co.uk^",
        ]
        rules, stats = self._compile(lines)

        assert rules == ["||*.co.uk^"]
        assert stats.tld_wildcard_pruned == 1

    def test_uk_wildcard_does_not_cover_co_uk_registrant(self):
        """TL-02: the PSL distinguishes co.uk from uk; no cross-TLD pruning."""
        lines = [
            "||*.uk^",
            "||example.co.uk^",
        ]
        rules, stats = self._compile(lines)

        assert rules == [
            "||*.uk^",
            "||example.co.uk^",
        ]
        assert stats.tld_wildcard_pruned == 0

    def test_com_au_wildcard_prunes_subdomain(self):
        """Multi-part TLD coverage works for .com.au as well."""
        lines = [
            "||*.com.au^",
            "||site.example.com.au^",
        ]
        rules, stats = self._compile(lines)

        assert rules == ["||*.com.au^"]
        assert stats.tld_wildcard_pruned == 1

    def test_com_wildcard_does_not_cover_com_au(self):
        """com and com.au are distinct PSL suffixes; no cross-covering."""
        lines = [
            "||*.com^",
            "||example.com.au^",
        ]
        rules, stats = self._compile(lines)

        assert rules == [
            "||*.com^",
            "||example.com.au^",
        ]
        assert stats.tld_wildcard_pruned == 0

    def test_apex_and_tld_wildcard_both_kept_documents_e06_gap(self):
        """E-06: apex-vs-TLD-wildcard redundancy is not pruned today.

        ||autos^ blocks the apex AND every subdomain, so it fully covers
        ||*.autos^ with equal modifiers — yet both rules survive because
        TLD wildcards bypass Phase 3 pruning and are written directly in
        Phase 4. This test documents the missed-redundancy opportunity as
        current expected behavior. Phase 14 FIX-01 owns the remediation;
        when that fix lands, this assertion must flip to expect only the
        apex rule.
        """
        lines = [
            "||autos^",
            "||*.autos^",
        ]
        rules, stats = self._compile(lines)

        assert rules == [
            "||*.autos^",
            "||autos^",
        ]
        assert stats.tld_wildcard_pruned == 0
        assert stats.abp_subdomain_pruned == 0

    def test_important_tld_wildcard_prunes_important_child(self):
        """TL-05: equal-priority TLD coverage prunes the child."""
        lines = [
            "||*.autos^$important",
            "||spam.autos^$important",
        ]
        rules, stats = self._compile(lines)

        assert rules == ["||*.autos^$important"]
        assert stats.tld_wildcard_pruned == 1

    def test_bare_tld_wildcard_keeps_important_child(self):
        """TL-06: a non-important TLD wildcard cannot cover an important child."""
        lines = [
            "||*.autos^",
            "||spam.autos^$important",
        ]
        rules, stats = self._compile(lines)

        assert rules == [
            "||*.autos^",
            "||spam.autos^$important",
        ]
        assert stats.tld_wildcard_pruned == 0

    def test_scoped_tld_wildcard_prunes_equal_scoped_child(self):
        """TL-07: equal-value $client scope proves safe TLD coverage."""
        lines = [
            "||*.autos^$client=10.0.0.1",
            "||spam.autos^$client=10.0.0.1",
        ]
        rules, stats = self._compile(lines)

        assert rules == ["||*.autos^$client=10.0.0.1"]
        assert stats.tld_wildcard_pruned == 1

    def test_scoped_tld_wildcard_keeps_unrestricted_child(self):
        """TL-08: a scoped parent cannot cover an unrestricted child."""
        lines = [
            "||*.autos^$client=10.0.0.1",
            "||spam.autos^",
        ]
        rules, stats = self._compile(lines)

        assert rules == [
            "||*.autos^$client=10.0.0.1",
            "||spam.autos^",
        ]
        assert stats.tld_wildcard_pruned == 0

    def test_unknown_tld_falls_back_to_conservative_keep(self):
        """TL-09: unrecognized suffixes get no TLD coverage and stay kept."""
        assert get_tld("example.xyz123") is None

        lines = [
            "||*.com^",
            "||example.xyz123^",
        ]
        rules, stats = self._compile(lines)

        assert rules == [
            "||*.com^",
            "||example.xyz123^",
        ]
        assert stats.tld_wildcard_pruned == 0
