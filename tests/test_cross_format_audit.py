#!/usr/bin/env python3
"""
test_cross_format_audit.py

Cross-format compression and modifier-aware pruning audit (AUD-01).

These tests prove that hosts/plain-domain entries compressed to bare ABP rules
during compiler Phase 1 are pruned only when an existing ABP parent rule covers
them at equal or broader modifier scope.

Note: the legacy modifier-pruning helper documented as dead since Phase 12
(should-prune-by-modifier-name fast path) was REMOVED in Phase 14 (plan 14-04)
together with its two orphaned modifier-set constants. The active pipeline
proves coverage through _find_covering_parent_record() ->
modifier_scope_covers().
"""

import os
import tempfile

from scripts.compiler import compile_rules


class TestCrossFormatPruningAudit:
    """End-to-end cross-format pruning audit through compile_rules()."""

    def _compile(self, lines):
        """Compile lines through the full pipeline, returning output and stats."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "output.txt")
            stats = compile_rules(lines, output)
            with open(output) as f:
                rules = [line.strip() for line in f if line.strip()]
            return rules, stats

    # ------------------------------------------------------------------
    # Task 1: End-to-end cross-format pruning proof — happy path
    # ------------------------------------------------------------------

    def test_hosts_entry_pruned_by_equivalent_native_abp_rule(self):
        """Hosts-compressed ||domain^ is pruned when native ABP ||domain^ exists."""
        rules, stats = self._compile([
            "0.0.0.0 example.com",
            "||example.com^",
        ])
        assert "||example.com^" in rules
        assert rules.count("||example.com^") == 1
        assert stats.duplicate_pruned == 1

    def test_hosts_entry_survives_when_no_abp_parent_exists(self):
        """A hosts entry alone compresses to bare ||domain^ and survives."""
        rules, stats = self._compile(["0.0.0.0 example.com"])
        assert "||example.com^" in rules
        assert stats.formats_compressed == 1

    # ------------------------------------------------------------------
    # Task 2: Narrow-scope modifier boundaries in cross-format dedup
    # ------------------------------------------------------------------

    def test_client_scoped_parent_does_not_prune_hosts_compressed_child(self):
        """ABP parent with $client=X must NOT prune hosts-compressed bare child."""
        rules, _stats = self._compile([
            "||sub.example.com^$client=10.0.0.1",
            "0.0.0.0 sub.example.com",
        ])
        assert "||sub.example.com^" in rules
        assert "||sub.example.com^$client=10.0.0.1" in rules

    def test_ctag_scoped_parent_does_not_prune_hosts_compressed_child(self):
        """ABP parent with $ctag=X must NOT prune hosts-compressed bare child."""
        rules, _stats = self._compile([
            "||sub.example.com^$ctag=ads",
            "0.0.0.0 sub.example.com",
        ])
        assert "||sub.example.com^" in rules
        assert "||sub.example.com^$ctag=ads" in rules

    def test_dnstype_scoped_parent_does_not_prune_hosts_compressed_child(self):
        """ABP parent with $dnstype=X must NOT prune hosts-compressed bare child."""
        rules, _stats = self._compile([
            "||sub.example.com^$dnstype=A",
            "0.0.0.0 sub.example.com",
        ])
        assert "||sub.example.com^" in rules
        assert "||sub.example.com^$dnstype=A" in rules

    def test_denyallow_parent_does_not_prune_hosts_compressed_child(self):
        """ABP parent with $denyallow=X must NOT prune hosts-compressed bare child."""
        rules, _stats = self._compile([
            "||sub.example.com^$denyallow=cdn.example.com",
            "0.0.0.0 sub.example.com",
        ])
        assert "||sub.example.com^" in rules
        assert "||sub.example.com^$denyallow=cdn.example.com" in rules

    def test_unmodified_parent_prunes_hosts_compressed_child(self):
        """ABP parent with NO modifiers prunes hosts-compressed bare child."""
        rules, stats = self._compile([
            "||example.com^",
            "0.0.0.0 sub.example.com",
        ])
        assert "||sub.example.com^" not in rules
        assert "||example.com^" in rules
        assert stats.abp_subdomain_pruned == 1

    def test_multi_domain_hosts_row_independent_dedup_decisions(self):
        """Each domain from a multi-domain hosts row gets its own dedup check."""
        rules, _stats = self._compile([
            "||a.com^$client=10.0.0.1",
            "||b.com^",
            "0.0.0.0 a.com b.com",
        ])
        # a.com survives because its parent has narrowing $client scope.
        assert "||a.com^" in rules
        assert "||a.com^$client=10.0.0.1" in rules
        # b.com is an exact duplicate of the unmodified native ABP parent.
        assert rules.count("||b.com^") == 1

    # ------------------------------------------------------------------
    # Task 3: $important asymmetry boundary
    # ------------------------------------------------------------------

    def test_important_parent_prunes_hosts_compressed_child(self):
        """ABP parent with $important prunes hosts-compressed bare child."""
        rules, _stats = self._compile([
            "||example.com^$important",
            "0.0.0.0 example.com",
        ])
        assert "||example.com^" in rules
        assert rules.count("||example.com^") == 1
        assert "||example.com^$important" in rules

    def test_important_child_not_pruned_by_compressed_bare_parent(self):
        """Native ABP $important child survives a hosts-compressed bare parent."""
        rules, _stats = self._compile([
            "0.0.0.0 example.com",
            "||example.com^$important",
        ])
        assert "||example.com^" in rules
        assert "||example.com^$important" in rules
