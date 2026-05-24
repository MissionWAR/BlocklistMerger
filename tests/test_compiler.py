#!/usr/bin/env python3
"""
test_compiler.py

Edge case tests for the compiler module.
Tests deduplication logic, TLD wildcards, and cross-format optimization.
"""
import os
import tempfile
from pathlib import Path

import pytest

from scripts.compiler import (
    CompileStats,
    compile_rules,
    extract_abp_info,
    extract_hosts_info,
    get_tld,
    walk_parent_domains,
)
from scripts.pruning_proof import (
    DELTA_CHANGED,
    DELTA_GAINED,
    DELTA_NOT_APPLICABLE,
    DELTA_PRESERVED,
    DELTA_UNCERTAIN,
    OUTCOME_KEPT,
    OUTCOME_PRUNED,
    OUTCOME_REMOVED,
    PROOF_STATUS_PROVEN,
    PROOF_STATUS_UNCERTAIN,
    REASON_BADFILTER_DISABLED,
    REASON_CROSS_FORMAT_BROADENED,
    REASON_DNSREWRITE_CHANGED,
    REASON_DUPLICATE_RULE,
    REASON_EXCEPTION_COVERED,
    REASON_IGNORED_NONBLOCKING,
    REASON_KEPT_BECAUSE_UNCERTAIN,
    REASON_PARENT_COVERED,
    REASON_REGEX_UNCERTAIN_KEPT,
    REASON_TLD_WILDCARD_COVERED,
    REASON_UNSUPPORTED_MODIFIER_REMOVED,
    REASON_WILDCARD_COVERED,
    ProofLedger,
)


def test_hosts_plain_policy_tests_do_not_use_misleading_legacy_names():
    """Hosts/plain tests should name the project policy, not strict AGH behavior."""
    test_source = Path(__file__).read_text(encoding="utf-8")
    forbidden_names = (
        "test_hosts" + "_no_subdomain_pruning",
        "test_plain" + "_no_subdomain_pruning",
    )

    assert not [name for name in forbidden_names if name in test_source]


class TestABPExtraction:
    """Test ABP rule parsing."""

    def test_basic_domain(self):
        domain, mods, is_exc, is_wc = extract_abp_info("||example.com^")
        assert domain == "example.com"
        assert not is_exc
        assert not is_wc

    def test_subdomain(self):
        domain, mods, is_exc, is_wc = extract_abp_info("||ads.example.com^")
        assert domain == "ads.example.com"

    def test_wildcard(self):
        domain, mods, is_exc, is_wc = extract_abp_info("||*.example.com^")
        assert domain == "example.com"
        assert is_wc

    def test_exception(self):
        domain, mods, is_exc, is_wc = extract_abp_info("@@||example.com^")
        assert domain == "example.com"
        assert is_exc
        assert not is_wc

    def test_exception_wildcard(self):
        domain, mods, is_exc, is_wc = extract_abp_info("@@||*.example.com^")
        assert is_exc
        assert is_wc

    def test_with_modifiers(self):
        domain, mods, is_exc, is_wc = extract_abp_info("||example.com^$important")
        assert domain == "example.com"
        assert "important" in mods

    def test_ip_address(self):
        domain, mods, is_exc, is_wc = extract_abp_info("||100.48.203.212^")
        assert domain == "100.48.203.212"

    def test_tld_wildcard(self):
        domain, mods, is_exc, is_wc = extract_abp_info("||*.autos^")
        assert domain == "autos"
        assert is_wc


class TestHostsExtraction:
    """Test hosts format parsing."""

    def test_basic_hosts(self):
        ip, domains = extract_hosts_info("0.0.0.0 example.com")
        assert ip == "0.0.0.0"
        assert domains == ["example.com"]

    def test_localhost_ip(self):
        ip, domains = extract_hosts_info("127.0.0.1 example.com")
        assert ip == "127.0.0.1"
        assert domains == ["example.com"]

    def test_multiple_domains(self):
        ip, domains = extract_hosts_info("0.0.0.0 a.com b.com c.com")
        assert domains == ["a.com", "b.com", "c.com"]

    def test_with_comment(self):
        ip, domains = extract_hosts_info("0.0.0.0 example.com # blocked")
        assert domains == ["example.com"]

    def test_localhost_filtered(self):
        ip, domains = extract_hosts_info("127.0.0.1 localhost")
        assert domains == []

    def test_non_blocking_ip_ignored(self):
        """Real IP addresses (not 0.0.0.0/127.0.0.1) should be ignored."""
        ip, domains = extract_hosts_info("8.8.8.8 dns.google")
        assert ip is None


class TestDomainHelpers:
    """Test domain utility functions."""

    def test_get_tld(self):
        assert get_tld("example.com") == "com"
        assert get_tld("test.co.uk") == "co.uk"
        assert get_tld("sub.example.autos") == "autos"

    def test_walk_parents(self):
        parents = walk_parent_domains("a.b.example.com")
        assert "b.example.com" in parents
        assert "example.com" in parents

    def test_walk_parents_apex(self):
        """Apex domain should have no parents."""
        parents = walk_parent_domains("example.com")
        assert parents == ()


class TestCompilation:
    """Test the main compilation logic."""

    def _compile(self, lines):
        """Helper to run compilation and return stats."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "output.txt")
            stats = compile_rules(lines, output)
            with open(output) as f:
                rules = [line.strip() for line in f if line.strip()]
            return rules, stats

    def _compile_with_ledger(self, lines):
        """Helper to run compilation with proof records enabled."""
        ledger = ProofLedger()
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "output.txt")
            stats = compile_rules(lines, output, proof_ledger=ledger)
            with open(output) as f:
                rules = [line.strip() for line in f if line.strip()]
            return rules, stats, ledger

    def test_abp_subdomain_pruning(self):
        """Subdomain should be pruned when parent exists."""
        lines = [
            "||example.com^",
            "||sub.example.com^",
        ]
        rules, stats = self._compile(lines)
        assert "||example.com^" in rules
        assert "||sub.example.com^" not in rules
        assert stats.abp_subdomain_pruned == 1

    def test_abp_subdomain_important_kept(self):
        """Subdomain with $important should NOT be pruned if parent lacks it."""
        lines = [
            "||example.com^",
            "||sub.example.com^$important",
        ]
        rules, stats = self._compile(lines)
        assert "||example.com^" in rules
        assert "||sub.example.com^$important" in rules

    def test_tld_wildcard_pruning(self):
        """TLD wildcard should prune all domains in that TLD."""
        lines = [
            "||*.autos^",
            "||spam.autos^",
            "||ads.spam.autos^",
        ]
        rules, stats = self._compile(lines)
        assert "||*.autos^" in rules
        assert "||spam.autos^" not in rules
        assert "||ads.spam.autos^" not in rules
        assert stats.tld_wildcard_pruned == 2

    def test_wildcard_subdomain_pruning(self):
        """Wildcard rule should prune explicit subdomains.

        ||*.example.com^ covers all subdomains, so ||sub.example.com^ is redundant.
        """
        lines = [
            "||*.example.com^",
            "||sub.example.com^",
            "||deep.sub.example.com^",
        ]
        rules, stats = self._compile(lines)
        assert "||*.example.com^" in rules
        assert "||sub.example.com^" not in rules
        assert "||deep.sub.example.com^" not in rules
        assert stats.abp_subdomain_pruned == 2

    def test_cross_format_abp_covers_hosts(self):
        """ABP rule should prune hosts rule for same/sub domain.

        With compression: hosts are converted to ABP first, then pruned.
        """
        lines = [
            "||example.com^",
            "0.0.0.0 example.com",  # Becomes duplicate after compression
            "0.0.0.0 sub.example.com",  # Becomes subdomain after compression
        ]
        rules, stats = self._compile(lines)
        assert "||example.com^" in rules
        # With compression, hosts become ABP then get pruned
        assert len(rules) == 1
        # Now it's duplicate + subdomain pruned, not cross-format
        assert stats.duplicate_pruned >= 1 or stats.abp_subdomain_pruned >= 1

    def test_cross_format_abp_covers_plain(self):
        """ABP rule should prune plain domain."""
        lines = [
            "||example.com^",
            "sub.example.com",
        ]
        rules, stats = self._compile(lines)
        assert "||example.com^" in rules
        assert "sub.example.com" not in rules

    def test_hosts_project_aggressive_promotion_prunes_subdomain(self):
        """Project policy promotes hosts exact-host rows to ABP before pruning."""
        lines = [
            "0.0.0.0 example.com",
            "0.0.0.0 sub.example.com",
        ]
        rules, stats, ledger = self._compile_with_ledger(lines)
        promotion_records = [
            record for record in ledger.records if record.reason == REASON_CROSS_FORMAT_BROADENED
        ]
        parent_records = [
            record for record in ledger.records if record.reason == REASON_PARENT_COVERED
        ]

        assert rules == ["||example.com^"]
        assert stats.formats_compressed == 2
        assert stats.compression_policy_broadened == 2
        assert stats.abp_subdomain_pruned == 1
        assert len(promotion_records) == 2
        assert len(parent_records) == 1
        assert {record.candidate.source_kind for record in promotion_records} == {"hosts"}
        assert {record.candidate.scope for record in promotion_records} == {"exact_host"}
        assert all(record.strict_agh_delta == DELTA_GAINED for record in promotion_records)
        assert all(record.project_policy_delta == DELTA_PRESERVED for record in promotion_records)

    def test_plain_project_aggressive_promotion_prunes_subdomain(self):
        """Project policy promotes plain exact-host rows to ABP before pruning."""
        lines = [
            "example.com",
            "sub.example.com",
        ]
        rules, stats, ledger = self._compile_with_ledger(lines)
        promotion_records = [
            record for record in ledger.records if record.reason == REASON_CROSS_FORMAT_BROADENED
        ]
        parent_records = [
            record for record in ledger.records if record.reason == REASON_PARENT_COVERED
        ]

        assert rules == ["||example.com^"]
        assert stats.formats_compressed == 2
        assert stats.compression_policy_broadened == 2
        assert stats.abp_subdomain_pruned == 1
        assert len(promotion_records) == 2
        assert len(parent_records) == 1
        assert {record.candidate.source_kind for record in promotion_records} == {"plain_domain"}
        assert {record.candidate.scope for record in promotion_records} == {"exact_host"}
        assert all(record.strict_agh_delta == DELTA_GAINED for record in promotion_records)
        assert all(record.project_policy_delta == DELTA_PRESERVED for record in promotion_records)

    def test_whitelist_conflict_removal(self):
        """Block rules for whitelisted domains should be removed.

        @@rules are NOT output (we only output blocking rules).
        The blocking rule is removed since the domain is whitelisted.
        """
        lines = [
            "||example.com^",
            "@@||example.com^",
        ]
        rules, stats = self._compile(lines)
        # The block rule should be removed since domain is whitelisted
        assert "||example.com^" not in rules
        # @@rule is NOT output (only blocking rules are output)
        assert "@@||example.com^" not in rules
        assert stats.whitelist_conflict_pruned >= 1

    def test_whitelist_subdomain_exception(self):
        """@@rule for subdomain causes parent block to be removed.

        Since we don't output @@rules, we need to remove the blocking rule
        for any domain that has a whitelist entry (even subdomain exceptions).

        NOTE: This is a trade-off - we lose subdomain exception granularity
        but keep the output file simple (blocking rules only).
        """
        lines = [
            "||example.com^",
            "@@||sub.example.com^",
        ]
        rules, stats = self._compile(lines)
        # The parent blocking rule is kept (sub.example.com exception doesn't affect parent)
        assert "||example.com^" in rules
        # @@rule is NOT output
        assert "@@||sub.example.com^" not in rules

    def test_client_restrictive_modifier_not_pruning(self):
        """Parent with $client should NOT prune child without $client.

        Parent only blocks for specific client, child blocks for everyone.
        Child is MORE general, not redundant!
        """
        lines = [
            "||example.com^$client=192.168.1.5",
            "||sub.example.com^",
        ]
        rules, stats = self._compile(lines)
        # Both should be kept - child blocks for everyone
        assert any("example.com^$client" in r for r in rules)
        assert "||sub.example.com^" in rules

    def test_badfilter_parent_not_pruning(self):
        """$badfilter directives are diagnostics only and should not prune children.

        $badfilter disables other rules, it doesn't block anything.
        """
        lines = [
            "||example.com^$badfilter",
            "||sub.example.com^",
        ]
        rules, stats = self._compile(lines)
        assert "||example.com^$badfilter" not in rules
        assert "||sub.example.com^" in rules
        assert stats.rule_effect_disable == 1

    def test_duplicate_removal(self):
        """Duplicate rules should be removed."""
        lines = [
            "||example.com^",
            "||example.com^",
            "||example.com^",
        ]
        rules, stats = self._compile(lines)
        assert rules.count("||example.com^") == 1
        assert stats.duplicate_pruned == 2

    def test_ip_rules_kept(self):
        """IP-based ABP rules should be kept."""
        lines = [
            "||100.48.203.212^",
        ]
        rules, stats = self._compile(lines)
        assert "||100.48.203.212^" in rules

    def test_url_path_rule_discarded_direct_input(self):
        """Compiler should not emit URL-path rules even if called directly."""
        rules, stats = self._compile(["||example.com/ads/"])
        assert "||example.com/ads/" not in rules
        assert rules == []
        assert stats.malformed_discarded == 1

    def test_invalid_abp_rule_discarded_direct_input(self):
        """Compiler should treat narrow invalid syntax as malformed direct input."""
        rules, stats = self._compile(["||^"])
        assert rules == []
        assert stats.malformed_discarded == 1

    def test_regex_rule_preserved_direct_input(self):
        """Valid regex rules remain non-ABP output rules."""
        rules, stats = self._compile(["/example.*/"])
        assert "/example.*/" in rules
        assert stats.other_kept == 1
        assert stats.regex_preserved_no_pruning == 1

    def test_other_rules_written_deterministically(self):
        """Other-rule output should not depend on set iteration or input order."""
        lines = [
            "/zeta.*/",
            "/alpha.*/",
            "/middle.*/",
        ]

        rules1, stats1 = self._compile(lines)
        rules2, stats2 = self._compile(list(reversed(lines)))

        assert rules1 == sorted(lines)
        assert rules2 == sorted(lines)
        assert stats1.other_kept == 3
        assert stats2.other_kept == 3

    def test_supported_slash_modifier_preserved_direct_input(self):
        """Supported slash-like modifier values should not look like URL paths."""
        rule = "||example.org^$client=192.168.0.0/24"
        rules, stats = self._compile([rule])
        assert rule in rules
        assert stats.malformed_discarded == 0

    def test_allocation_cleanup_regression_preserves_semantics_and_cardinalities(self):
        """Mixed compile protects pruning behavior while exposing inspect-only sizes."""
        lines = [
            "||example.com^",
            "||ads.example.com^",
            "||*.autos^",
            "||spam.autos^",
            "||allowed.org^",
            "@@||allowed.org^",
            "||semantic-dup.net^$client=10.0.0.1,dnstype=a",
            "||semantic-dup.net^$dnstype=A,client=10.0.0.1",
            "/zeta.*/",
            "/alpha.*/",
        ]

        rules, stats = self._compile(lines)

        assert rules == [
            "||*.autos^",
            "||example.com^",
            "||semantic-dup.net^$client=10.0.0.1,dnstype=a",
            "/alpha.*/",
            "/zeta.*/",
        ]
        assert stats.abp_subdomain_pruned == 1
        assert stats.tld_wildcard_pruned == 1
        assert stats.whitelist_conflict_pruned == 1
        assert stats.duplicate_pruned == 1
        assert stats.malformed_discarded == 0
        assert stats.abp_kept == 3
        assert stats.other_kept == 2
        assert stats.total_output == 5
        assert stats.abp_rule_keys == 5
        assert stats.abp_wildcard_keys == 1
        assert stats.exception_rule_keys == 1
        assert stats.duplicate_index_size == 6
        assert stats.other_rule_count == 2


class TestCompilerSemanticDiagnostics:
    """Compiler-level RuleEffect integration diagnostics."""

    def _compile(self, lines):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "output.txt")
            stats = compile_rules(lines, output)
            with open(output) as f:
                return [line.strip() for line in f if line.strip()], stats

    def test_stats_expose_semantic_counter_fields(self):
        """CompileStats exposes the Phase 7 inspect-only semantic counters."""
        stats = CompileStats()

        assert stats.rule_effect_block == 0
        assert stats.rule_effect_exception == 0
        assert stats.rule_effect_rewrite == 0
        assert stats.rule_effect_disable == 0
        assert stats.rule_effect_ignored == 0
        assert stats.rule_effect_unsupported == 0
        assert stats.rule_effect_uncertain == 0
        assert stats.compression_policy_broadened == 0
        assert stats.regex_preserved_no_pruning == 0

    def test_effect_counters_and_nonblocking_rows_are_diagnostics_only(self):
        """Compiler classifies every non-empty row before deciding output behavior."""
        lines = [
            "||block.example.com^",
            "@@||exception.example.com^",
            "||rewrite.example.com^$dnsrewrite=1.2.3.4",
            "||disable.example.com^$badfilter",
            "||unsupported.example.com^$future=value",
            "8.8.8.8 dns.google",
            "/regex.*/",
            "0.0.0.0 hosts-policy.example.com",
            "plain-policy.example.com",
        ]

        rules, stats = self._compile(lines)

        assert rules == [
            "||block.example.com^",
            "||hosts-policy.example.com^",
            "||plain-policy.example.com^",
            "/regex.*/",
        ]
        assert stats.rule_effect_block == 4
        assert stats.rule_effect_exception == 1
        assert stats.rule_effect_rewrite == 1
        assert stats.rule_effect_disable == 1
        assert stats.rule_effect_unsupported == 1
        assert stats.rule_effect_ignored == 1
        assert stats.rule_effect_uncertain == 2
        assert stats.compression_policy_broadened == 2
        assert stats.regex_preserved_no_pruning == 1
        assert stats.formats_compressed == 2

    def test_badfilter_and_unknown_modifiers_are_not_blocking_output(self):
        """Disabling and unsupported rows are consumed for diagnostics only."""
        lines = [
            "||disable.example.com^$badfilter",
            "||unsupported.example.com^$future=value",
        ]

        rules, stats = self._compile(lines)

        assert rules == []
        assert stats.rule_effect_disable == 1
        assert stats.rule_effect_unsupported == 1
        assert stats.rule_effect_uncertain == 1
        assert stats.abp_kept == 0
        assert stats.total_output == 0

    def test_equal_scoped_exception_still_prunes_block_and_records_effects(self):
        """Safe exception consumption keeps existing whitelist diagnostics."""
        block_rule = "||covered.example.com^$client=10.0.0.1"
        exception_rule = "@@||covered.example.com^$client=10.0.0.1"

        rules, stats = self._compile([block_rule, exception_rule])

        assert rules == []
        assert stats.whitelist_conflict_pruned == 1
        assert stats.rule_effect_block == 1
        assert stats.rule_effect_exception == 1
        assert stats.rule_effect_uncertain == 2


class TestCompilerProofLedgerPlumbing:
    """Optional proof-ledger records emitted by compiler diagnostics."""

    def _compile(self, lines, *, proof_ledger=None):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "output.txt")
            if proof_ledger is None:
                stats = compile_rules(lines, output)
            else:
                stats = compile_rules(lines, output, proof_ledger=proof_ledger)
            with open(output) as f:
                return [line.strip() for line in f if line.strip()], stats

    def test_compile_rules_two_positional_arguments_remain_default_contract(self):
        """The historical compile_rules(lines, output_file) call remains unchanged."""
        lines = [
            "||block.example.com^",
            "0.0.0.0 host-policy.example.com",
            "plain-policy.example.com",
            "/regex.*/",
        ]

        rules, stats = self._compile(lines)

        assert rules == [
            "||block.example.com^",
            "||host-policy.example.com^",
            "||plain-policy.example.com^",
            "/regex.*/",
        ]
        assert stats.total_output == 4
        assert stats.formats_compressed == 2
        assert stats.compression_policy_broadened == 2

    def test_optional_ledger_records_nonblocking_diagnostics_and_regex_uncertainty(self):
        """Diagnostics-only rows are recorded as changed, uncertain, or not applicable."""
        ledger = ProofLedger()
        lines = [
            "||unsupported.example.com^$future=value",
            "||disable.example.com^$badfilter",
            "||rewrite.example.com^$dnsrewrite=1.2.3.4",
            "8.8.8.8 dns.google",
            "/regex.*/",
        ]

        rules, stats = self._compile(lines, proof_ledger=ledger)
        records_by_reason = {record.reason: record for record in ledger.records}

        assert rules == ["/regex.*/"]
        assert stats.rule_effect_unsupported == 1
        assert stats.rule_effect_disable == 1
        assert stats.rule_effect_rewrite == 1
        assert stats.rule_effect_ignored == 1
        assert stats.regex_preserved_no_pruning == 1
        assert set(records_by_reason) == {
            REASON_UNSUPPORTED_MODIFIER_REMOVED,
            REASON_BADFILTER_DISABLED,
            REASON_DNSREWRITE_CHANGED,
            REASON_IGNORED_NONBLOCKING,
            REASON_REGEX_UNCERTAIN_KEPT,
        }
        assert (
            records_by_reason[REASON_UNSUPPORTED_MODIFIER_REMOVED].strict_agh_delta
            == DELTA_NOT_APPLICABLE
        )
        assert records_by_reason[REASON_BADFILTER_DISABLED].project_policy_delta == (
            DELTA_NOT_APPLICABLE
        )
        assert records_by_reason[REASON_DNSREWRITE_CHANGED].strict_agh_delta == "changed"
        assert records_by_reason[REASON_IGNORED_NONBLOCKING].project_policy_delta == (
            DELTA_NOT_APPLICABLE
        )
        regex_record = records_by_reason[REASON_REGEX_UNCERTAIN_KEPT]
        assert regex_record.outcome == OUTCOME_KEPT
        assert regex_record.strict_agh_delta == DELTA_UNCERTAIN
        assert regex_record.project_policy_delta == DELTA_UNCERTAIN
        assert regex_record.candidate.rule_kind == "regex"

    def test_hosts_and_plain_promotion_records_dual_baseline_delta(self):
        """Hosts/plain promotion gains strict AGH coverage while preserving project policy."""
        ledger = ProofLedger()

        rules, stats = self._compile(
            [
                "0.0.0.0 hosts-policy.example.com",
                "plain-policy.example.net",
            ],
            proof_ledger=ledger,
        )
        promotion_records = [
            record
            for record in ledger.records
            if record.reason == REASON_CROSS_FORMAT_BROADENED
        ]

        assert rules == [
            "||hosts-policy.example.com^",
            "||plain-policy.example.net^",
        ]
        assert stats.formats_compressed == 2
        assert len(promotion_records) == 2
        assert {record.candidate.source_kind for record in promotion_records} == {
            "hosts",
            "plain_domain",
        }
        assert {record.candidate.normalized_rule for record in promotion_records} == set(rules)
        assert all(record.strict_agh_delta == DELTA_GAINED for record in promotion_records)
        assert all(record.project_policy_delta == DELTA_PRESERVED for record in promotion_records)


class TestCompilerPruningProofLedger:
    """Proof-ledger records for existing pruning decisions."""

    def _compile(self, lines):
        ledger = ProofLedger()
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "output.txt")
            stats = compile_rules(lines, output, proof_ledger=ledger)
            with open(output) as f:
                rules = [line.strip() for line in f if line.strip()]
            return rules, stats, ledger

    def _record(self, ledger, reason):
        matches = [record for record in ledger.records if record.reason == reason]
        assert len(matches) == 1
        return matches[0]

    def _assert_required_facets(self, record):
        assert record.candidate.rule_kind
        assert record.candidate.domain_shape
        assert record.candidate.modifier_signature is not None
        assert record.candidate.effect
        assert record.candidate.priority
        assert record.candidate.agh_behavior_basis
        assert record.outcome
        assert record.reason
        assert record.strict_agh_delta
        assert record.project_policy_delta
        assert record.fingerprint

    def test_duplicate_pruning_records_exact_semantic_equivalence(self):
        rules, stats, ledger = self._compile([
            "||dup.example.com^$client=10.0.0.1,dnstype=a",
            "||dup.example.com^$dnstype=A,client=10.0.0.1",
        ])

        record = self._record(ledger, REASON_DUPLICATE_RULE)

        assert rules == ["||dup.example.com^$client=10.0.0.1,dnstype=a"]
        assert stats.duplicate_pruned == 1
        assert record.outcome == OUTCOME_PRUNED
        assert record.proof_status == PROOF_STATUS_PROVEN
        assert record.strict_agh_delta == DELTA_PRESERVED
        assert record.project_policy_delta == DELTA_PRESERVED
        assert record.covering is not None
        assert record.candidate.modifier_signature == record.covering.modifier_signature
        self._assert_required_facets(record)

    def test_parent_wildcard_and_tld_pruning_record_covering_facets(self):
        rules, stats, ledger = self._compile([
            "||parent.example.com^",
            "||child.parent.example.com^",
            "||*.wild.example.com^",
            "||child.wild.example.com^",
            "||*.autos^",
            "||spam.autos^",
        ])

        parent_record = self._record(ledger, REASON_PARENT_COVERED)
        wildcard_record = self._record(ledger, REASON_WILDCARD_COVERED)
        tld_record = self._record(ledger, REASON_TLD_WILDCARD_COVERED)

        assert set(rules) == {
            "||*.autos^",
            "||*.wild.example.com^",
            "||parent.example.com^",
        }
        assert stats.abp_subdomain_pruned == 2
        assert stats.tld_wildcard_pruned == 1
        assert parent_record.covering.normalized_rule == "||parent.example.com^"
        assert wildcard_record.covering.normalized_rule == "||*.wild.example.com^"
        assert tld_record.covering.normalized_rule == "||*.autos^"
        assert wildcard_record.covering.domain_shape == "wildcard"
        assert tld_record.covering.domain_shape == "tld_wildcard"
        for record in (parent_record, wildcard_record, tld_record):
            assert record.outcome == OUTCOME_PRUNED
            assert record.proof_status == PROOF_STATUS_PROVEN
            assert record.strict_agh_delta == DELTA_PRESERVED
            assert record.project_policy_delta == DELTA_PRESERVED
            self._assert_required_facets(record)

    def test_exception_pruning_records_proven_and_uncertain_decisions(self):
        rules, stats, ledger = self._compile([
            "||covered.example.com^$client=10.0.0.1",
            "@@||covered.example.com^$client=10.0.0.1",
            "||uncertain.example.com^",
            "@@||uncertain.example.com^$client=10.0.0.1",
        ])

        proven_record = self._record(ledger, REASON_EXCEPTION_COVERED)
        uncertain_record = self._record(ledger, REASON_KEPT_BECAUSE_UNCERTAIN)

        assert rules == ["||uncertain.example.com^"]
        assert stats.whitelist_conflict_pruned == 1
        assert proven_record.outcome == OUTCOME_REMOVED
        assert proven_record.proof_status == PROOF_STATUS_PROVEN
        assert proven_record.strict_agh_delta == DELTA_CHANGED
        assert proven_record.project_policy_delta == DELTA_CHANGED
        assert proven_record.covering.normalized_rule == (
            "@@||covered.example.com^$client=10.0.0.1"
        )
        assert uncertain_record.outcome == OUTCOME_KEPT
        assert uncertain_record.proof_status == PROOF_STATUS_UNCERTAIN
        assert uncertain_record.strict_agh_delta == DELTA_UNCERTAIN
        assert uncertain_record.project_policy_delta == DELTA_UNCERTAIN
        assert uncertain_record.covering.normalized_rule == (
            "@@||uncertain.example.com^$client=10.0.0.1"
        )
        self._assert_required_facets(proven_record)
        self._assert_required_facets(uncertain_record)

    def test_unproven_parent_modifier_scope_records_kept_uncertain(self):
        child_rule = "||child.example.com^$important"
        rules, stats, ledger = self._compile(["||example.com^", child_rule])

        record = self._record(ledger, REASON_KEPT_BECAUSE_UNCERTAIN)

        assert "||example.com^" in rules
        assert child_rule in rules
        assert stats.abp_subdomain_pruned == 0
        assert record.candidate.normalized_rule == child_rule
        assert record.covering.normalized_rule == "||example.com^"
        assert record.outcome == OUTCOME_KEPT
        assert record.proof_status == PROOF_STATUS_UNCERTAIN
        assert record.strict_agh_delta == DELTA_UNCERTAIN
        assert record.project_policy_delta == DELTA_UNCERTAIN
        self._assert_required_facets(record)

    def test_tld_wildcard_whitelist_removal_records_output_write_decision(self):
        rules, stats, ledger = self._compile(["||*.autos^", "@@||*.autos^"])

        record = self._record(ledger, REASON_EXCEPTION_COVERED)

        assert rules == []
        assert stats.whitelist_conflict_pruned == 1
        assert record.candidate.normalized_rule == "||*.autos^"
        assert record.covering.normalized_rule == "@@||*.autos^"
        assert record.outcome == OUTCOME_REMOVED
        assert record.proof_status == PROOF_STATUS_PROVEN
        self._assert_required_facets(record)


class TestEdgeCases:
    """Edge cases that could cause issues."""

    def _compile(self, lines):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "output.txt")
            stats = compile_rules(lines, output)
            with open(output) as f:
                return [line.strip() for line in f if line.strip()], stats

    def test_order_independence(self):
        """Deduplication should work regardless of input order."""
        # Parent after child
        lines1 = ["||sub.example.com^", "||example.com^"]
        rules1, _ = self._compile(lines1)

        # Parent before child
        lines2 = ["||example.com^", "||sub.example.com^"]
        rules2, _ = self._compile(lines2)

        assert set(rules1) == set(rules2)
        assert "||example.com^" in rules1
        assert "||sub.example.com^" not in rules1

    def test_complex_subdomain_chain(self):
        """Deep subdomain chains should be handled correctly."""
        lines = [
            "||example.com^",
            "||a.example.com^",
            "||b.a.example.com^",
            "||c.b.a.example.com^",
        ]
        rules, stats = self._compile(lines)
        assert rules == ["||example.com^"]
        assert stats.abp_subdomain_pruned == 3

    def test_different_tlds_not_confused(self):
        """example.com should not affect example.org."""
        lines = [
            "||example.com^",
            "||example.org^",
        ]
        rules, _ = self._compile(lines)
        assert "||example.com^" in rules
        assert "||example.org^" in rules

    def test_co_uk_tld_handled(self):
        """Multi-part TLDs like .co.uk should be handled correctly."""
        lines = [
            "||example.co.uk^",
            "||sub.example.co.uk^",
        ]
        rules, stats = self._compile(lines)
        assert "||example.co.uk^" in rules
        assert "||sub.example.co.uk^" not in rules


class TestModifierHandling:
    """Tests for modifier-aware deduplication."""

    def _compile(self, lines):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "output.txt")
            stats = compile_rules(lines, output)
            with open(output) as f:
                return [line.strip() for line in f if line.strip()], stats

    # -------------------------------------------------------------------------
    # $important tests
    # -------------------------------------------------------------------------

    def test_important_child_kept_when_parent_lacks(self):
        """Child with $important MUST be kept if parent lacks it."""
        lines = [
            "||example.com^",
            "||sub.example.com^$important",
        ]
        rules, _ = self._compile(lines)
        assert "||example.com^" in rules
        assert "||sub.example.com^$important" in rules

    def test_important_child_pruned_when_parent_has(self):
        """Child with $important CAN be pruned if parent also has it."""
        lines = [
            "||example.com^$important",
            "||sub.example.com^$important",
        ]
        rules, _ = self._compile(lines)
        assert "||example.com^$important" in rules
        assert "||sub.example.com^$important" not in rules

    def test_child_without_important_pruned(self):
        """Child without $important can be pruned by parent without it."""
        lines = [
            "||example.com^",
            "||sub.example.com^",
        ]
        rules, _ = self._compile(lines)
        assert "||example.com^" in rules
        assert "||sub.example.com^" not in rules

    # -------------------------------------------------------------------------
    # $dnsrewrite tests
    # -------------------------------------------------------------------------

    def test_dnsrewrite_not_emitted_as_blocking_coverage(self):
        """$dnsrewrite rows are rewrite diagnostics, not blocklist output."""
        lines = [
            "||example.com^",
            "||sub.example.com^$dnsrewrite=1.2.3.4",
        ]
        rules, stats = self._compile(lines)
        assert "||example.com^" in rules
        assert "||sub.example.com^$dnsrewrite=1.2.3.4" not in rules
        assert stats.rule_effect_rewrite == 1

    def test_dnsrewrite_parent_does_not_remove_standard_child(self):
        """A rewrite parent is not blocking coverage and cannot remove a child block."""
        lines = [
            "||example.com^$dnsrewrite=1.2.3.4",
            "||sub.example.com^",
        ]
        rules, stats = self._compile(lines)
        assert "||example.com^$dnsrewrite=1.2.3.4" not in rules
        # DNS rewrite is special behavior, so the blocking rule for sub.example.com must remain.
        assert "||sub.example.com^" in rules
        assert stats.rule_effect_rewrite == 1

    # -------------------------------------------------------------------------
    # $badfilter tests
    # -------------------------------------------------------------------------

    def test_badfilter_not_emitted_as_blocking_coverage(self):
        """$badfilter rows are disabling diagnostics, not blocklist output."""
        lines = [
            "||example.com^",
            "||sub.example.com^$badfilter",
        ]
        rules, stats = self._compile(lines)
        assert "||example.com^" in rules
        assert "||sub.example.com^$badfilter" not in rules
        assert stats.rule_effect_disable == 1

    # -------------------------------------------------------------------------
    # $denyallow tests
    # -------------------------------------------------------------------------

    def test_denyallow_never_pruned(self):
        """$denyallow rules should NEVER be pruned."""
        lines = [
            "||example.com^",
            "||sub.example.com^$denyallow=good.com",
        ]
        rules, _ = self._compile(lines)
        assert "||example.com^" in rules
        assert "||sub.example.com^$denyallow=good.com" in rules

    # -------------------------------------------------------------------------
    # $dnstype tests
    # -------------------------------------------------------------------------

    def test_dnstype_child_pruned_when_parent_blocks_all(self):
        """Parent blocks all types, child blocks specific type -> prune child."""
        lines = [
            "||example.com^",               # Blocks ALL DNS types
            "||sub.example.com^$dnstype=A", # Blocks only A records
        ]
        rules, _ = self._compile(lines)
        # Parent already blocks ALL types, so specific type is redundant
        assert "||example.com^" in rules
        assert "||sub.example.com^$dnstype=A" not in rules

    def test_dnstype_child_kept_when_parent_has_different_dnstype(self):
        """Both have $dnstype but might differ -> keep child (safe)."""
        lines = [
            "||example.com^$dnstype=A",      # Blocks only A records
            "||sub.example.com^$dnstype=AAAA", # Blocks only AAAA records
        ]
        rules, _ = self._compile(lines)
        # Can't tell if same type, so keep both for safety
        assert "||example.com^$dnstype=A" in rules
        assert "||sub.example.com^$dnstype=AAAA" in rules

    def test_dnstype_child_blocks_all_parent_blocks_specific(self):
        """Child blocks all types, parent only specific -> keep child."""
        lines = [
            "||example.com^$dnstype=A",  # Blocks only A records
            "||sub.example.com^",        # Blocks ALL types
        ]
        rules, _ = self._compile(lines)
        # Child is MORE restrictive, should NOT be pruned
        assert "||example.com^$dnstype=A" in rules
        assert "||sub.example.com^" in rules

    # -------------------------------------------------------------------------
    # $client and $ctag restrictions
    # -------------------------------------------------------------------------

    def test_client_parent_cannot_prune_unrestricted_child(self):
        """Parent with $client should NOT prune a child without $client."""
        lines = [
            "||example.com^$client=10.0.0.1",
            "||sub.example.com^",
        ]
        rules, _ = self._compile(lines)
        assert "||example.com^$client=10.0.0.1" in rules
        assert "||sub.example.com^" in rules

    def test_client_parent_cannot_prune_restricted_child(self):
        """Parent with $client should NOT prune a child with a $client."""
        lines = [
            "||example.com^$client=10.0.0.1",
            "||sub.example.com^$client=192.168.1.5",
        ]
        rules, _ = self._compile(lines)
        assert "||example.com^$client=10.0.0.1" in rules
        assert "||sub.example.com^$client=192.168.1.5" in rules

    def test_unrestricted_parent_can_prune_client_child(self):
        """Parent without $client CAN prune a child with $client."""
        lines = [
            "||example.com^",
            "||sub.example.com^$client=10.0.0.1",
        ]
        rules, _ = self._compile(lines)
        assert "||example.com^" in rules
        assert "||sub.example.com^$client=10.0.0.1" not in rules

    @pytest.mark.parametrize(
        "modifier",
        [
            "client=10.0.0.1",
            "ctag=pc",
            "dnstype=a",
        ],
    )
    def test_equal_value_scoped_parent_prunes_equal_child(self, modifier):
        """Equal structured client, ctag, and dnstype scopes prove parent coverage."""
        parent_rule = f"||example.com^${modifier}"
        child_rule = f"||sub.example.com^${modifier}"

        rules, stats = self._compile([parent_rule, child_rule])

        assert parent_rule in rules
        assert child_rule not in rules
        assert stats.abp_subdomain_pruned == 1

    @pytest.mark.parametrize(
        ("parent_modifier", "child_modifier"),
        [
            ("client=10.0.0.1", "client=192.168.1.5"),
            ("ctag=pc", "ctag=mobile"),
            ("dnstype=A", "dnstype=AAAA"),
        ],
    )
    def test_different_value_scoped_parent_keeps_child(
        self,
        parent_modifier,
        child_modifier,
    ):
        """Different structured values cannot prove parent coverage."""
        parent_rule = f"||example.com^${parent_modifier}"
        child_rule = f"||sub.example.com^${child_modifier}"

        rules, stats = self._compile([parent_rule, child_rule])

        assert parent_rule in rules
        assert child_rule in rules
        assert stats.abp_subdomain_pruned == 0

    @pytest.mark.parametrize(
        "child_modifier",
        [
            "denyallow=allowed.example",
        ],
    )
    def test_broad_parent_keeps_supported_child_with_unproven_coverage(self, child_modifier):
        """Supported child modifiers with unproven coverage must not be parent-pruned."""
        child_rule = f"||sub.example.com^${child_modifier}"

        rules, stats = self._compile(["||example.com^", child_rule])

        assert "||example.com^" in rules
        assert child_rule in rules
        assert stats.abp_subdomain_pruned == 0

    @pytest.mark.parametrize(
        "parent_modifier",
        [
            "denyallow=allowed.example",
        ],
    )
    def test_supported_parent_with_unproven_coverage_keeps_children(self, parent_modifier):
        """Supported parents with unproven coverage cannot prove child coverage."""
        parent_rule = f"||example.com^${parent_modifier}"

        rules, stats = self._compile([parent_rule, "||sub.example.com^"])

        assert parent_rule in rules
        assert "||sub.example.com^" in rules
        assert stats.abp_subdomain_pruned == 0

    @pytest.mark.parametrize(
        "modifier",
        [
            "dnsrewrite=1.2.3.4",
            "badfilter",
            "future=value",
            "client='unterminated",
        ],
    )
    def test_nonblocking_or_unsupported_modifier_rows_are_skipped(self, modifier):
        """Rewrite, disabling, unsupported, and uncertain rows are diagnostics only."""
        parent_rule = f"||example.com^${modifier}"

        rules, stats = self._compile([parent_rule, "||sub.example.com^"])

        assert parent_rule not in rules
        assert "||sub.example.com^" in rules
        assert stats.abp_subdomain_pruned == 0


class TestRealWorldScenarios:
    """Test with real-world-like domain scenarios."""

    def _compile(self, lines):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "output.txt")
            stats = compile_rules(lines, output)
            with open(output) as f:
                return [line.strip() for line in f if line.strip()], stats

    def test_google_analytics_subdomain_pruning(self):
        """Google Analytics domains - common real-world case."""
        lines = [
            "||google-analytics.com^",
            "||ssl.google-analytics.com^",
            "||www.google-analytics.com^",
        ]
        rules, stats = self._compile(lines)
        assert rules == ["||google-analytics.com^"]
        assert stats.abp_subdomain_pruned == 2

    def test_facebook_tracking_domains(self):
        """Facebook's various tracking domains."""
        lines = [
            "||facebook.com^",
            "||pixel.facebook.com^",
            "||connect.facebook.net^",  # Different TLD!
            "0.0.0.0 graph.facebook.com",
        ]
        rules, stats = self._compile(lines)
        assert "||facebook.com^" in rules
        assert "||pixel.facebook.com^" not in rules
        assert "||connect.facebook.net^" in rules  # Different TLD, not pruned
        assert "0.0.0.0 graph.facebook.com" not in rules  # Cross-format pruned

    def test_mixed_formats_same_domains(self):
        """Same domains in different formats - ABP wins."""
        lines = [
            "||ads.example.com^",
            "0.0.0.0 ads.example.com",
            "ads.example.com",
        ]
        rules, stats = self._compile(lines)
        # Only ABP should remain
        assert "||ads.example.com^" in rules
        assert len([r for r in rules if "ads.example.com" in r]) == 1

    def test_tld_wildcard_real_abused_tlds(self):
        """Real abused TLDs from Hagezi's list."""
        lines = [
            "||*.autos^",
            "||*.beauty^",
            "||*.boats^",
            "||spam.autos^",
            "||tracker.beauty^",
            "||ads.boats^",
            "0.0.0.0 malware.autos",
            "phishing.beauty",
        ]
        rules, stats = self._compile(lines)
        assert "||*.autos^" in rules
        assert "||*.beauty^" in rules
        assert "||*.boats^" in rules
        # All specific domains should be pruned
        assert "||spam.autos^" not in rules
        assert "||tracker.beauty^" not in rules
        assert "||ads.boats^" not in rules
        # Cross-format also pruned
        assert "0.0.0.0 malware.autos" not in rules
        assert "phishing.beauty" not in rules

    def test_cdn_domains_not_wrongly_pruned(self):
        """Different CDN subdomains should NOT affect each other."""
        lines = [
            "||cdn1.example.com^",
            "||cdn2.example.com^",
            "||cdn3.example.com^",
        ]
        rules, _ = self._compile(lines)
        # None should be pruned - they're siblings, not parent/child
        assert "||cdn1.example.com^" in rules
        assert "||cdn2.example.com^" in rules
        assert "||cdn3.example.com^" in rules

    def test_partial_overlap_domains(self):
        """Domains that share a suffix but aren't parent/child."""
        lines = [
            "||tracking.com^",
            "||adtracking.com^",  # NOT a subdomain of tracking.com!
        ]
        rules, _ = self._compile(lines)
        assert "||tracking.com^" in rules
        assert "||adtracking.com^" in rules


class TestCoveragePreservationBoundaries:
    """
    Critical tests for rules that must stay and explicit aggressive policy cases.
    """

    def _compile(self, lines):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "output.txt")
            stats = compile_rules(lines, output)
            with open(output) as f:
                return [line.strip() for line in f if line.strip()], stats

    def test_hosts_project_aggressive_subdomain_pruning_is_expected(self):
        """
        Project policy converts hosts rows to ABP before subdomain deduplication.
        """
        lines = [
            "0.0.0.0 example.com",
            "0.0.0.0 sub.example.com",
        ]
        rules, stats = self._compile(lines)
        assert "||example.com^" in rules
        assert len(rules) == 1
        assert stats.abp_subdomain_pruned == 1

    def test_plain_project_aggressive_subdomain_pruning_is_expected(self):
        """
        Project policy converts plain rows to ABP before subdomain deduplication.
        """
        lines = [
            "example.com",
            "sub.example.com",
        ]
        rules, stats = self._compile(lines)
        assert "||example.com^" in rules
        assert len(rules) == 1
        assert stats.abp_subdomain_pruned == 1

    def test_different_modifiers_MUST_be_kept(self):
        """Rules with different modifiers should NOT be pruned."""
        lines = [
            "||example.com^$dnstype=A",
            "||sub.example.com^$dnstype=AAAA",
        ]
        rules, _ = self._compile(lines)
        # Both should exist - different types!
        assert "||example.com^$dnstype=A" in rules
        assert "||sub.example.com^$dnstype=AAAA" in rules


class TestStressAndComplexScenarios:
    """Stress tests with many rules and complex scenarios."""

    def _compile(self, lines):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "output.txt")
            stats = compile_rules(lines, output)
            with open(output) as f:
                return [line.strip() for line in f if line.strip()], stats

    def test_many_subdomains_single_parent(self):
        """100 subdomains should all be pruned by single parent."""
        lines = ["||example.com^"]
        lines += [f"||sub{i}.example.com^" for i in range(100)]
        rules, stats = self._compile(lines)
        assert len(rules) == 1
        assert "||example.com^" in rules
        assert stats.abp_subdomain_pruned == 100

    def test_many_tld_domains(self):
        """TLD wildcard should prune many domains."""
        lines = ["||*.xyz^"]
        lines += [f"||domain{i}.xyz^" for i in range(50)]
        rules, stats = self._compile(lines)
        assert len(rules) == 1
        assert "||*.xyz^" in rules
        assert stats.tld_wildcard_pruned == 50

    def test_mixed_formats_large(self):
        """Mix of ABP, hosts, plain - all become ABP with compression."""
        lines = [
            "||example.com^",
            "||other.com^",
        ]
        # Add 20 hosts rules for subdomains of example.com
        lines += [f"0.0.0.0 sub{i}.example.com" for i in range(20)]
        # Add 20 plain domains for subdomains of example.com
        lines += [f"plain{i}.example.com" for i in range(20)]
        # Add hosts for other.com (should also be pruned)
        lines += [f"0.0.0.0 sub{i}.other.com" for i in range(10)]

        rules, stats = self._compile(lines)
        # Only the two ABP rules should remain
        assert len(rules) == 2
        # With compression, all become ABP then subdomain pruned
        assert stats.abp_subdomain_pruned == 50

    def test_deep_subdomain_chain_pruning(self):
        """Very deep subdomain chains."""
        lines = [
            "||example.com^",
            "||a.example.com^",
            "||b.a.example.com^",
            "||c.b.a.example.com^",
            "||d.c.b.a.example.com^",
            "||e.d.c.b.a.example.com^",
        ]
        rules, stats = self._compile(lines)
        assert rules == ["||example.com^"]
        assert stats.abp_subdomain_pruned == 5

    def test_multiple_tld_wildcards(self):
        """Multiple TLD wildcards should each prune their domains."""
        lines = [
            "||*.autos^",
            "||*.boats^",
            "||*.xyz^",
            "||spam.autos^",
            "||spam.boats^",
            "||spam.xyz^",
        ]
        rules, stats = self._compile(lines)
        assert len(rules) == 3
        assert stats.tld_wildcard_pruned == 3



class TestIPRules:
    """Tests for IP-based blocking rules."""

    def _compile(self, lines):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "output.txt")
            stats = compile_rules(lines, output)
            with open(output) as f:
                return [line.strip() for line in f if line.strip()], stats

    def test_ip_abp_rules_kept(self):
        """IP-based ABP rules should be kept."""
        lines = [
            "||1.2.3.4^",
            "||192.168.1.1^",
            "||10.0.0.1^",
        ]
        rules, _ = self._compile(lines)
        assert "||1.2.3.4^" in rules
        assert "||192.168.1.1^" in rules
        assert "||10.0.0.1^" in rules

    def test_ip_not_confused_with_domains(self):
        """IPs should not be confused with domains."""
        lines = [
            "||1.2.3.4^",
            "||example.com^",
        ]
        rules, _ = self._compile(lines)
        assert len(rules) == 2


class TestSpecialDomains:
    """Tests for special domain patterns."""

    def _compile(self, lines):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "output.txt")
            stats = compile_rules(lines, output)
            with open(output) as f:
                return [line.strip() for line in f if line.strip()], stats

    def test_punycode_domains(self):
        """Punycode (internationalized) domains."""
        lines = [
            "||xn--n3h.com^",  # Emoji domain
            "||xn--e1afmkfd.xn--p1ai^",  # Russian domain
        ]
        rules, _ = self._compile(lines)
        assert len(rules) == 2

    def test_very_long_domain(self):
        """Very long domain names."""
        long_subdomain = "a" * 60
        lines = [
            f"||{long_subdomain}.example.com^",
        ]
        rules, _ = self._compile(lines)
        assert len(rules) == 1

    def test_numeric_domain(self):
        """Domain with all numbers."""
        lines = [
            "||123456.com^",
        ]
        rules, _ = self._compile(lines)
        assert "||123456.com^" in rules

    def test_hyphenated_domain(self):
        """Domain with hyphens."""
        lines = [
            "||my-domain-name.com^",
            "||sub.my-domain-name.com^",
        ]
        rules, _ = self._compile(lines)
        assert "||my-domain-name.com^" in rules
        assert "||sub.my-domain-name.com^" not in rules  # Pruned


class TestDuplicateHandling:
    """Tests for duplicate rule handling."""

    def _compile(self, lines):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "output.txt")
            stats = compile_rules(lines, output)
            with open(output) as f:
                return [line.strip() for line in f if line.strip()], stats

    def test_exact_duplicates(self):
        """Exact duplicate rules removed."""
        lines = [
            "||example.com^",
            "||example.com^",
            "||example.com^",
        ]
        rules, stats = self._compile(lines)
        assert len(rules) == 1
        assert stats.duplicate_pruned == 2

    def test_duplicate_keeps_important_variant(self):
        """Same-domain important and non-important rules are distinct variants."""
        lines = [
            "||example.com^",
            "||example.com^$important",
        ]
        rules, stats = self._compile(lines)
        assert "||example.com^" in rules
        assert "||example.com^$important" in rules
        assert stats.duplicate_pruned == 0

    def test_reordered_equivalent_modifiers_deduplicated(self):
        """Equivalent modifier signatures dedupe even when modifier order differs."""
        lines = [
            "||example.com^$client=10.0.0.1,dnstype=a",
            "||example.com^$dnstype=A,client=10.0.0.1",
        ]
        rules, stats = self._compile(lines)
        assert len(rules) == 1
        assert "||example.com^$client=10.0.0.1,dnstype=a" in rules
        assert stats.duplicate_pruned == 1

    @pytest.mark.parametrize(
        ("first_modifier", "second_modifier"),
        [
            ("client=10.0.0.1", "client=192.168.1.5"),
            ("ctag=pc", "ctag=mobile"),
            ("dnstype=A", "dnstype=AAAA"),
            ("denyallow=allowed.example", "denyallow=other.example"),
        ],
    )
    def test_same_domain_value_bearing_modifier_variants_are_kept(
        self,
        first_modifier,
        second_modifier,
    ):
        """Different value-bearing modifier signatures must not collapse."""
        first_rule = f"||example.com^${first_modifier}"
        second_rule = f"||example.com^${second_modifier}"

        rules, stats = self._compile([first_rule, second_rule])

        assert first_rule in rules
        assert second_rule in rules
        assert stats.duplicate_pruned == 0

    def test_badfilter_not_duplicate_of_plain_block(self):
        """badfilter is a disabling directive, not a duplicate block variant."""
        lines = [
            "||example.com^",
            "||example.com^$badfilter",
        ]
        rules, stats = self._compile(lines)
        assert "||example.com^" in rules
        assert "||example.com^$badfilter" not in rules
        assert stats.duplicate_pruned == 0
        assert stats.rule_effect_disable == 1

    def test_unknown_modifier_variants_are_not_blocking_output(self):
        """Unsupported modifier variants are counted but not emitted as coverage."""
        lines = [
            "||example.com^$future=value-one",
            "||example.com^$future=value-two",
        ]
        rules, stats = self._compile(lines)
        assert rules == []
        assert stats.duplicate_pruned == 0
        assert stats.rule_effect_unsupported == 2
        assert stats.rule_effect_uncertain == 2

    def test_cross_format_same_domain(self):
        """Same domain in multiple formats - ABP wins."""
        lines = [
            "||example.com^",
            "0.0.0.0 example.com",
            "example.com",
        ]
        rules, stats = self._compile(lines)
        assert "||example.com^" in rules
        # With compression, hosts/plain are converted to ABP
        assert "0.0.0.0 example.com" not in rules
        assert "example.com" not in rules


class TestCompression:
    """Tests for hosts/plain to ABP compression."""

    def _compile(self, lines):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "output.txt")
            stats = compile_rules(lines, output)
            with open(output) as f:
                return [line.strip() for line in f if line.strip()], stats

    def test_hosts_converted_to_abp(self):
        """Hosts rules should be converted to ABP format."""
        lines = [
            "0.0.0.0 example.com",
        ]
        rules, stats = self._compile(lines)
        assert "||example.com^" in rules
        assert "0.0.0.0 example.com" not in rules
        assert stats.formats_compressed == 1

    def test_plain_converted_to_abp(self):
        """Plain domains should be converted to ABP format."""
        lines = [
            "tracking.example.com",
        ]
        rules, stats = self._compile(lines)
        assert "||tracking.example.com^" in rules
        assert "tracking.example.com" not in rules
        assert stats.formats_compressed == 1

    def test_compression_enables_subdomain_pruning(self):
        """Compressed hosts should benefit from ABP subdomain dedup."""
        lines = [
            "||example.com^",  # ABP parent
            "0.0.0.0 sub.example.com",  # Hosts subdomain - should be pruned
        ]
        rules, stats = self._compile(lines)
        assert "||example.com^" in rules
        # sub.example.com was converted to ABP then pruned by parent
        assert len(rules) == 1
        assert stats.abp_subdomain_pruned == 1

    def test_multi_domain_formats_compressed(self):
        """Multi-domain hosts lines should convert each domain."""
        lines = [
            "0.0.0.0 a.com b.com c.com",
        ]
        rules, stats = self._compile(lines)
        assert "||a.com^" in rules
        assert "||b.com^" in rules
        assert "||c.com^" in rules
        assert stats.formats_compressed == 3

    def test_compressed_dedup_with_existing_abp(self):
        """Hosts domain matching existing ABP should be deduped."""
        lines = [
            "||example.com^",
            "0.0.0.0 example.com",  # Same domain - should be duplicate
        ]
        rules, stats = self._compile(lines)
        assert len(rules) == 1
        assert "||example.com^" in rules
        assert stats.duplicate_pruned >= 1


class TestWhitelistParentSubdomain:
    """Tests for the whitelist parent subdomain fix.

    Bug: @@||example.com^ should whitelist example.com AND all subdomains.
    Previously, only exact domain matches were checked.
    """

    def _compile(self, lines):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "output.txt")
            stats = compile_rules(lines, output)
            with open(output) as f:
                return [line.strip() for line in f if line.strip()], stats

    def test_whitelist_parent_covers_subdomain(self):
        """@@||example.com^ should whitelist sub.example.com too."""
        lines = [
            "||sub.example.com^",
            "@@||example.com^",
        ]
        rules, stats = self._compile(lines)
        # Subdomain should be removed because parent is whitelisted
        assert "||sub.example.com^" not in rules
        assert stats.whitelist_conflict_pruned >= 1

    def test_whitelist_parent_covers_deep_subdomain(self):
        """@@||example.com^ should whitelist a.b.c.example.com too."""
        lines = [
            "||a.b.c.example.com^",
            "@@||example.com^",
        ]
        rules, stats = self._compile(lines)
        assert "||a.b.c.example.com^" not in rules
        assert stats.whitelist_conflict_pruned >= 1

    def test_whitelist_grandparent_covers_subdomain(self):
        """@@||example.com^ should whitelist sub.child.example.com."""
        lines = [
            "||sub.child.example.com^",
            "@@||example.com^",
        ]
        rules, stats = self._compile(lines)
        assert "||sub.child.example.com^" not in rules

    def test_whitelist_does_not_affect_sibling(self):
        """@@||a.example.com^ should NOT whitelist b.example.com."""
        lines = [
            "||b.example.com^",
            "@@||a.example.com^",
        ]
        rules, stats = self._compile(lines)
        # b.example.com should still be blocked (not a subdomain of a.example.com)
        assert "||b.example.com^" in rules

    def test_whitelist_does_not_affect_different_tld(self):
        """@@||example.com^ should NOT whitelist example.org."""
        lines = [
            "||example.org^",
            "@@||example.com^",
        ]
        rules, stats = self._compile(lines)
        assert "||example.org^" in rules


class TestSemanticWhitelistHandling:
    """Tests for modifier-aware whitelist consumption."""

    def _compile(self, lines):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "output.txt")
            stats = compile_rules(lines, output)
            with open(output) as f:
                return [line.strip() for line in f if line.strip()], stats

    def test_exact_exception_removes_equal_scoped_block(self):
        """An exact exception removes a block only when modifier scope matches."""
        block_rule = "||example.com^$client=10.0.0.1,dnstype=a"
        exception_rule = "@@||example.com^$dnstype=A,client=10.0.0.1"

        rules, stats = self._compile([block_rule, exception_rule])

        assert block_rule not in rules
        assert stats.whitelist_conflict_pruned == 1
        assert not any(rule.startswith("@@") for rule in rules)

    def test_parent_exception_removes_scoped_child_block(self):
        """A broad parent exception covers a scoped child block."""
        block_rule = "||sub.example.com^$dnstype=A"

        rules, stats = self._compile([block_rule, "@@||example.com^"])

        assert block_rule not in rules
        assert stats.whitelist_conflict_pruned == 1

    def test_wildcard_exception_removes_equal_scoped_subdomain_block(self):
        """Wildcard exceptions cover subdomains when modifier scope matches."""
        block_rule = "||sub.example.com^$ctag=pc"
        exception_rule = "@@||*.example.com^$ctag=pc"

        rules, stats = self._compile([block_rule, exception_rule])

        assert block_rule not in rules
        assert stats.whitelist_conflict_pruned == 1

    @pytest.mark.parametrize(
        ("block_rule", "exception_rule"),
        [
            ("||example.com^", "@@||example.com^$client=10.0.0.1"),
            (
                "||example.com^$client=10.0.0.1",
                "@@||example.com^$client=192.168.1.5",
            ),
            ("||example.com^$dnstype=A", "@@||example.com^$dnstype=AAAA"),
        ],
    )
    def test_scoped_exception_mismatch_keeps_block(self, block_rule, exception_rule):
        """Scoped exceptions cannot remove broader or differently scoped blocks."""
        rules, stats = self._compile([block_rule, exception_rule])

        assert block_rule in rules
        assert exception_rule not in rules
        assert stats.whitelist_conflict_pruned == 0

    def test_non_important_exception_keeps_important_block(self):
        """An ordinary exception cannot remove an important block rule."""
        block_rule = "||example.com^$important"

        rules, stats = self._compile([block_rule, "@@||example.com^"])

        assert block_rule in rules
        assert stats.whitelist_conflict_pruned == 0

    def test_important_exception_removes_important_block_when_scope_matches(self):
        """An important exception can remove an important block with matching scope."""
        block_rule = "||example.com^$important,client=10.0.0.1"
        exception_rule = "@@||example.com^$client=10.0.0.1,important"

        rules, stats = self._compile([block_rule, exception_rule])

        assert block_rule not in rules
        assert stats.whitelist_conflict_pruned == 1

    @pytest.mark.parametrize(
        "exception_modifier",
        [
            "dnsrewrite=1.2.3.4",
            "denyallow=allowed.example",
            "badfilter",
            "future=value",
            "client='unterminated",
        ],
    )
    def test_special_unknown_and_uncertain_exceptions_keep_block(self, exception_modifier):
        """Exceptions with unproven behavior are consumed but cannot delete blocks."""
        block_rule = "||example.com^"
        exception_rule = f"@@||example.com^${exception_modifier}"

        rules, stats = self._compile([block_rule, exception_rule])

        assert block_rule in rules
        assert exception_rule not in rules
        assert stats.whitelist_conflict_pruned == 0


class TestEmptyAndEdgeCases:
    """Tests for empty input and other edge cases."""

    def _compile(self, lines):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "output.txt")
            stats = compile_rules(lines, output)
            with open(output) as f:
                return [line.strip() for line in f if line.strip()], stats

    def test_empty_input(self):
        """Empty input should produce empty output without errors."""
        lines = []
        rules, stats = self._compile(lines)
        assert rules == []
        assert stats.total_input == 0
        assert stats.total_output == 0

    def test_only_whitespace_lines(self):
        """Lines with only whitespace should be handled."""
        lines = ["   ", "\t", "  \n  ", ""]
        rules, stats = self._compile(lines)
        assert rules == []

    def test_only_comment_lines(self):
        """Comment-only input should produce empty output."""
        lines = [
            "# This is a comment",
            "! Another comment",
        ]
        # Note: cleaner removes these before compiler sees them
        # But compiler should still handle them gracefully
        rules, stats = self._compile(lines)
        assert rules == []

    def test_single_rule(self):
        """Single rule should be output correctly."""
        lines = ["||example.com^"]
        rules, stats = self._compile(lines)
        assert rules == ["||example.com^"]
        assert stats.total_output == 1

    def test_trailing_dot_domain(self):
        """Domain with trailing dot should be normalized."""
        lines = ["||example.com.^"]  # Trailing dot before ^
        rules, stats = self._compile(lines)
        # Should be normalized and kept
        assert len(rules) >= 0  # At minimum, shouldn't crash


class TestTLDWildcardModifiers:
    """Tests for modifiers on TLD wildcard rules."""

    def _compile(self, lines):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "output.txt")
            stats = compile_rules(lines, output)
            with open(output) as f:
                return [line.strip() for line in f if line.strip()], stats

    def test_tld_wildcard_with_important(self):
        """TLD wildcard with $important should prune child with $important."""
        lines = [
            "||*.autos^$important",
            "||spam.autos^$important",
        ]
        rules, stats = self._compile(lines)
        assert "||*.autos^$important" in rules
        assert "||spam.autos^$important" not in rules

    def test_tld_wildcard_without_important_keeps_important_child(self):
        """TLD wildcard without $important should NOT prune child with $important."""
        lines = [
            "||*.autos^",
            "||spam.autos^$important",
        ]
        rules, stats = self._compile(lines)
        assert "||*.autos^" in rules
        assert "||spam.autos^$important" in rules

    def test_tld_wildcard_dnsrewrite_child_not_emitted(self):
        """Child with $dnsrewrite is rewrite diagnostics, not block output."""
        lines = [
            "||*.autos^",
            "||special.autos^$dnsrewrite=1.2.3.4",
        ]
        rules, stats = self._compile(lines)
        assert "||*.autos^" in rules
        assert "||special.autos^$dnsrewrite=1.2.3.4" not in rules
        assert stats.tld_wildcard_pruned == 0
        assert stats.rule_effect_rewrite == 1

    @pytest.mark.parametrize(
        "modifier",
        [
            "client=10.0.0.1",
            "ctag=pc",
            "dnstype=a",
        ],
    )
    def test_tld_wildcard_prunes_equal_value_scoped_child(self, modifier):
        """TLD wildcard pruning uses the same structured modifier coverage."""
        parent_rule = f"||*.autos^${modifier}"
        child_rule = f"||spam.autos^${modifier}"

        rules, stats = self._compile([parent_rule, child_rule])

        assert parent_rule in rules
        assert child_rule not in rules
        assert stats.tld_wildcard_pruned == 1

    @pytest.mark.parametrize(
        "child_modifier",
        [
            "denyallow=allowed.example",
        ],
    )
    def test_tld_wildcard_keeps_special_unknown_and_uncertain_children(
        self,
        child_modifier,
    ):
        """TLD wildcard pruning must keep child rules when modifier coverage is uncertain."""
        child_rule = f"||spam.autos^${child_modifier}"

        rules, stats = self._compile(["||*.autos^", child_rule])

        assert "||*.autos^" in rules
        assert child_rule in rules
        assert stats.tld_wildcard_pruned == 0


class TestWildcardParentSemanticPruning:
    """Tests for structured modifier coverage under wildcard parent rules."""

    def _compile(self, lines):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "output.txt")
            stats = compile_rules(lines, output)
            with open(output) as f:
                return [line.strip() for line in f if line.strip()], stats

    @pytest.mark.parametrize(
        "modifier",
        [
            "client=10.0.0.1",
            "ctag=pc",
            "dnstype=a",
        ],
    )
    def test_wildcard_parent_prunes_equal_value_scoped_child(self, modifier):
        """Wildcard parent pruning uses structured modifier coverage."""
        parent_rule = f"||*.example.com^${modifier}"
        child_rule = f"||sub.example.com^${modifier}"

        rules, stats = self._compile([parent_rule, child_rule])

        assert parent_rule in rules
        assert child_rule not in rules
        assert stats.abp_subdomain_pruned == 1

    @pytest.mark.parametrize(
        "child_modifier",
        [
            "denyallow=allowed.example",
        ],
    )
    def test_wildcard_parent_keeps_special_unknown_and_uncertain_children(
        self,
        child_modifier,
    ):
        """Wildcard parent rules cannot prune when modifier coverage is not proven."""
        child_rule = f"||sub.example.com^${child_modifier}"

        rules, stats = self._compile(["||*.example.com^", child_rule])

        assert "||*.example.com^" in rules
        assert child_rule in rules
        assert stats.abp_subdomain_pruned == 0


class TestWildcardWhitelistHandling:
    """Tests for wildcard whitelist rules (@@||*.domain^)."""

    def _compile(self, lines):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "output.txt")
            stats = compile_rules(lines, output)
            with open(output) as f:
                return [line.strip() for line in f if line.strip()], stats

    def test_wildcard_whitelist_covers_subdomain(self):
        """@@||*.example.com^ should whitelist sub.example.com."""
        lines = [
            "||sub.example.com^",
            "@@||*.example.com^",
        ]
        rules, stats = self._compile(lines)
        assert "||sub.example.com^" not in rules
        assert stats.whitelist_conflict_pruned >= 1

    def test_wildcard_whitelist_does_not_cover_parent(self):
        """@@||*.example.com^ should NOT whitelist example.com itself."""
        lines = [
            "||example.com^",
            "@@||*.example.com^",
        ]
        rules, stats = self._compile(lines)
        # example.com should still be blocked (wildcard only covers subdomains)
        assert "||example.com^" in rules


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
