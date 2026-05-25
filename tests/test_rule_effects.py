from __future__ import annotations

import pytest

from scripts.rule_semantics import (
    EFFECT_BLOCK,
    EFFECT_DISABLE,
    EFFECT_EXCEPTION,
    EFFECT_IGNORED,
    EFFECT_REWRITE,
    EFFECT_UNSUPPORTED,
    classify_rule_effect,
)


@pytest.mark.parametrize(
    ("rule", "expected_effect", "expected_scope", "expected_uncertain"),
    [
        ("||example.org^", EFFECT_BLOCK, "apex_and_subdomains", False),
        ("@@||example.org^", EFFECT_EXCEPTION, "apex_and_subdomains", False),
        ("||example.org^$dnsrewrite=1.2.3.4", EFFECT_REWRITE, "apex_and_subdomains", False),
        ("||example.org^$badfilter", EFFECT_DISABLE, "apex_and_subdomains", False),
        ("||example.org^$unknown=value", EFFECT_UNSUPPORTED, "unsupported_modifier", True),
    ],
)
def test_core_rule_effect_taxonomy(
    rule: str,
    expected_effect: str,
    expected_scope: str,
    expected_uncertain: bool,
) -> None:
    effect = classify_rule_effect(rule)

    assert effect.syntax_kind == "abp"
    assert effect.effect == expected_effect
    assert effect.scope == expected_scope
    assert effect.docs_source == "adguard_dns_filtering_syntax"
    assert effect.uncertain is expected_uncertain
    assert effect.reason


@pytest.mark.parametrize(
    ("rule", "expected_kind"),
    [
        ("0.0.0.0 example.org", "hosts"),
        ("example.org", "plain_domain"),
    ],
)
def test_hosts_and_plain_domains_expose_exact_host_baseline_and_project_policy(
    rule: str,
    expected_kind: str,
) -> None:
    effect = classify_rule_effect(rule)

    assert effect.syntax_kind == expected_kind
    assert effect.effect == EFFECT_BLOCK
    assert effect.scope == "exact_host"
    assert "project_policy_promotes_to_abp" in effect.reason
    assert "adguard_home_hosts_blocklists" in effect.docs_source
    assert "project_policy" in effect.docs_source
    assert effect.uncertain is False


@pytest.mark.parametrize(
    ("rule", "reason_fragment", "expected_scope"),
    [
        (
            "||example.org^$client=10.0.0.1",
            "known_scoped_modifier:client",
            "scoped_apex_and_subdomains",
        ),
        ("||example.org^$ctag=pc", "known_scoped_modifier:ctag", "scoped_apex_and_subdomains"),
        (
            "||example.org^$dnstype=A",
            "known_scoped_modifier:dnstype",
            "scoped_apex_and_subdomains",
        ),
        (
            "||example.org^$denyallow=allowed.example",
            "known_scoped_modifier:denyallow",
            "scoped_apex_and_subdomains",
        ),
        ("||example.org^$important", "known_priority_modifier:important", "apex_and_subdomains"),
    ],
)
def test_known_scoped_and_priority_modifiers_are_non_unsupported(
    rule: str,
    reason_fragment: str,
    expected_scope: str,
) -> None:
    effect = classify_rule_effect(rule)

    assert effect.syntax_kind == "abp"
    assert effect.effect == EFFECT_BLOCK
    assert effect.effect != EFFECT_UNSUPPORTED
    assert effect.scope == expected_scope
    assert reason_fragment in effect.reason
    assert effect.uncertain is True


def test_scoped_exception_marks_unproven_scope_uncertain() -> None:
    effect = classify_rule_effect("@@||example.org^$client=10.0.0.1")

    assert effect.syntax_kind == "abp"
    assert effect.effect == EFFECT_EXCEPTION
    assert effect.scope == "scoped_apex_and_subdomains"
    assert "exception_scope_unproven" in effect.reason
    assert "known_scoped_modifier:client" in effect.reason
    assert effect.uncertain is True


def test_regex_rules_are_preserved_without_structural_pruning_proof() -> None:
    effect = classify_rule_effect("/^example\\.org$/")

    assert effect.syntax_kind == "regex"
    assert effect.effect == EFFECT_BLOCK
    assert effect.scope == "regex"
    assert "regex_preserved_dns_rule" in effect.reason
    assert "no_structural_pruning_proof" in effect.reason
    assert effect.uncertain is True


@pytest.mark.parametrize(
    ("rule", "expected_effect"),
    [
        ("||", EFFECT_IGNORED),
        ("||example.org/ads/", EFFECT_UNSUPPORTED),
        ("localhost", EFFECT_IGNORED),
        ("0.0.0.0 localhost", EFFECT_IGNORED),
        ("8.8.8.8 dns.google", EFFECT_IGNORED),
        ("||example.org^$client='unterminated", EFFECT_UNSUPPORTED),
    ],
)
def test_invalid_unsupported_local_and_uncertain_rows_are_not_active_coverage(
    rule: str,
    expected_effect: str,
) -> None:
    effect = classify_rule_effect(rule)

    assert effect.effect == expected_effect
    assert effect.effect != EFFECT_BLOCK
    assert effect.scope != "apex_and_subdomains"
