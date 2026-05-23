from __future__ import annotations

import pytest

from scripts.rule_semantics import (
    EFFECT_BLOCK,
    EFFECT_DISABLE,
    EFFECT_EXCEPTION,
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
