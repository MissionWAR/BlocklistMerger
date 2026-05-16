from __future__ import annotations

from scripts.cleaner import extract_modifiers
from scripts.compiler import (
    EMPTY_FROZENSET,
    _parse_abp_rule,
    extract_abp_info,
    extract_hosts_info,
    get_registered_domain,
    normalize_domain,
    should_prune_by_modifiers,
    walk_parent_domains,
)
from scripts.rule_semantics import canonical_modifier_signature


def test_normalize_domain_basic_and_trailing_dot() -> None:
    assert normalize_domain("Example.COM") == "example.com"
    assert normalize_domain("  example.com.  ") == "example.com"


def test_extract_abp_info_basic_and_exception_and_wildcard() -> None:
    domain, mods, is_exc, is_wc = extract_abp_info("||example.com^")
    assert domain == "example.com"
    assert mods is EMPTY_FROZENSET
    assert is_exc is False
    assert is_wc is False

    domain, mods, is_exc, is_wc = extract_abp_info("||example.com^$important,client=1.2.3.4")
    assert domain == "example.com"
    assert mods == frozenset({"important", "client"})
    assert is_exc is False
    assert is_wc is False

    domain, mods, is_exc, is_wc = extract_abp_info("@@||*.example.net^")
    assert domain == "example.net"
    assert mods is EMPTY_FROZENSET
    assert is_exc is True
    assert is_wc is True

    # Malformed rule should return (None, EMPTY_FROZENSET, False, False)
    domain, mods, is_exc, is_wc = extract_abp_info("||^")
    assert domain is None
    assert mods is EMPTY_FROZENSET
    assert is_exc is False
    assert is_wc is False


def test_parse_abp_rule_preserves_structured_modifier_values() -> None:
    rule = (
        "||example.com^$client=10.0.0.1,ctag=pc,dnstype=a,"
        "dnsrewrite=1.2.3.4,denyallow=allowed.example"
    )

    record = _parse_abp_rule(rule)

    assert record is not None
    assert record.rule == rule
    assert record.domain == "example.com"
    assert record.is_exception is False
    assert record.is_wildcard is False
    assert record.modifier_names == frozenset(
        {"client", "ctag", "dnstype", "dnsrewrite", "denyallow"}
    )
    assert record.semantic_signature == canonical_modifier_signature(record.modifiers)

    raw_values_by_name = {
        modifier.name: modifier.raw_value
        for modifier in record.modifiers
    }
    assert raw_values_by_name == {
        "client": "10.0.0.1",
        "ctag": "pc",
        "dnstype": "a",
        "dnsrewrite": "1.2.3.4",
        "denyallow": "allowed.example",
    }


def test_extract_hosts_info_blocking_and_non_blocking_ip() -> None:
    ip, domains = extract_hosts_info("0.0.0.0 example.com ads.example.com")
    assert ip == "0.0.0.0"
    assert domains == ["example.com", "ads.example.com"]

    # Non-blocking real IP should be ignored
    ip, domains = extract_hosts_info("8.8.8.8 dns.google")
    assert ip is None
    assert domains == []


def test_walk_parent_domains_and_registered_domain() -> None:
    parents = walk_parent_domains("a.b.example.co.uk")
    assert parents == ("b.example.co.uk", "example.co.uk")

    parents = walk_parent_domains("example.com")
    assert parents == ()

    assert get_registered_domain("deep.sub.example.com") == "example.com"
    assert get_registered_domain("example.co.uk") == "example.co.uk"


def test_should_prune_by_modifiers_basic_cases() -> None:
    # No modifiers on either side → prune
    assert should_prune_by_modifiers(EMPTY_FROZENSET, EMPTY_FROZENSET) is True

    # Parent with badfilter should never prune
    assert (
        should_prune_by_modifiers(EMPTY_FROZENSET, frozenset({"badfilter"}))
        is False
    )

    # Child important must not be pruned by non-important parent
    assert (
        should_prune_by_modifiers(frozenset({"important"}), EMPTY_FROZENSET)
        is False
    )

    # Child with special behavior should not be pruned
    for mod in ("dnsrewrite", "denyallow", "badfilter"):
        assert (
            should_prune_by_modifiers(frozenset({mod}), EMPTY_FROZENSET)
            is False
        )


def test_should_prune_by_modifiers_dnstype_and_client_restrictions() -> None:
    # Child dnstype vs parent without dnstype → parent blocks all types, prune
    assert (
        should_prune_by_modifiers(frozenset({"dnstype"}), EMPTY_FROZENSET)
        is True
    )

    # Parent dnstype vs child without → child blocks all types, do not prune
    assert (
        should_prune_by_modifiers(EMPTY_FROZENSET, frozenset({"dnstype"}))
        is False
    )

    # Parent/client restricted vs unrestricted child → do not prune
    assert (
        should_prune_by_modifiers(
            EMPTY_FROZENSET,
            frozenset({"client"}),
        )
        is False
    )


def test_cleaner_extract_modifiers_roundtrip() -> None:
    # Sanity check that cleaner and compiler agree on modifier parsing basics
    mods = extract_modifiers("||example.com^$important,third-party,~script")
    # UNSUPPORTED_MODIFIERS are defined in cleaner; this test just checks
    # extraction logic here and keeps the set small.
    assert "important" in mods
    assert "third-party" in mods
    assert "script" in mods
    # Negation should be unwrapped
    assert "~script" not in mods

