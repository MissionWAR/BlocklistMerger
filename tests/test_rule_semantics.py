from __future__ import annotations

import pytest

from scripts.rule_semantics import (
    ModifierValue,
    ParsedModifier,
    canonical_modifier_signature,
    modifier_names,
    modifier_scope_covers,
    parse_modifier_text,
)


def test_parse_modifier_text_returns_empty_tuple_for_no_modifiers() -> None:
    assert parse_modifier_text(None) == ()
    assert parse_modifier_text("") == ()


def test_client_values_are_structured_and_not_collapsed() -> None:
    first = parse_modifier_text("client=10.0.0.1")
    second = parse_modifier_text("client=192.168.1.5")

    assert first[0].name == "client"
    assert first[0].raw == "client=10.0.0.1"
    assert first[0].raw_value == "10.0.0.1"
    assert first[0].values == (ModifierValue("10.0.0.1", "10.0.0.1", False),)
    assert first[0].values != second[0].values


def test_modifier_and_value_negation_are_preserved() -> None:
    modifiers = parse_modifier_text("~client=~10.0.0.1|192.168.1.5")

    assert modifiers[0].name == "client"
    assert modifiers[0].negated is True
    assert modifiers[0].values == (
        ModifierValue("~10.0.0.1", "10.0.0.1", True),
        ModifierValue("192.168.1.5", "192.168.1.5", False),
    )


@pytest.mark.parametrize(
    ("modifier_text", "expected_name", "expected_values"),
    [
        (
            "ctag=~pc|mobile",
            "ctag",
            (
                ModifierValue("~pc", "pc", True),
                ModifierValue("mobile", "mobile", False),
            ),
        ),
        (
            "dnstype=a|AAAA",
            "dnstype",
            (
                ModifierValue("a", "A", False),
                ModifierValue("AAAA", "AAAA", False),
            ),
        ),
        (
            "dnsrewrite=1.2.3.4",
            "dnsrewrite",
            (ModifierValue("1.2.3.4", "1.2.3.4", False),),
        ),
        (
            "denyallow=allowed.example|other.example",
            "denyallow",
            (
                ModifierValue("allowed.example", "allowed.example", False),
                ModifierValue("other.example", "other.example", False),
            ),
        ),
    ],
)
def test_known_value_modifiers_preserve_raw_and_structured_values(
    modifier_text: str,
    expected_name: str,
    expected_values: tuple[ModifierValue, ...],
) -> None:
    modifiers = parse_modifier_text(modifier_text)

    assert modifiers[0].name == expected_name
    assert modifiers[0].raw == modifier_text
    assert modifiers[0].raw_value == modifier_text.split("=", 1)[1]
    assert modifiers[0].values == expected_values
    assert modifiers[0].uncertain is False


def test_flag_modifiers_have_no_values() -> None:
    modifiers = parse_modifier_text("badfilter,important")

    assert [(modifier.name, modifier.raw_value, modifier.values) for modifier in modifiers] == [
        ("badfilter", None, ()),
        ("important", None, ()),
    ]
    assert not any(modifier.uncertain for modifier in modifiers)


def test_escaped_delimiters_inside_quoted_client_values_are_not_split() -> None:
    modifiers = parse_modifier_text("client='Mary\\, John\\|Laptop'|192.168.1.5")

    assert modifiers[0].raw == "client='Mary\\, John\\|Laptop'|192.168.1.5"
    assert modifiers[0].raw_value == "'Mary\\, John\\|Laptop'|192.168.1.5"
    assert modifiers[0].values == (
        ModifierValue("'Mary\\, John\\|Laptop'", "Mary, John|Laptop", False),
        ModifierValue("192.168.1.5", "192.168.1.5", False),
    )
    assert modifiers[0].uncertain is False


@pytest.mark.parametrize(
    "modifier_text",
    [
        "unknown=value",
        "client='unterminated",
        "=missing-name",
    ],
)
def test_unknown_or_malformed_chunks_are_uncertain_records(modifier_text: str) -> None:
    modifiers = parse_modifier_text(modifier_text)

    assert len(modifiers) == 1
    assert modifiers[0].raw == modifier_text
    assert modifiers[0].uncertain is True


def test_modifier_names_returns_names_from_structured_records() -> None:
    modifiers = parse_modifier_text("client=10.0.0.1,dnstype=A,important")

    assert modifier_names(modifiers) == frozenset({"client", "dnstype", "important"})


def test_canonical_signature_matches_reordered_equivalent_modifiers() -> None:
    first = parse_modifier_text("client=10.0.0.1,dnstype=A")
    second = parse_modifier_text("dnstype=a,client=10.0.0.1")

    assert canonical_modifier_signature(first) == canonical_modifier_signature(second)


@pytest.mark.parametrize(
    ("first_text", "second_text"),
    [
        ("client=10.0.0.1", "client=192.168.1.5"),
        ("ctag=pc", "ctag=mobile"),
        ("dnstype=A", "dnstype=AAAA"),
        ("dnsrewrite=1.2.3.4", "dnsrewrite=5.6.7.8"),
        ("denyallow=allowed.example", "denyallow=other.example"),
    ],
)
def test_canonical_signature_preserves_behavior_changing_values(
    first_text: str,
    second_text: str,
) -> None:
    first = parse_modifier_text(first_text)
    second = parse_modifier_text(second_text)

    assert canonical_modifier_signature(first) != canonical_modifier_signature(second)


@pytest.mark.parametrize(
    ("parent_text", "child_text"),
    [
        (None, None),
        (None, "client=10.0.0.1"),
        (None, "ctag=pc"),
        (None, "dnstype=A"),
        ("client=10.0.0.1", "client=10.0.0.1"),
        ("ctag=pc", "ctag=pc"),
        ("dnstype=a", "dnstype=A"),
        ("client=10.0.0.1", "client=10.0.0.1,dnstype=A"),
    ],
)
def test_modifier_scope_covers_proven_broad_or_equal_scopes(
    parent_text: str | None,
    child_text: str | None,
) -> None:
    assert modifier_scope_covers(
        parse_modifier_text(parent_text),
        parse_modifier_text(child_text),
    )


@pytest.mark.parametrize(
    ("parent_text", "child_text"),
    [
        ("client=10.0.0.1", None),
        ("client=10.0.0.1", "client=192.168.1.5"),
        (None, "important"),
        ("important", None),
        ("dnsrewrite=1.2.3.4", "dnsrewrite=1.2.3.4"),
        ("denyallow=allowed.example", "denyallow=allowed.example"),
        ("badfilter", None),
        ("unknown=value", None),
        (None, "unknown=value"),
    ],
)
def test_modifier_scope_does_not_cover_unproven_or_special_scopes(
    parent_text: str | None,
    child_text: str | None,
) -> None:
    assert (
        modifier_scope_covers(
            parse_modifier_text(parent_text),
            parse_modifier_text(child_text),
        )
        is False
    )


def test_modifier_scope_rejects_unknown_record_even_if_uncertainty_flag_is_wrong() -> None:
    unknown = (
        ParsedModifier(
            name="future-modifier",
            raw="future-modifier",
            raw_value=None,
            values=(),
            negated=False,
            uncertain=False,
        ),
    )

    assert modifier_scope_covers(unknown, ()) is False
    assert modifier_scope_covers((), unknown) is False
