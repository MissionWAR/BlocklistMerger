from __future__ import annotations

import pytest

from scripts.rule_semantics import ModifierValue, parse_modifier_text


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
