#!/usr/bin/env python3
"""
rule_semantics.py - Structured AdGuard Home rule modifier semantics.

This module parses raw ABP modifier text into immutable semantic records for
compiler pruning decisions. It is intentionally conservative: unsupported,
unknown, or ambiguous modifier chunks are preserved as uncertain records so
downstream code can keep rules instead of proving unsafe equivalence.
"""

from typing import Final, NamedTuple

# =============================================================================
# MODIFIER CONSTANTS
# =============================================================================

VALUE_MODIFIERS: Final[frozenset[str]] = frozenset({
    "client",
    "ctag",
    "denyallow",
    "dnsrewrite",
    "dnstype",
})

FLAG_MODIFIERS: Final[frozenset[str]] = frozenset({
    "badfilter",
    "important",
})

KNOWN_MODIFIERS: Final[frozenset[str]] = VALUE_MODIFIERS | FLAG_MODIFIERS

NARROW_SCOPE_MODIFIERS: Final[frozenset[str]] = frozenset({
    "client",
    "ctag",
    "dnstype",
})

NO_COVERAGE_MODIFIERS: Final[frozenset[str]] = frozenset({
    "badfilter",
    "denyallow",
    "dnsrewrite",
})

__all__ = [
    "ModifierValue",
    "ParsedModifier",
    "canonical_modifier_signature",
    "modifier_names",
    "modifier_scope_covers",
    "parse_modifier_text",
]


# =============================================================================
# DATA STRUCTURES
# =============================================================================


class ModifierValue(NamedTuple):
    """
    Parsed value inside a value-bearing modifier.

    Attributes:
        raw: Raw value token, preserving value-level `~`, quoting, and escapes.
        value: Canonical semantic value used for comparisons.
        negated: True when the value token starts with a value-level `~`.
    """

    raw: str
    value: str
    negated: bool


class ParsedModifier(NamedTuple):
    """
    Parsed modifier record.

    Attributes:
        name: Lowercase modifier name without name-level `~`.
        raw: Raw modifier chunk without surrounding comma separators.
        raw_value: Raw text after `=`, if present.
        values: Parsed value records for value-bearing modifiers.
        negated: True when the modifier name starts with `~`.
        uncertain: True when this record must not enable pruning decisions.
    """

    name: str
    raw: str
    raw_value: str | None
    values: tuple[ModifierValue, ...]
    negated: bool
    uncertain: bool


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================


def _split_escaped(text: str, separator: str) -> tuple[tuple[str, ...], bool]:
    """Split on separator characters outside quotes and backslash escapes."""
    if not text:
        return (("",), False)

    parts: list[str] = []
    start = 0
    quote: str | None = None
    escaped = False

    for index, char in enumerate(text):
        if escaped:
            escaped = False
            continue

        if char == "\\":
            escaped = True
            continue

        if quote is not None:
            if char == quote:
                quote = None
            continue

        if char in {"'", '"'}:
            quote = char
            continue

        if char == separator:
            parts.append(text[start:index])
            start = index + 1

    parts.append(text[start:])
    return tuple(parts), quote is not None or escaped


def _unescape(text: str) -> str:
    """Remove backslash escape markers while preserving the escaped character."""
    chars: list[str] = []
    escaped = False

    for char in text:
        if escaped:
            chars.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        else:
            chars.append(char)

    if escaped:
        chars.append("\\")

    return "".join(chars)


def _decode_value(raw_value: str) -> str:
    """Decode a raw value token for semantic comparisons."""
    value = raw_value
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
    return _unescape(value)


def _canonical_value(name: str, raw_value: str) -> str:
    """Return the canonical semantic value for a modifier value token."""
    value = _decode_value(raw_value)
    if name == "dnstype":
        return value.upper()
    return value


def _parse_values(name: str, raw_value: str) -> tuple[tuple[ModifierValue, ...], bool]:
    """Parse pipe-separated modifier values."""
    value_parts, uncertain = _split_escaped(raw_value, "|")
    values: list[ModifierValue] = []

    for part in value_parts:
        raw_part = part.strip()
        value_negated = raw_part.startswith("~")
        semantic_raw = raw_part[1:] if value_negated else raw_part
        if not semantic_raw:
            uncertain = True

        values.append(
            ModifierValue(
                raw=raw_part,
                value=_canonical_value(name, semantic_raw),
                negated=value_negated,
            )
        )

    return tuple(values), uncertain


def _parse_name(raw_name: str) -> tuple[str, bool]:
    """Parse a modifier name and name-level negation."""
    name = raw_name.strip().lower()
    negated = name.startswith("~")
    if negated:
        name = name[1:].strip()
    return name, negated


def _has_duplicate_names(modifiers: tuple[ParsedModifier, ...]) -> bool:
    """Return True if a modifier tuple contains duplicate names."""
    names = [modifier.name for modifier in modifiers if modifier.name]
    return len(names) != len(set(names))


def _by_name(modifiers: tuple[ParsedModifier, ...]) -> dict[str, ParsedModifier]:
    """Return modifiers keyed by name."""
    return {modifier.name: modifier for modifier in modifiers if modifier.name}


def _value_signature(modifier: ParsedModifier) -> tuple[tuple[str, bool], ...]:
    """Return comparable value and value-negation data for a modifier."""
    return tuple((value.value, value.negated) for value in modifier.values)


def _modifier_signature(modifier: ParsedModifier) -> tuple[object, ...]:
    """Return one deterministic signature item for a parsed modifier."""
    return (
        modifier.name,
        modifier.negated,
        modifier.raw_value is not None,
        _value_signature(modifier),
        modifier.uncertain,
        modifier.raw if modifier.uncertain else "",
    )


# =============================================================================
# PUBLIC API
# =============================================================================


def parse_modifier_text(modifier_text: str | None) -> tuple[ParsedModifier, ...]:
    """
    Parse raw ABP modifier text into structured semantic records.

    Args:
        modifier_text: Raw modifier text without the leading `$`.

    Returns:
        Tuple of parsed modifier records. Empty input returns an empty tuple.
    """
    if not modifier_text:
        return ()

    raw_chunks, split_uncertain = _split_escaped(modifier_text, ",")
    modifiers: list[ParsedModifier] = []

    for chunk in raw_chunks:
        raw = chunk.strip()
        raw_name, separator, raw_value = raw.partition("=")
        name, negated = _parse_name(raw_name)
        raw_value_or_none = raw_value if separator else None

        uncertain = split_uncertain or not name or name not in KNOWN_MODIFIERS
        values: tuple[ModifierValue, ...] = ()

        if raw_value_or_none is None:
            if name in VALUE_MODIFIERS:
                uncertain = True
        else:
            values, values_uncertain = _parse_values(name, raw_value_or_none)
            uncertain = uncertain or values_uncertain
            if name in FLAG_MODIFIERS:
                uncertain = True
            if name in VALUE_MODIFIERS and not values:
                uncertain = True

        modifiers.append(
            ParsedModifier(
                name=name,
                raw=raw,
                raw_value=raw_value_or_none,
                values=values,
                negated=negated,
                uncertain=uncertain,
            )
        )

    return tuple(modifiers)


def modifier_names(modifiers: tuple[ParsedModifier, ...]) -> frozenset[str]:
    """Return lowercase modifier names from parsed modifier records."""
    return frozenset(modifier.name for modifier in modifiers if modifier.name)


def canonical_modifier_signature(modifiers: tuple[ParsedModifier, ...]) -> tuple[object, ...]:
    """
    Return a deterministic semantic signature for parsed modifiers.

    Reordered known modifiers with equivalent structured values produce the same
    signature. Uncertain records include raw text so they cannot accidentally
    collapse unrelated behavior.
    """
    return tuple(sorted(_modifier_signature(modifier) for modifier in modifiers))


def modifier_scope_covers(
    parent_modifiers: tuple[ParsedModifier, ...],
    child_modifiers: tuple[ParsedModifier, ...],
) -> bool:
    """
    Return True when parent modifiers prove broad enough coverage for a child rule.

    This helper is deliberately conservative. Unknown, uncertain, and special
    behavior modifiers return False because they cannot prove safe pruning.
    """
    if not parent_modifiers and not child_modifiers:
        return True

    all_modifiers = parent_modifiers + child_modifiers
    if any(modifier.uncertain for modifier in all_modifiers):
        return False
    if _has_duplicate_names(parent_modifiers) or _has_duplicate_names(child_modifiers):
        return False

    parent_names = modifier_names(parent_modifiers)
    child_names = modifier_names(child_modifiers)
    if (parent_names | child_names) & NO_COVERAGE_MODIFIERS:
        return False

    parent_by_name = _by_name(parent_modifiers)
    child_by_name = _by_name(child_modifiers)

    parent_important = parent_by_name.get("important")
    child_important = child_by_name.get("important")
    if (parent_important is None) != (child_important is None):
        return False
    if parent_important is not None and (
        parent_important.negated != child_important.negated
        or _value_signature(parent_important) != _value_signature(child_important)
    ):
        return False

    for name in NARROW_SCOPE_MODIFIERS:
        parent = parent_by_name.get(name)
        child = child_by_name.get(name)

        if parent is None:
            continue
        if child is None:
            return False
        if parent.negated != child.negated or _value_signature(parent) != _value_signature(child):
            return False

    return True
