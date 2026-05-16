#!/usr/bin/env python3
"""
rule_syntax.py - Shared AdGuard Home rule syntax classification helpers.

This module owns lightweight tokenization shared by the cleaner and compiler.
It is deliberately not a full AdGuard parser: it only identifies the syntax
boundaries this project needs before DNS-level compatibility decisions.
"""

import re
from typing import Final, NamedTuple

# =============================================================================
# RULE KIND CONSTANTS
# =============================================================================

RULE_KIND_ABP: Final[str] = "abp"
RULE_KIND_HOSTS: Final[str] = "hosts"
RULE_KIND_INVALID: Final[str] = "invalid"
RULE_KIND_OTHER: Final[str] = "other"
RULE_KIND_PLAIN_DOMAIN: Final[str] = "plain_domain"
RULE_KIND_REGEX: Final[str] = "regex"


# =============================================================================
# REGEX PATTERNS
# =============================================================================

HOSTS_PREFIX_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[\d.:a-fA-F]+\s+\S+")
PLAIN_DOMAIN_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)


# =============================================================================
# DATA STRUCTURES
# =============================================================================


class RuleSyntax(NamedTuple):
    """
    Tokenized rule syntax.

    Attributes:
        raw: Original rule text passed to the classifier.
        pattern: Rule pattern before optional modifiers.
        modifier_text: Raw modifier section without the leading `$`, if present.
        modifier_names: Parsed lowercase modifier names without values or `~`.
        is_exception: True when the rule starts with `@@`.
        kind: Lightweight rule kind constant.
        has_url_path: True when a non-regex pattern contains URL path syntax.
        is_invalid: True for narrow malformed cases pinned by Phase 1.
    """

    raw: str
    pattern: str
    modifier_text: str | None
    modifier_names: frozenset[str]
    is_exception: bool
    kind: str
    has_url_path: bool
    is_invalid: bool


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================


def _is_escaped(text: str, index: int) -> bool:
    """Return True if the character at index is escaped by an odd number of backslashes."""
    backslashes = 0
    cursor = index - 1
    while cursor >= 0 and text[cursor] == "\\":
        backslashes += 1
        cursor -= 1
    return backslashes % 2 == 1


def _find_regex_end(pattern: str) -> int | None:
    """Find the closing slash for a regex pattern, ignoring escaped slashes."""
    if not pattern.startswith("/"):
        return None

    for index in range(1, len(pattern)):
        if pattern[index] == "/" and not _is_escaped(pattern, index):
            return index
    return None


def split_pattern_and_modifiers(rule: str) -> tuple[str, str | None]:
    """
    Split a rule into pattern and raw modifier text.

    Regex patterns may contain `$` before their closing slash, so regex rules are
    split only after the closing regex delimiter.
    """
    rule = rule.strip()
    candidate = rule[2:] if rule.startswith("@@/") else rule

    if candidate.startswith("/"):
        regex_end = _find_regex_end(candidate)
        if regex_end is not None:
            split_at = regex_end + 1
            if len(candidate) > split_at and candidate[split_at] == "$":
                pattern = candidate[:split_at]
                if rule.startswith("@@/"):
                    pattern = f"@@{pattern}"
                return pattern, candidate[split_at + 1 :] or None
            return rule, None

    modifier_start = rule.rfind("$")
    if modifier_start == -1:
        return rule, None
    return rule[:modifier_start], rule[modifier_start + 1 :] or None


def extract_modifier_names(modifier_text: str | None) -> frozenset[str]:
    """
    Extract lowercase modifier names from raw modifier text.

    Values are intentionally preserved in `RuleSyntax.modifier_text`; this helper
    returns names only for support checks and pruning decisions.
    """
    if not modifier_text:
        return frozenset()

    names: set[str] = set()
    for part in modifier_text.split(","):
        name = part.split("=", 1)[0].strip().lower()
        if name.startswith("~"):
            name = name[1:]
        if name:
            names.add(name)
    return frozenset(names)


def is_regex_pattern(pattern: str) -> bool:
    """Return True for valid `/.../` regex patterns, including exception regexes."""
    candidate = pattern[2:] if pattern.startswith("@@/") else pattern
    regex_end = _find_regex_end(candidate)
    return regex_end is not None and regex_end == len(candidate) - 1


def pattern_has_url_path(pattern: str) -> bool:
    """
    Return True when a non-regex rule pattern contains URL path syntax.

    The cleaner runs this after modifier splitting, so slash-like modifier values
    such as `$client=192.168.0.0/24` do not trigger URL-path rejection.
    """
    if is_regex_pattern(pattern):
        return False

    candidate = pattern[2:] if pattern.startswith("@@") else pattern
    if "://" in candidate:
        return True

    if candidate.startswith("||"):
        body = candidate[2:]
        separator_index = body.find("^")
        slash_index = body.find("/")
        return slash_index != -1 and (separator_index == -1 or slash_index < separator_index)

    return "/" in candidate


def _classify_kind(pattern: str, is_invalid: bool) -> str:
    """Classify the coarse rule kind from the already-split pattern."""
    if is_invalid:
        return RULE_KIND_INVALID

    candidate = pattern[2:] if pattern.startswith("@@") else pattern
    if candidate.startswith("||"):
        return RULE_KIND_ABP
    if is_regex_pattern(pattern):
        return RULE_KIND_REGEX
    if HOSTS_PREFIX_PATTERN.match(pattern):
        return RULE_KIND_HOSTS
    if PLAIN_DOMAIN_PATTERN.match(pattern):
        return RULE_KIND_PLAIN_DOMAIN
    return RULE_KIND_OTHER


def classify_rule_syntax(rule: str) -> RuleSyntax:
    """
    Classify the lightweight syntax features needed by cleaner/compiler.

    Phase 1 intentionally marks only narrow invalid cases to avoid reducing
    blocking coverage by rejecting uncommon but valid AdGuard Home syntax.
    """
    raw = rule
    pattern, modifier_text = split_pattern_and_modifiers(rule)
    modifier_names = extract_modifier_names(modifier_text)
    is_exception = pattern.startswith("@@")
    candidate = pattern[2:] if is_exception else pattern
    is_invalid = not candidate or candidate in {"||", "||^"}
    has_url_path = pattern_has_url_path(pattern)
    kind = _classify_kind(pattern, is_invalid)

    return RuleSyntax(
        raw=raw,
        pattern=pattern,
        modifier_text=modifier_text,
        modifier_names=modifier_names,
        is_exception=is_exception,
        kind=kind,
        has_url_path=has_url_path,
        is_invalid=is_invalid,
    )
