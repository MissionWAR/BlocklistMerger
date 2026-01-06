#!/usr/bin/env python3
"""
cleaner.py - Rule Filtering and Validation for AdGuard Home

This module filters blocklist rules to keep only those compatible with AdGuard Home.
It's the first stage of the pipeline, running BEFORE the compiler.

CRITICAL UNDERSTANDING - DNS vs Browser Blocking:
    AdGuard Home is a DNS-level blocker, NOT a browser extension. This means:
    
    - DNS only sees domain names, not URLs, request types, or page content
    - Cosmetic rules (##) that hide page elements are USELESS at DNS level
    - Modifiers like $script, $image, $third-party are browser-only concepts
    
    Example: ||ads.example.com^$script,third-party
    - In browser: Block ads.example.com ONLY when loading scripts from third-party context
    - In DNS: ??? DNS can't know if a request is for a script or from third-party
    
    If we stripped the modifiers, we'd get ||ads.example.com^ which blocks EVERYTHING
    from that domain - a much more aggressive rule than intended! This could break sites.

DESIGN DECISION - Discard, Don't Strip:
    Rules with unsupported modifiers are COMPLETELY DISCARDED, not stripped.
    This prevents false positives and unexpected site breakage.
    
    A smaller, more accurate blocklist is better than a larger, overly-aggressive one.

KEY OPERATIONS:
    1. Remove comments (# and ! lines)
    2. Discard cosmetic/element-hiding rules (##, #@#, #$#, etc.)
    3. Discard rules with browser-only modifiers
    4. Keep hosts, plain domains, and ABP rules with supported modifiers
"""

import re
from typing import NamedTuple


# ============================================================================
# MODIFIER DEFINITIONS (based on official AdGuard DNS filtering syntax docs)
# ============================================================================

# Modifiers supported by AdGuard Home DNS filtering
SUPPORTED_MODIFIERS = frozenset({
    "important",       # Increases rule priority
    "badfilter",       # Disables matching rules
    "dnsrewrite",      # Rewrites DNS responses
    "denyallow",       # Excludes domains from blocking
    "client",          # Restricts to specific clients
    "dnstype",         # Filters by DNS record type
    "ctag",            # Client tags (keeping for completeness, though rare in public lists)
})

# Modifiers that are browser-only and NOT supported by AGH
# If a rule contains ANY of these, the ENTIRE RULE should be discarded
UNSUPPORTED_MODIFIERS = frozenset({
    # Content type modifiers (browser-only)
    "script", "image", "stylesheet", "font", "media", "object",
    "subdocument", "xmlhttprequest", "websocket", "webrtc",
    "ping", "other",
    # Shorthand content types
    "css", "js",
    # Third-party/first-party
    "third-party", "3p", "first-party", "1p",
    # Document modifiers
    "document", "doc", "popup", "all",
    # Network/redirect modifiers
    "network", "redirect", "redirect-rule", "empty", "mp4",
    # Request modification
    "csp", "permissions", "header", "removeparam", "removeheader",
    "replace", "hls", "jsonprune",
    # Exception modifiers
    "genericblock", "generichide", "elemhide", "specifichide",
    "jsinject", "urlblock", "content", "extension",
    # Domain restriction (would make rule domain-specific, not useful for DNS-wide)
    "domain",
    # Matching modifiers
    "match-case", "strict-first-party", "strict-third-party",
    # Stealth mode
    "stealth",
    # App-specific
    "app",
    # Method restrictions (browser-only)
    "method",
    # Any other modifiers not in supported list
})


# ============================================================================
# REGEX PATTERNS
# ============================================================================

# Cosmetic/element-hiding rule patterns (DISCARD entirely)
# These include: ## #@# #?# #$# #$?# #@?# #@$# etc.
COSMETIC_PATTERN = re.compile(
    r"#[@$?%]*#|"            # Standard element hiding: ## #@# #?# #$# etc.
    r"#[@$?%]*\?#|"          # Extended CSS: #?# #@?# etc.
    r"\$#|"                  # Snippet injection: $#
    r"#%#|"                  # Scriptlet injection: #%#
    r"\[adblock",            # Adblock header
    re.IGNORECASE
)

# Pattern to detect if a line is likely a comment
COMMENT_PATTERN = re.compile(r"^\s*[#!]")

# Trailing inline comment: match "# comment" preceded by whitespace
TRAILING_COMMENT_PATTERN = re.compile(r"\s+#\s+.*$")

# Pattern to extract modifier section from ABP rule
# Matches: $modifier1,modifier2,... at end of rule
MODIFIER_PATTERN = re.compile(r"\$([^$]+)$")

# Pattern to validate basic ABP format
ABP_RULE_PATTERN = re.compile(r"^@@?\|\|[^\s|^]+\^")


# ============================================================================
# DATA STRUCTURES
# ============================================================================

class CleanResult(NamedTuple):
    """Result of cleaning a single line."""
    line: str | None       # Cleaned line, or None if discarded
    discarded: bool        # True if line was discarded
    reason: str | None     # Reason for discard (for logging)


class CleanStats(NamedTuple):
    """Statistics from cleaning operation."""
    total_lines: int
    kept_lines: int
    comments_removed: int
    cosmetic_removed: int
    unsupported_modifier_removed: int
    empty_removed: int
    invalid_removed: int
    trimmed: int  # Lines that had whitespace trimmed


# ============================================================================
# CLEANING FUNCTIONS
# ============================================================================

def is_comment(line: str) -> bool:
    """Check if line is a comment (starts with # or !)."""
    return bool(COMMENT_PATTERN.match(line))


def is_cosmetic_rule(line: str) -> bool:
    """
    Check if line is a cosmetic/element-hiding rule.
    
    These rules can't be processed by AdGuard Home (DNS-level blocker)
    and should be completely discarded.
    """
    return bool(COSMETIC_PATTERN.search(line))


def strip_trailing_comment(line: str) -> str:
    """
    Remove trailing inline comments to reduce file size.
    
    Example:
        "||example.com^ # block ads"  ->  "||example.com^"
    
    Be careful not to strip URL fragments or rule modifiers.
    """
    # Don't process lines that might have # in modifiers
    if "$" in line and "#" in line.split("$")[-1]:
        return line
    
    # Only strip if there's whitespace before the #
    match = TRAILING_COMMENT_PATTERN.search(line)
    if match:
        return line[:match.start()].rstrip()
    return line


def extract_modifiers(rule: str) -> set[str]:
    """
    Extract modifier names from an ABP-style rule.
    
    Example:
        "||example.com^$script,third-party" -> {"script", "third-party"}
        "||example.com^$important" -> {"important"}
        "||example.com^" -> set()
    """
    match = MODIFIER_PATTERN.search(rule)
    if not match:
        return set()
    
    modifier_string = match.group(1)
    modifiers = set()
    
    for part in modifier_string.split(","):
        # Handle modifiers with values: client=192.168.1.1, dnsrewrite=example.com
        modifier_name = part.split("=")[0].strip().lower()
        # Handle negation: ~third-party
        if modifier_name.startswith("~"):
            modifier_name = modifier_name[1:]
        if modifier_name:
            modifiers.add(modifier_name)
    
    return modifiers


def has_unsupported_modifiers(modifiers: set[str]) -> bool:
    """
    Check if any modifier is unsupported by AdGuard Home.
    
    If ANY unsupported modifier is found, the rule should be DISCARDED
    (not stripped) to avoid false positives and breakage.
    """
    return bool(modifiers & UNSUPPORTED_MODIFIERS)


def clean_line(line: str) -> tuple[CleanResult, bool]:
    """
    Clean a single rule line.
    
    Returns:
        (CleanResult, was_trimmed) - was_trimmed is True if whitespace was removed
    """
    original = line
    
    # Strip whitespace
    line = line.strip()
    was_trimmed = len(line) != len(original) and len(line) > 0
    
    # Skip empty lines
    if not line:
        return CleanResult(None, True, "empty"), False
    
    # Remove full-line comments
    if is_comment(line):
        return CleanResult(None, True, "comment"), False
    
    # Discard cosmetic/element-hiding rules
    # Example: example.com##.ad-banner, example.com#$#div
    if is_cosmetic_rule(line):
        return CleanResult(None, True, "cosmetic"), False
    
    # Strip trailing inline comments
    line_before_comment = line
    line = strip_trailing_comment(line)
    if len(line) != len(line_before_comment):
        was_trimmed = True
    
    # For ABP-style rules, check modifiers
    if line.startswith("||") or line.startswith("@@||"):
        modifiers = extract_modifiers(line)
        if modifiers and has_unsupported_modifiers(modifiers):
            # DISCARD entire rule (as per user's requirement)
            # This prevents false positives like blocking google.com when
            # the original rule was "$third-party" (third-party connections only)
            return CleanResult(None, True, "unsupported_modifier"), False
    
    # Handle rules with just $ and modifiers (no pattern)
    # e.g., "$script,third-party" without a domain prefix
    if line.startswith("$") or ("|" not in line and "$" in line):
        modifiers = extract_modifiers(line)
        if modifiers and has_unsupported_modifiers(modifiers):
            return CleanResult(None, True, "unsupported_modifier"), False
    
    # Line is valid, return cleaned version
    return CleanResult(line, False, None), was_trimmed


def clean_lines(lines: list[str]) -> tuple[list[str], CleanStats]:
    """
    Clean a list of lines.
    
    Returns:
        (cleaned_lines, stats)
    """
    cleaned = []
    stats = {
        "total": 0,
        "kept": 0,
        "comments": 0,
        "cosmetic": 0,
        "unsupported_modifier": 0,
        "empty": 0,
        "invalid": 0,
        "trimmed": 0,
    }
    
    for line in lines:
        stats["total"] += 1
        result, was_trimmed = clean_line(line)
        
        if was_trimmed:
            stats["trimmed"] += 1
        
        if result.discarded:
            if result.reason == "comment":
                stats["comments"] += 1
            elif result.reason == "cosmetic":
                stats["cosmetic"] += 1
            elif result.reason == "unsupported_modifier":
                stats["unsupported_modifier"] += 1
            elif result.reason == "empty":
                stats["empty"] += 1
            else:
                stats["invalid"] += 1
        else:
            cleaned.append(result.line)
            stats["kept"] += 1
    
    return cleaned, CleanStats(
        total_lines=stats["total"],
        kept_lines=stats["kept"],
        comments_removed=stats["comments"],
        cosmetic_removed=stats["cosmetic"],
        unsupported_modifier_removed=stats["unsupported_modifier"],
        empty_removed=stats["empty"],
        invalid_removed=stats["invalid"],
        trimmed=stats["trimmed"],
    )


def clean_file(input_path: str, output_path: str | None = None) -> CleanStats:
    """
    Clean a single file.
    
    Args:
        input_path: Path to input file
        output_path: Path to output file (defaults to in-place modification)
    
    Returns:
        CleanStats
    """
    from pathlib import Path
    
    in_path = Path(input_path)
    out_path = Path(output_path) if output_path else in_path
    
    with open(in_path, encoding="utf-8-sig", errors="replace") as f:
        lines = f.readlines()
    
    cleaned, stats = clean_lines(lines)
    
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        for line in cleaned:
            f.write(line + "\n")
    
    return stats


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python -m scripts.cleaner <input_file> [output_file]")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    stats = clean_file(input_file, output_file)
    
    print(f"Cleaned: {stats.total_lines} total, {stats.kept_lines} kept")
    print(f"  Removed: {stats.comments_removed} comments, "
          f"{stats.cosmetic_removed} cosmetic, "
          f"{stats.unsupported_modifier_removed} unsupported modifiers, "
          f"{stats.empty_removed} empty, "
          f"{stats.invalid_removed} invalid")
