#!/usr/bin/env python3
"""
cleaner.py - Rule Filtering and Validation for AdGuard Home

This module filters blocklist rules to keep only those compatible with AdGuard Home.
It's the first stage of the pipeline, running BEFORE the compiler.

Critical Understanding - DNS vs Browser Blocking:
    AdGuard Home is a DNS-level blocker, NOT a browser extension. This means:
    
    - DNS only sees domain names, not URLs, request types, or page content
    - Cosmetic rules (##) that hide page elements are USELESS at DNS level
    - Modifiers like $script, $image, $third-party are browser-only concepts
    
    Example: ||ads.example.com^$script,third-party
    - In browser: Block ads.example.com ONLY when loading scripts from third-party context
    - In DNS: ??? DNS can't know if a request is for a script or from third-party
    
    If we stripped the modifiers, we'd get ||ads.example.com^ which blocks EVERYTHING
    from that domain - a much more aggressive rule than intended! This could break sites.

Design Decision - Discard, Don't Strip:
    Rules with unsupported modifiers are COMPLETELY DISCARDED, not stripped.
    This prevents false positives and unexpected site breakage.
    
    A smaller, more accurate blocklist is better than a larger, overly-aggressive one.

Key Operations:
    1. Remove comments (# and ! lines)
    2. Discard cosmetic/element-hiding rules (##, #@#, #$#, etc.)
    3. Discard rules with browser-only modifiers
    4. Keep hosts, plain domains, and ABP rules with supported modifiers
    
See Also:
    - docs/ARCHITECTURE.md for pipeline overview
    - docs/PROJECT.md for project goals
"""

import re
from typing import Final, NamedTuple, TypedDict


# =============================================================================
# MODIFIER DEFINITIONS
# =============================================================================
# Based on official AdGuard DNS filtering syntax documentation.
# https://adguard-dns.io/kb/general/dns-filtering-syntax/

# Modifiers that are browser-only and NOT supported by AdGuard Home.
# If a rule contains ANY of these, the ENTIRE RULE should be discarded.
#
# Grouped by category for easier maintenance:
UNSUPPORTED_MODIFIERS: Final[frozenset[str]] = frozenset({
    # -------------------------------------------------------------------------
    # Content type modifiers (browser-only, DNS can't see content types)
    # -------------------------------------------------------------------------
    "script",         # JavaScript files
    "image",          # Images (png, jpg, etc.)
    "stylesheet",     # CSS files
    "font",           # Web fonts
    "media",          # Audio/video content
    "object",         # Flash/plugins (legacy)
    "subdocument",    # Iframes
    "xmlhttprequest", # AJAX requests
    "websocket",      # WebSocket connections
    "webrtc",         # WebRTC connections
    "ping",           # Navigator.sendBeacon()
    "other",          # Other content types
    
    # -------------------------------------------------------------------------
    # Shorthand content types
    # -------------------------------------------------------------------------
    "css",  # Alias for stylesheet
    "js",   # Alias for script
    
    # -------------------------------------------------------------------------
    # Third-party/first-party (requires page context)
    # -------------------------------------------------------------------------
    "third-party",  # Requests from different domain
    "3p",           # Shorthand for third-party
    "first-party",  # Requests from same domain
    "1p",           # Shorthand for first-party
    
    # -------------------------------------------------------------------------
    # Document modifiers (page-level blocking)
    # -------------------------------------------------------------------------
    "document",  # Block entire document
    "doc",       # Alias for document
    "popup",     # Block popups
    "all",       # Match all content types
    
    # -------------------------------------------------------------------------
    # Network/redirect modifiers (require HTTP-level access)
    # -------------------------------------------------------------------------
    "network",       # Network requests
    "redirect",      # Redirect to resource
    "redirect-rule", # Conditional redirect
    "empty",         # Return empty response
    "mp4",           # Return empty MP4
    
    # -------------------------------------------------------------------------
    # Request modification (HTTP header manipulation)
    # -------------------------------------------------------------------------
    "csp",          # Content Security Policy injection
    "permissions",  # Permissions Policy injection
    "header",       # HTTP header modification
    "removeparam",  # Remove URL parameters
    "removeheader", # Remove HTTP headers
    "replace",      # Replace response content
    "hls",          # HLS playlist modification
    "jsonprune",    # JSON response modification
    
    # -------------------------------------------------------------------------
    # Exception modifiers (browser extension exceptions)
    # -------------------------------------------------------------------------
    "genericblock",  # Disable generic blocking
    "generichide",   # Disable generic hiding
    "elemhide",      # Disable element hiding
    "specifichide",  # Disable specific hiding
    "jsinject",      # Disable JS injection
    "urlblock",      # Disable URL blocking
    "content",       # Disable content blocking
    "extension",     # Disable extension rules
    
    # -------------------------------------------------------------------------
    # Domain restriction (page-level, not useful for DNS-wide blocking)
    # -------------------------------------------------------------------------
    "domain",  # Only apply on specific domains
    
    # -------------------------------------------------------------------------
    # Matching modifiers (case sensitivity, strict party)
    # -------------------------------------------------------------------------
    "match-case",           # Case-sensitive matching
    "strict-first-party",   # Strict first-party check
    "strict-third-party",   # Strict third-party check
    
    # -------------------------------------------------------------------------
    # Other browser-only features
    # -------------------------------------------------------------------------
    "stealth",  # Stealth mode settings
    "app",      # App-specific rules
    "method",   # HTTP method restrictions
})


# =============================================================================
# REGEX PATTERNS
# =============================================================================

#: Cosmetic/element-hiding rule patterns (DISCARD entirely)
#: These include: ## #@# #?# #$# #$?# #@?# #@$# etc.
COSMETIC_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"#[@$?%]*#|"            # Standard element hiding: ## #@# #?# #$# etc.
    r"#[@$?%]*\?#|"          # Extended CSS: #?# #@?# etc.
    r"\$#|"                  # Snippet injection: $#
    r"#%#|"                  # Scriptlet injection: #%#
    r"\[adblock",            # Adblock header: [Adblock Plus ...]
    re.IGNORECASE
)

#: Pattern to detect if a line is a comment (starts with # or !)
COMMENT_PATTERN: Final[re.Pattern[str]] = re.compile(r"^\s*[#!]")

#: Trailing inline comment: match " # comment" (space before #)
#: Example: "||example.com^ # block ads" → "||example.com^"
TRAILING_COMMENT_PATTERN: Final[re.Pattern[str]] = re.compile(r"\s+#\s+.*$")

#: Pattern to extract modifier section from ABP rule
#: Matches: $modifier1,modifier2,... at end of rule
MODIFIER_PATTERN: Final[re.Pattern[str]] = re.compile(r"\$([^$]+)$")


# =============================================================================
# DATA STRUCTURES
# =============================================================================

class CleanResult(NamedTuple):
    """
    Result of cleaning a single line.
    
    Attributes:
        line: Cleaned line, or None if discarded
        discarded: True if line was discarded
        reason: Reason for discard (for logging/stats), or None if kept
        
    Example:
        >>> result = CleanResult("||example.com^", False, None)
        >>> result.discarded
        False
    """
    line: str | None
    discarded: bool
    reason: str | None


class CleanStats(NamedTuple):
    """
    Statistics from cleaning operation.
    
    Attributes:
        total_lines: Total lines processed
        kept_lines: Lines kept after cleaning
        comments_removed: Comment lines removed
        cosmetic_removed: Cosmetic/element-hiding rules removed
        unsupported_modifier_removed: Rules with unsupported modifiers removed
        empty_removed: Empty lines removed
        invalid_removed: Invalid/malformed lines removed
        trimmed: Lines that had whitespace trimmed
        
    Example:
        >>> stats = CleanStats(100, 80, 10, 5, 3, 2, 0, 15)
        >>> stats.kept_lines
        80
    """
    total_lines: int
    kept_lines: int
    comments_removed: int
    cosmetic_removed: int
    unsupported_modifier_removed: int
    empty_removed: int
    invalid_removed: int
    trimmed: int


class CleanStatsDict(TypedDict):
    """TypedDict for internal stats tracking with type safety."""
    total: int
    kept: int
    comments: int
    cosmetic: int
    unsupported_modifier: int
    empty: int
    invalid: int
    trimmed: int


# =============================================================================
# CLEANING FUNCTIONS
# =============================================================================

def is_comment(line: str) -> bool:
    """
    Check if line is a comment (starts with # or !).
    
    Args:
        line: The line to check
        
    Returns:
        True if the line is a comment
        
    Example:
        >>> is_comment("# This is a comment")
        True
        >>> is_comment("! Another comment style")
        True
        >>> is_comment("||example.com^")
        False
    """
    return bool(COMMENT_PATTERN.match(line))


def is_cosmetic_rule(line: str) -> bool:
    """
    Check if line is a cosmetic/element-hiding rule.
    
    These rules can't be processed by AdGuard Home (DNS-level blocker)
    and should be completely discarded.
    
    Args:
        line: The line to check
        
    Returns:
        True if the line is a cosmetic rule
        
    Example:
        >>> is_cosmetic_rule("example.com##.ad-banner")
        True
        >>> is_cosmetic_rule("||example.com^")
        False
    """
    return bool(COSMETIC_PATTERN.search(line))


def strip_trailing_comment(line: str) -> str:
    """
    Remove trailing inline comments to reduce file size.
    
    Only strips comments that are preceded by whitespace, to avoid
    accidentally stripping URL fragments or modifier values.
    
    Args:
        line: The line to process
        
    Returns:
        Line with trailing comment removed
        
    Example:
        >>> strip_trailing_comment("||example.com^ # block ads")
        '||example.com^'
        >>> strip_trailing_comment("||example.com^#fragment")  # No space, kept
        '||example.com^#fragment'
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
    
    Handles modifiers with values (key=value) and negation (~modifier).
    
    Args:
        rule: The ABP rule to parse
        
    Returns:
        Set of modifier names (lowercase, without ~ prefix or =value suffix)
        
    Example:
        >>> extract_modifiers("||example.com^$script,third-party")
        {'script', 'third-party'}
        >>> extract_modifiers("||example.com^$important")
        {'important'}
        >>> extract_modifiers("||example.com^")
        set()
    """
    match = MODIFIER_PATTERN.search(rule)
    if not match:
        return set()
    
    modifier_string = match.group(1)
    modifiers: set[str] = set()
    
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
    
    Args:
        modifiers: Set of modifier names to check
        
    Returns:
        True if any modifier is unsupported
        
    Example:
        >>> has_unsupported_modifiers({'script', 'important'})
        True  # 'script' is unsupported
        >>> has_unsupported_modifiers({'important', 'client'})
        False  # Both are supported
    """
    return bool(modifiers & UNSUPPORTED_MODIFIERS)


def clean_line(line: str) -> tuple[CleanResult, bool]:
    """
    Clean a single rule line.
    
    Performs all cleaning operations: strip whitespace, remove comments,
    discard cosmetic rules, and check for unsupported modifiers.
    
    Args:
        line: The raw line to clean
        
    Returns:
        Tuple of (CleanResult, was_trimmed):
        - CleanResult: The cleaning result with line/discarded/reason
        - was_trimmed: True if whitespace was removed from the line
        
    Example:
        >>> result, trimmed = clean_line("  ||example.com^  ")
        >>> result.line
        '||example.com^'
        >>> trimmed
        True
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
            # DISCARD entire rule (as per design decision)
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
    
    Processes each line through the cleaning pipeline and collects statistics.
    
    Args:
        lines: List of raw lines to clean
        
    Returns:
        Tuple of (cleaned_lines, stats):
        - cleaned_lines: List of valid, cleaned lines
        - stats: CleanStats with counts of removed line types
        
    Example:
        >>> lines = ["# comment", "||example.com^", "bad.com##.ad"]
        >>> cleaned, stats = clean_lines(lines)
        >>> len(cleaned)
        1
        >>> stats.comments_removed
        1
    """
    cleaned: list[str] = []
    stats: CleanStatsDict = {
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
            cleaned.append(result.line)  # type: ignore[arg-type]
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
    
    Reads the input file, cleans all lines, and writes to output.
    
    Args:
        input_path: Path to input file
        output_path: Path to output file (defaults to in-place modification)
        
    Returns:
        CleanStats with counts of removed line types
        
    Example:
        >>> stats = clean_file("raw.txt", "cleaned.txt")
        >>> print(f"Kept {stats.kept_lines} of {stats.total_lines} lines")
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


# =============================================================================
# CLI INTERFACE
# =============================================================================

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
