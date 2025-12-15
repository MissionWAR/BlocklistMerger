#!/usr/bin/env python3
"""
compiler.py

Modifier-aware deduplication and cross-format optimization for AdGuard Home.

Key features:
- ABP format prioritization (broader coverage)
- Subdomain pruning (||example.com^ covers *.example.com)
- Modifier-aware pruning (respects $important, $client, $denyallow)
- Logging of "kept for caution" rules for safety review
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import tldextract


# ============================================================================
# CONFIGURATION
# ============================================================================

# Enable verbose logging of cautious prunes
VERBOSE_LOGGING = True


# ============================================================================
# REGEX PATTERNS
# ============================================================================

# ABP domain pattern: ||domain^ or ||*.domain^
ABP_DOMAIN_PATTERN = re.compile(
    r"^@@?\|\|"           # Start with || or @@||
    r"(\*\.)?([^\^$|*]+)"  # Optional *. then domain
    r"\^"                  # Separator
)

# Hosts format: IP domain [domain2 ...]
HOSTS_PATTERN = re.compile(
    r"^([\d.:a-fA-F]+)\s+"  # IP address (IPv4 or IPv6)
    r"([a-zA-Z0-9][\w.-]+)"  # First domain
)

# Plain domain (simple domain name, no special chars except . and -)
PLAIN_DOMAIN_PATTERN = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"  # First label
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"  # More labels
)

# Local addresses to ignore in hosts format
LOCAL_IPS = frozenset({
    "0.0.0.0", "127.0.0.1", "::1", "::0", "0:0:0:0:0:0:0:0", "0:0:0:0:0:0:0:1",
})

# Local hostnames to ignore
LOCAL_HOSTNAMES = frozenset({
    "localhost", "localhost.localdomain", "local", "broadcasthost",
    "ip6-localhost", "ip6-loopback", "ip6-localnet",
})


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class ParsedRule:
    """Parsed representation of a blocking rule."""
    original: str              # Original rule text
    domain: str                # Normalized domain (lowercase)
    rule_type: str             # "abp", "abp_wildcard", "hosts", "plain", "other"
    is_exception: bool         # @@rules
    modifiers: frozenset       # Set of modifiers (for ABP rules)
    
    def __hash__(self):
        return hash(self.original)


@dataclass
class CompileState:
    """State during compilation."""
    abp_rules: dict[str, ParsedRule] = field(default_factory=dict)    # domain -> rule
    abp_wildcards: dict[str, ParsedRule] = field(default_factory=dict)  # domain -> rule
    hosts_rules: dict[str, ParsedRule] = field(default_factory=dict)  # domain -> rule
    plain_rules: dict[str, ParsedRule] = field(default_factory=dict)  # domain -> rule
    allow_rules: list[str] = field(default_factory=list)              # @@rules kept intact
    other_rules: list[str] = field(default_factory=list)              # regex, etc.
    
    # Logging for safety review
    pruned_rules: list[tuple[str, str]] = field(default_factory=list)  # (rule, reason)
    kept_cautious: list[tuple[str, str]] = field(default_factory=list)  # (rule, reason)


@dataclass
class CompileStats:
    """Statistics from compilation."""
    total_input: int = 0
    total_output: int = 0
    abp_kept: int = 0
    hosts_kept: int = 0
    plain_kept: int = 0
    allow_kept: int = 0
    other_kept: int = 0
    
    # Pruning stats
    subdomain_pruned: int = 0
    cross_format_pruned: int = 0
    duplicate_pruned: int = 0
    
    # Cautious keeps
    cautious_kept: int = 0


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def normalize_domain(domain: str) -> str:
    """Normalize domain to lowercase, stripped."""
    return domain.lower().strip().rstrip(".")


def extract_abp_info(rule: str) -> tuple[str | None, frozenset, bool]:
    """
    Extract domain, modifiers, and exception status from ABP rule.
    
    Returns:
        (domain, modifiers, is_exception) or (None, frozenset(), False) if not ABP
    """
    is_exception = rule.startswith("@@")
    
    match = ABP_DOMAIN_PATTERN.match(rule)
    if not match:
        return None, frozenset(), is_exception
    
    is_wildcard = match.group(1) is not None  # Has *.
    domain = normalize_domain(match.group(2))
    
    # Extract modifiers
    modifiers = set()
    if "$" in rule:
        mod_part = rule.split("$", 1)[1]
        for mod in mod_part.split(","):
            mod_name = mod.split("=")[0].strip().lower()
            if mod_name.startswith("~"):
                mod_name = mod_name[1:]
            if mod_name:
                modifiers.add(mod_name)
    
    if is_wildcard:
        # For wildcard rules, prepend *. to domain for tracking
        domain = f"*.{domain}"
    
    return domain, frozenset(modifiers), is_exception


def extract_hosts_domains(rule: str) -> list[str]:
    """
    Extract domains from hosts-style rule.
    
    Example: "0.0.0.0 example.com ad.example.com" -> ["example.com", "ad.example.com"]
    """
    match = HOSTS_PATTERN.match(rule)
    if not match:
        return []
    
    ip = match.group(1)
    # Only process blocking IPs (0.0.0.0, 127.0.0.1, etc.)
    if ip not in LOCAL_IPS and not ip.startswith("0.") and not ip.startswith("127."):
        # Non-blocking IP (like real DNS rewrites), skip
        return []
    
    # Extract all domains after the IP
    parts = rule.split()
    domains = []
    for part in parts[1:]:
        # Stop at comments
        if part.startswith("#"):
            break
        domain = normalize_domain(part)
        if domain and domain not in LOCAL_HOSTNAMES:
            domains.append(domain)
    
    return domains


def is_plain_domain(rule: str) -> bool:
    """Check if rule is a plain domain (no special syntax)."""
    return bool(PLAIN_DOMAIN_PATTERN.match(rule))


def get_parent_domain(domain: str) -> str | None:
    """
    Get parent domain.
    
    Example: "sub.example.com" -> "example.com"
    
    Uses tldextract to avoid cutting into TLD.
    """
    # Handle wildcard format
    if domain.startswith("*."):
        domain = domain[2:]
    
    ext = tldextract.extract(domain)
    if not ext.suffix or not ext.domain:
        return None
    
    # If there's a subdomain, remove one level
    if ext.subdomain:
        parts = ext.subdomain.split(".")
        if len(parts) > 1:
            new_subdomain = ".".join(parts[1:])
            return f"{new_subdomain}.{ext.domain}.{ext.suffix}"
        else:
            return f"{ext.domain}.{ext.suffix}"
    
    return None


def walk_parents(domain: str) -> list[str]:
    """Walk up the domain tree to find all parent domains."""
    parents = []
    current = domain
    
    # Handle wildcard format
    if current.startswith("*."):
        current = current[2:]
    
    while True:
        parent = get_parent_domain(current)
        if not parent:
            break
        parents.append(parent)
        current = parent
    
    return parents


# ============================================================================
# PRUNING LOGIC
# ============================================================================

def should_prune_abp(
    child: ParsedRule,
    parent: ParsedRule,
    state: CompileState,
) -> tuple[bool, str]:
    """
    Determine if child ABP rule is redundant given parent ABP rule.
    
    Returns:
        (should_prune, reason)
    
    SAFETY PRINCIPLE: When in doubt, KEEP the rule.
    False positives (keeping redundant rules) waste RAM but work.
    False negatives (removing necessary rules) break blocking.
    """
    # NEVER prune exception rules
    if child.is_exception:
        return False, "exception_rule"
    
    # NEVER prune if child has $badfilter
    if "badfilter" in child.modifiers:
        return False, "has_badfilter"
    
    # NEVER prune if child has $dnsrewrite (specific behavior)
    if "dnsrewrite" in child.modifiers:
        return False, "has_dnsrewrite"
    
    # Parent must be a blocking rule (not exception)
    if parent.is_exception:
        return False, "parent_is_exception"
    
    # -------------------------------------------------------------------------
    # $important handling
    # If child has $important but parent doesn't, child takes priority
    # Example: Parent: ||example.com^  Child: ||sub.example.com^$important
    # Child MUST be kept because $important overrides parent's block
    # -------------------------------------------------------------------------
    child_important = "important" in child.modifiers
    parent_important = "important" in parent.modifiers
    
    if child_important and not parent_important:
        if VERBOSE_LOGGING:
            state.kept_cautious.append((child.original, "child_has_important"))
        return False, "child_has_important"
    
    # -------------------------------------------------------------------------
    # $denyallow handling
    # If child has $denyallow, it's more specific, keep it
    # -------------------------------------------------------------------------
    if "denyallow" in child.modifiers:
        if VERBOSE_LOGGING:
            state.kept_cautious.append((child.original, "child_has_denyallow"))
        return False, "child_has_denyallow"
    
    # -------------------------------------------------------------------------
    # $client handling (commented out per user request - public lists don't use)
    # -------------------------------------------------------------------------
    # child_client = [m for m in child.modifiers if m.startswith("client")]
    # parent_client = [m for m in parent.modifiers if m.startswith("client")]
    # if child_client != parent_client:
    #     return False, "different_client_scope"
    
    # -------------------------------------------------------------------------
    # General modifier comparison
    # Parent should be AT LEAST as restrictive as child
    # If child has modifiers that parent lacks, child is more specific
    # -------------------------------------------------------------------------
    child_mods = child.modifiers - {"important", "badfilter", "dnsrewrite"}
    parent_mods = parent.modifiers - {"important", "badfilter", "dnsrewrite"}
    
    if child_mods and not child_mods.issubset(parent_mods):
        if VERBOSE_LOGGING:
            state.kept_cautious.append((child.original, f"child_more_specific: {child_mods - parent_mods}"))
        return False, "child_more_specific"
    
    # All checks passed - safe to prune
    return True, "covered_by_parent"


def is_covered_by_abp(domain: str, state: CompileState) -> bool:
    """
    Check if a domain is covered by an existing ABP rule.
    
    Coverage logic:
    - ||example.com^ covers example.com AND all subdomains
    - ||*.example.com^ covers subdomains but NOT example.com itself
    """
    # Check direct match
    if domain in state.abp_rules:
        return True
    
    # Check if any parent domain has an ABP rule
    for parent in walk_parents(domain):
        if parent in state.abp_rules:
            return True
        # Wildcard match (*.example.com covers sub.example.com but not example.com)
        wildcard_key = f"*.{parent}"
        if wildcard_key in state.abp_wildcards:
            return True
    
    return False


# ============================================================================
# MAIN COMPILATION
# ============================================================================

def parse_rule(line: str) -> ParsedRule | None:
    """Parse a single rule line into ParsedRule."""
    line = line.strip()
    if not line:
        return None
    
    # ABP-style rule
    if line.startswith("||") or line.startswith("@@||"):
        domain, modifiers, is_exception = extract_abp_info(line)
        if domain:
            rule_type = "abp_wildcard" if domain.startswith("*.") else "abp"
            return ParsedRule(
                original=line,
                domain=domain,
                rule_type=rule_type,
                is_exception=is_exception,
                modifiers=modifiers,
            )
    
    # Exception rule (non-ABP format)
    if line.startswith("@@"):
        return ParsedRule(
            original=line,
            domain="",
            rule_type="other",
            is_exception=True,
            modifiers=frozenset(),
        )
    
    # Hosts-style rule
    domains = extract_hosts_domains(line)
    if domains:
        # Return a rule for the first domain (hosts rules can have multiple)
        return ParsedRule(
            original=line,
            domain=domains[0],
            rule_type="hosts",
            is_exception=False,
            modifiers=frozenset(),
        )
    
    # Plain domain
    if is_plain_domain(line):
        return ParsedRule(
            original=line,
            domain=normalize_domain(line),
            rule_type="plain",
            is_exception=False,
            modifiers=frozenset(),
        )
    
    # Regex or other rule
    if line.startswith("/") or "|" in line or "*" in line:
        return ParsedRule(
            original=line,
            domain="",
            rule_type="other",
            is_exception=False,
            modifiers=frozenset(),
        )
    
    return None


def compile_rules(lines: list[str]) -> tuple[list[str], CompileStats]:
    """
    Compile and deduplicate rules.
    
    Returns:
        (output_rules, stats)
    """
    state = CompileState()
    stats = CompileStats()
    
    # -------------------------------------------------------------------------
    # Pass 1: Parse all rules and categorize
    # -------------------------------------------------------------------------
    parsed_rules: list[ParsedRule] = []
    for line in lines:
        stats.total_input += 1
        rule = parse_rule(line)
        if rule:
            parsed_rules.append(rule)
    
    # -------------------------------------------------------------------------
    # Pass 2: Process exception rules first (never pruned, used for whitelist)
    # -------------------------------------------------------------------------
    for rule in parsed_rules:
        if rule.is_exception:
            state.allow_rules.append(rule.original)
            stats.allow_kept += 1
    
    # -------------------------------------------------------------------------
    # Pass 3: Process ABP rules (highest priority, broadest coverage)
    # -------------------------------------------------------------------------
    for rule in parsed_rules:
        if rule.rule_type == "abp" and not rule.is_exception:
            domain = rule.domain
            
            # Check for duplicates
            if domain in state.abp_rules:
                existing = state.abp_rules[domain]
                # Keep the one with more restrictive modifiers
                if "important" in rule.modifiers and "important" not in existing.modifiers:
                    state.abp_rules[domain] = rule
                stats.duplicate_pruned += 1
                continue
            
            # Check if subdomain is covered by parent
            should_prune = False
            prune_reason = ""
            
            for parent in walk_parents(domain):
                if parent in state.abp_rules:
                    parent_rule = state.abp_rules[parent]
                    should_prune, prune_reason = should_prune_abp(rule, parent_rule, state)
                    if should_prune:
                        break
            
            if should_prune:
                stats.subdomain_pruned += 1
                state.pruned_rules.append((rule.original, prune_reason))
            else:
                state.abp_rules[domain] = rule
        
        elif rule.rule_type == "abp_wildcard" and not rule.is_exception:
            domain = rule.domain
            
            if domain in state.abp_wildcards:
                stats.duplicate_pruned += 1
                continue
            
            # Check if parent apex rule exists (||example.com^ covers *.example.com)
            apex = domain[2:]  # Remove *.
            if apex in state.abp_rules:
                stats.subdomain_pruned += 1
                state.pruned_rules.append((rule.original, "wildcard_covered_by_apex"))
            else:
                state.abp_wildcards[domain] = rule
    
    # -------------------------------------------------------------------------
    # Pass 4: Process hosts rules (lower priority than ABP)
    # -------------------------------------------------------------------------
    for rule in parsed_rules:
        if rule.rule_type == "hosts":
            domain = rule.domain
            
            # Skip if covered by ABP
            if is_covered_by_abp(domain, state):
                stats.cross_format_pruned += 1
                state.pruned_rules.append((rule.original, "covered_by_abp"))
                continue
            
            # Skip duplicates
            if domain in state.hosts_rules:
                stats.duplicate_pruned += 1
                continue
            
            state.hosts_rules[domain] = rule
    
    # -------------------------------------------------------------------------
    # Pass 5: Process plain domains (lowest priority)
    # -------------------------------------------------------------------------
    for rule in parsed_rules:
        if rule.rule_type == "plain":
            domain = rule.domain
            
            # Skip if covered by ABP
            if is_covered_by_abp(domain, state):
                stats.cross_format_pruned += 1
                state.pruned_rules.append((rule.original, "covered_by_abp"))
                continue
            
            # Skip if same domain in hosts
            if domain in state.hosts_rules:
                stats.duplicate_pruned += 1
                continue
            
            # Skip duplicates
            if domain in state.plain_rules:
                stats.duplicate_pruned += 1
                continue
            
            state.plain_rules[domain] = rule
    
    # -------------------------------------------------------------------------
    # Pass 6: Process other rules (regex, etc.)
    # -------------------------------------------------------------------------
    seen_other: set[str] = set()
    for rule in parsed_rules:
        if rule.rule_type == "other" and not rule.is_exception:
            if rule.original not in seen_other:
                seen_other.add(rule.original)
                state.other_rules.append(rule.original)
    
    # -------------------------------------------------------------------------
    # Build output
    # -------------------------------------------------------------------------
    output: list[str] = []
    
    # Add allow rules first
    output.extend(state.allow_rules)
    
    # Add ABP rules
    for rule in state.abp_rules.values():
        output.append(rule.original)
        stats.abp_kept += 1
    
    for rule in state.abp_wildcards.values():
        output.append(rule.original)
        stats.abp_kept += 1
    
    # Add hosts rules
    for rule in state.hosts_rules.values():
        output.append(rule.original)
        stats.hosts_kept += 1
    
    # Add plain rules
    for rule in state.plain_rules.values():
        output.append(rule.original)
        stats.plain_kept += 1
    
    # Add other rules
    output.extend(state.other_rules)
    stats.other_kept = len(state.other_rules)
    
    stats.total_output = len(output)
    stats.cautious_kept = len(state.kept_cautious)
    
    # -------------------------------------------------------------------------
    # Log cautious keeps if verbose
    # -------------------------------------------------------------------------
    if VERBOSE_LOGGING and state.kept_cautious:
        print(f"\n[KEEP-CAUTION] {len(state.kept_cautious)} rules kept for safety:")
        for rule, reason in state.kept_cautious[:20]:  # Show first 20
            print(f"  {rule[:60]}... - {reason}")
        if len(state.kept_cautious) > 20:
            print(f"  ... and {len(state.kept_cautious) - 20} more")
    
    return output, stats


def compile_files(input_dir: str, output_file: str) -> CompileStats:
    """
    Compile all files in input directory.
    
    Args:
        input_dir: Directory containing cleaned rule files
        output_file: Output file path
    
    Returns:
        CompileStats
    """
    from scripts.cleaner import clean_line
    
    input_path = Path(input_dir)
    output_path = Path(output_file)
    
    if not input_path.is_dir():
        raise FileNotFoundError(f"Input directory not found: {input_dir}")
    
    # Collect all lines from all files
    all_lines: list[str] = []
    
    for file in sorted(input_path.glob("*.txt")):
        with open(file, encoding="utf-8-sig", errors="replace") as f:
            for line in f:
                # Clean each line
                result = clean_line(line)
                if not result.discarded and result.line:
                    all_lines.append(result.line)
    
    # Compile
    output_rules, stats = compile_rules(all_lines)
    
    # Write output
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8", newline="\n") as f:
        for rule in output_rules:
            f.write(rule + "\n")
    
    return stats


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python -m scripts.compiler <input_dir> <output_file>")
        sys.exit(1)
    
    input_dir = sys.argv[1]
    output_file = sys.argv[2]
    
    stats = compile_files(input_dir, output_file)
    
    print(f"\nCompilation complete:")
    print(f"  Input:  {stats.total_input} rules")
    print(f"  Output: {stats.total_output} rules")
    print(f"  Reduction: {(1 - stats.total_output / max(stats.total_input, 1)) * 100:.1f}%")
    print(f"\nBreakdown:")
    print(f"  ABP rules:   {stats.abp_kept}")
    print(f"  Hosts rules: {stats.hosts_kept}")
    print(f"  Plain rules: {stats.plain_kept}")
    print(f"  Allow rules: {stats.allow_kept}")
    print(f"  Other rules: {stats.other_kept}")
    print(f"\nPruning:")
    print(f"  Subdomain pruned:    {stats.subdomain_pruned}")
    print(f"  Cross-format pruned: {stats.cross_format_pruned}")
    print(f"  Duplicates:          {stats.duplicate_pruned}")
    print(f"  Cautious keeps:      {stats.cautious_kept}")
