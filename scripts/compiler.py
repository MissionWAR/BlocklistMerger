#!/usr/bin/env python3
"""
compiler.py - Blocklist Compiler with Format Compression and Modifier-Aware Deduplication

This module is the core of the blocklist merging pipeline. It takes cleaned rules
from multiple blocklists and produces a minimal, deduplicated output file.

Core Goals (in priority order):
    1. Maximum blocking coverage - Every domain that should be blocked, IS blocked
    2. Minimum rule count - Smaller lists = faster loading, less memory in AdGuard Home
    3. Only output blocking rules - No whitelist/exception rules (@@) in output

Key Insight - Format Compression:
    Instead of handling hosts, plain domains, and ABP rules separately, we CONVERT
    everything to ABP format during parsing::
    
        0.0.0.0 ads.example.com  →  ||ads.example.com^
        ads.example.com          →  ||ads.example.com^
        ||ads.example.com^       →  ||ads.example.com^  (unchanged)
    
    This unification enables subdomain deduplication across ALL input formats:
    If we have ||example.com^, then ||sub.example.com^ becomes redundant regardless
    of whether it came from a hosts file or an ABP list.

Modifier-Aware Pruning:
    Not all subdomain rules can be pruned! AdGuard Home modifiers change behavior:
    
    ============  ================================================================
    Modifier      Behavior
    ============  ================================================================
    $important    Child with $important must NOT be pruned by parent without it
    $badfilter    Never prune by a $badfilter parent (it disables rules, not blocks)
    $dnsrewrite   Never prune (has custom DNS response behavior)
    $denyallow    Never prune (excludes specific domains)
    $dnstype      Only prune if parent blocks ALL types
    $client/$ctag Parent with restrictions can't prune unrestricted child
    ============  ================================================================

Whitelist Handling:
    @@rules (whitelist/exception rules) are used ONLY to remove conflicting blocking
    rules. The @@rules themselves are NOT output. This keeps the output file simple.
"""

import re
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Final

import tldextract

# =============================================================================
# TYPE ALIASES
# =============================================================================
# These make complex type signatures more readable throughout the codebase.

#: A parsed ABP rule entry: (original_rule, modifiers_frozenset, is_wildcard)
RuleEntry = tuple[str, frozenset[str], bool]

#: A TLD wildcard entry: (original_rule, modifiers_frozenset)
WildcardEntry = tuple[str, frozenset[str]]

# =============================================================================
# CONFIGURATION CONSTANTS
# =============================================================================
# Named constants improve readability and make tuning easier.

#: LRU cache size for domain extraction (covers most unique domains in a run)
LRU_CACHE_SIZE: Final[int] = 65536

# Pre-configure tldextract for better performance (no online updates check)
_tld_extract = tldextract.TLDExtract(suffix_list_urls=None)

# =============================================================================
# REGEX PATTERNS
# =============================================================================
# Pre-compiled patterns for performance. Each pattern is documented with
# examples of what it matches.

#: ABP pattern: ||[*.]domain^ (including IP addresses)
#: Examples: ||example.com^, ||*.example.com^, @@||example.com^$important
ABP_DOMAIN_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^(@@)?\|\|"              # Start: || or @@|| (group 1: exception marker)
    r"(\*\.)?"                 # Optional *. wildcard (group 2)
    r"([^^$|*\s]+)"            # Domain/IP (group 3)
    r"\^"                      # Separator
)

#: Hosts format: IP domain [domain2 ...]
#: Examples: 0.0.0.0 example.com, 127.0.0.1 ads.example.com tracking.example.com
HOSTS_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^([\d.:a-fA-F]+)\s+"   # IP address (IPv4 or IPv6)
    r"(.+)$"                 # Rest of line (domains)
)

#: Valid domain/IP for hosts file entries
#: Examples: example.com, sub.example.com, my-domain.co.uk
HOSTS_DOMAIN_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^[a-zA-Z0-9][\w.-]*$"
)

#: Plain domain (simple domain name, no special chars except . and -)
#: Examples: example.com, sub.example.com (NOT: ||example.com^, 0.0.0.0 example.com)
PLAIN_DOMAIN_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)

# =============================================================================
# DOMAIN CONSTANTS
# =============================================================================

#: Local/blocking IPs recognized in hosts format
#: These indicate the entry is meant to block the domain, not redirect it.
BLOCKING_IPS: Final[frozenset[str]] = frozenset({
    "0.0.0.0", "127.0.0.1", "::1", "::0", "::",
    "0:0:0:0:0:0:0:0", "0:0:0:0:0:0:0:1",
})

#: Local hostnames to skip (these appear in hosts files but shouldn't be blocked)
LOCAL_HOSTNAMES: Final[frozenset[str]] = frozenset({
    "localhost", "localhost.localdomain", "local", "broadcasthost",
    "ip6-localhost", "ip6-loopback", "ip6-localnet",
    "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters", "ip6-allhosts",
})

# =============================================================================
# MODIFIER CONSTANTS
# =============================================================================

#: Modifiers with special behavior that should never be pruned.
#: These modifiers have effects that can't be covered by a parent rule.
SPECIAL_BEHAVIOR_MODIFIERS: Final[frozenset[str]] = frozenset({
    "badfilter",   # Disables other rules (meta-modifier)
    "dnsrewrite",  # Custom DNS response (e.g., redirect to specific IP)
    "denyallow",   # Excludes specific domains from blocking
})

#: Modifiers that restrict who is blocked (client-specific rules).
#: A parent with these can't prune a child without them.
CLIENT_RESTRICTION_MODIFIERS: Final[frozenset[str]] = frozenset({
    "client",  # Block only for specific client IP
    "ctag",    # Block only for specific client tag
})


# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass(slots=True)
class CompileStats:
    """
    Statistics from the compilation process.
    
    This dataclass tracks all metrics during rule compilation, 
    providing insight into how many rules were kept, pruned, or transformed.
    
    Attributes:
        total_input: Total number of input lines processed
        total_output: Total number of rules written to output
        abp_kept: ABP-style rules kept in output
        other_kept: Other rules (regex, etc.) kept in output
        abp_subdomain_pruned: Subdomain rules pruned by parent rules
        tld_wildcard_pruned: Rules pruned by TLD wildcards (e.g., ||*.autos^)
        duplicate_pruned: Exact duplicate rules removed
        whitelist_conflict_pruned: Rules removed due to whitelist conflicts
        local_hostname_pruned: Local hostnames (localhost, etc.) skipped
        formats_compressed: Hosts/plain domains converted to ABP format
        malformed_discarded: Malformed rules (e.g., ||^) discarded
    
    Example:
        >>> stats = CompileStats()
        >>> stats.total_input = 1000
        >>> stats.abp_kept = 500
        >>> print(f"Kept {stats.abp_kept} of {stats.total_input}")
        Kept 500 of 1000
    """
    total_input: int = 0
    total_output: int = 0
    
    # By format
    abp_kept: int = 0
    other_kept: int = 0
    
    # Pruning counts
    abp_subdomain_pruned: int = 0
    tld_wildcard_pruned: int = 0
    duplicate_pruned: int = 0
    whitelist_conflict_pruned: int = 0
    local_hostname_pruned: int = 0
    formats_compressed: int = 0
    malformed_discarded: int = 0


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def normalize_domain(domain: str) -> str:
    """
    Normalize a domain to lowercase, stripped of whitespace and trailing dots.
    
    Args:
        domain: The domain string to normalize
        
    Returns:
        Normalized domain string
        
    Example:
        >>> normalize_domain("  Example.COM.  ")
        'example.com'
    """
    return domain.lower().strip().rstrip(".")


def extract_abp_info(rule: str) -> tuple[str | None, frozenset[str], bool, bool]:
    """
    Extract domain, modifiers, exception status, and wildcard status from ABP rule.
    
    Args:
        rule: An ABP-style rule string
        
    Returns:
        A tuple of (domain, modifiers, is_exception, is_wildcard):
        - domain: The extracted domain, or None if parsing failed
        - modifiers: Frozenset of modifier names (lowercase)
        - is_exception: True if this is a whitelist rule (@@)
        - is_wildcard: True if this is a wildcard rule (||*.domain^)
        
    Example:
        >>> extract_abp_info("||example.com^$important")
        ('example.com', frozenset({'important'}), False, False)
        >>> extract_abp_info("@@||*.example.com^")
        ('example.com', frozenset(), True, True)
    """
    match = ABP_DOMAIN_PATTERN.match(rule)
    if not match:
        return None, frozenset(), False, False
    
    # Groups: (1) @@ exception, (2) *. wildcard, (3) domain
    is_exception = match.group(1) is not None
    is_wildcard = match.group(2) is not None
    domain = normalize_domain(match.group(3))
    
    # Extract modifiers from $modifier1,modifier2,...
    modifiers: set[str] = set()
    if "$" in rule:
        mod_part = rule.split("$", 1)[1]
        for mod in mod_part.split(","):
            mod_name = mod.split("=")[0].strip().lower()
            # Handle negation prefix (e.g., ~third-party)
            if mod_name.startswith("~"):
                mod_name = mod_name[1:]
            if mod_name:
                modifiers.add(mod_name)
    
    return domain, frozenset(modifiers), is_exception, is_wildcard


def extract_hosts_info(rule: str) -> tuple[str | None, list[str]]:
    """
    Extract IP and domains from hosts-style rule.
    
    Args:
        rule: A hosts-style rule string (e.g., "0.0.0.0 example.com")
        
    Returns:
        A tuple of (ip, domains):
        - ip: The IP address, or None if not a valid hosts rule
        - domains: List of domain names (may be empty)
        
    Note:
        Only "blocking" IPs (0.0.0.0, 127.0.0.1, etc.) are recognized.
        Real IPs like 8.8.8.8 are ignored as they indicate redirects, not blocks.
        
    Example:
        >>> extract_hosts_info("0.0.0.0 example.com ads.example.com")
        ('0.0.0.0', ['example.com', 'ads.example.com'])
        >>> extract_hosts_info("8.8.8.8 dns.google")  # Real IP, not blocking
        (None, [])
    """
    match = HOSTS_PATTERN.match(rule)
    if not match:
        return None, []
    
    ip = match.group(1)
    rest = match.group(2)
    
    # Only process blocking IPs (0.0.0.0, 127.x.x.x, ::, etc.)
    if ip not in BLOCKING_IPS and not ip.startswith("0.") and not ip.startswith("127."):
        return None, []
    
    domains: list[str] = []
    for part in rest.split():
        # Stop at comments
        if part.startswith("#"):
            break
        if HOSTS_DOMAIN_PATTERN.match(part):
            domain = normalize_domain(part)
            if domain and domain not in LOCAL_HOSTNAMES:
                domains.append(domain)
    
    return ip, domains


@lru_cache(maxsize=LRU_CACHE_SIZE)
def _extract_domain_parts(domain: str) -> tuple[str, str, str]:
    """
    Cached tldextract extraction.
    
    Uses LRU cache to avoid repeated expensive tldextract calls for the same domain.
    
    Args:
        domain: Full domain to parse
        
    Returns:
        Tuple of (subdomain, domain, suffix)
        
    Example:
        >>> _extract_domain_parts("sub.example.co.uk")
        ('sub', 'example', 'co.uk')
    """
    ext = _tld_extract(domain)
    return ext.subdomain, ext.domain, ext.suffix


def get_tld(domain: str) -> str | None:
    """
    Get the TLD (suffix) of a domain.
    
    Args:
        domain: The domain to extract TLD from
        
    Returns:
        The TLD string, or None if not found
        
    Example:
        >>> get_tld("example.com")
        'com'
        >>> get_tld("example.co.uk")
        'co.uk'
    """
    _, _, suffix = _extract_domain_parts(domain)
    return suffix if suffix else None


def get_registered_domain(domain: str) -> str | None:
    """
    Get registered domain (domain.tld) from full domain.
    
    Args:
        domain: Full domain including subdomains
        
    Returns:
        The registered domain (e.g., "example.com"), or None if not found
        
    Example:
        >>> get_registered_domain("sub.example.com")
        'example.com'
        >>> get_registered_domain("deep.sub.example.co.uk")
        'example.co.uk'
    """
    _, dom, suffix = _extract_domain_parts(domain)
    if suffix and dom:
        return f"{dom}.{suffix}"
    return None


@lru_cache(maxsize=LRU_CACHE_SIZE)
def walk_parent_domains(domain: str) -> tuple[str, ...]:
    """
    Walk up the domain hierarchy to find all parent domains.
    
    Args:
        domain: The domain to find parents for
        
    Returns:
        Tuple of parent domains, from most specific to least specific.
        Returns empty tuple for apex domains (no parents).
        
    Note:
        Returns tuple (not list) for hashability, enabling LRU caching.
        
    Example:
        >>> walk_parent_domains("a.b.example.com")
        ('b.example.com', 'example.com')
        >>> walk_parent_domains("example.com")  # Apex domain
        ()
    """
    subdomain, dom, suffix = _extract_domain_parts(domain)
    if not suffix or not dom:
        return ()
    
    registered = f"{dom}.{suffix}"
    
    if not subdomain:
        return ()
    
    parts = subdomain.split(".")
    parents: list[str] = []
    
    # Build parents from most specific to least specific
    for i in range(1, len(parts) + 1):
        if i == len(parts):
            parents.append(registered)
        else:
            suffix_parts = parts[i:]
            parents.append(f"{'.'.join(suffix_parts)}.{registered}")
    
    return tuple(parents)


def should_prune_by_modifiers(child_mods: frozenset[str], parent_mods: frozenset[str]) -> bool:
    """
    Determine if a child rule is redundant given the parent's modifiers.
    
    This function implements the modifier-aware pruning logic that ensures
    we don't incorrectly remove rules with special behavior.
    
    Args:
        child_mods: Modifiers on the child (subdomain) rule
        parent_mods: Modifiers on the parent rule
        
    Returns:
        True if child can be safely pruned (parent covers it), False otherwise
        
    Pruning Rules:
        1. $badfilter parent → Never prune (it disables rules, doesn't block)
        2. $important child → Keep if parent lacks $important
        3. $dnsrewrite/$denyallow/$badfilter child → Never prune (special behavior)
        4. $dnstype mismatch → Child blocking ALL types not covered by parent blocking ONE
        5. $client/$ctag parent → Child without restrictions blocks more broadly
        
    Example:
        >>> should_prune_by_modifiers(frozenset(), frozenset())
        True
        >>> should_prune_by_modifiers(frozenset({'important'}), frozenset())
        False  # Child's $important takes priority
    """
    # $badfilter disables rules, it doesn't block anything
    if "badfilter" in parent_mods:
        return False
    
    # Child's $important overrides non-important parent
    if "important" in child_mods and "important" not in parent_mods:
        return False
    
    # Special behavior modifiers are never redundant
    if child_mods & SPECIAL_BEHAVIOR_MODIFIERS:
        return False
    
    # Handle $dnstype: parent blocking ALL types covers child blocking specific type,
    # but not vice versa (child blocking ALL not covered by parent blocking ONE)
    if "dnstype" in child_mods:
        if "dnstype" in parent_mods:
            return False  # Can't compare values, be conservative
        # else: parent blocks ALL types, covers child's specific type
    elif "dnstype" in parent_mods:
        return False  # Child blocks ALL types, parent only blocks one type
    
    # $client/$ctag restrict WHO is blocked. Unrestricted child is more general.
    if (parent_mods & CLIENT_RESTRICTION_MODIFIERS) and not (child_mods & CLIENT_RESTRICTION_MODIFIERS):
        return False
    
    return True


# =============================================================================
# MAIN COMPILATION
# =============================================================================

def compile_rules(
    lines: list[str],
    output_file: str,
) -> CompileStats:
    """
    Compile and deduplicate rules with format compression.
    
    This is the main entry point for the compiler. It processes input lines through
    multiple phases to produce a minimal, deduplicated output file.
    
    Args:
        lines: List of rule strings to compile
        output_file: Path to write the compiled output
        
    Returns:
        CompileStats with metrics about the compilation process
        
    Pipeline Phases:
        1. **Parse & Compress**: Parse all rules, converting hosts/plain to ABP format
        2. **Build Lookups**: Create efficient lookup structures for pruning
        3. **Prune**: Remove redundant subdomain and whitelist-conflicted rules
        4. **Output**: Write deduplicated rules atomically
        
    Example:
        >>> lines = ["||example.com^", "||sub.example.com^", "0.0.0.0 other.example.com"]
        >>> stats = compile_rules(lines, "output.txt")
        >>> print(f"Reduced {stats.total_input} to {stats.total_output} rules")
        Reduced 3 to 1 rules
    """
    stats = CompileStats()
    
    # =========================================================================
    # PHASE 1: Parse and categorize all rules
    # =========================================================================
    
    # ABP blocking rules: domain -> (original_rule, modifiers, is_wildcard)
    abp_rules: dict[str, RuleEntry] = {}
    abp_wildcards: dict[str, WildcardEntry] = {}  # TLD wildcards: tld -> rule
    
    # Whitelisted domains (from @@rules)
    allow_domains: set[str] = set()
    
    # Other rules (regex, partial matches, etc.)
    other_rules: list[str] = []
    
    for line in lines:
        stats.total_input += 1
        line = line.strip()
        if not line:
            continue
        
        # -----------------------------------------------------------------
        # ABP-style rules (highest priority)
        # -----------------------------------------------------------------
        if line.startswith("||") or line.startswith("@@||"):
            domain, modifiers, is_exception, is_wildcard = extract_abp_info(line)
            
            if not domain:
                # Malformed ABP rule (e.g., ||^ or ||$modifier) - discard
                stats.malformed_discarded += 1
                continue
            
            if is_exception:
                # Track whitelisted domains for conflict removal
                if is_wildcard:
                    # @@||*.example.com^ - covers all subdomains
                    allow_domains.add(f"*.{domain}")
                else:
                    allow_domains.add(domain)
                continue
            
            # Blocking rule
            if is_wildcard:
                # Check if this is a TLD wildcard like ||*.autos^
                tld = get_tld(domain)
                if tld and domain == tld:
                    # This is ||*.tld^ - covers entire TLD
                    if tld not in abp_wildcards:
                        abp_wildcards[tld] = (line, modifiers)
                else:
                    # Regular subdomain wildcard like ||*.example.com^
                    key = f"*.{domain}"
                    if key not in abp_rules:
                        abp_rules[key] = (line, modifiers, True)
            else:
                # Regular ABP rule
                if domain not in abp_rules:
                    abp_rules[domain] = (line, modifiers, False)
                else:
                    # Duplicate - prefer one with $important
                    existing = abp_rules[domain]
                    if "important" in modifiers and "important" not in existing[1]:
                        abp_rules[domain] = (line, modifiers, False)
                    stats.duplicate_pruned += 1
            continue
        
        # Other exception rules (non-ABP format like /regex/)
        if line.startswith("@@"):
            # Can't extract domain from non-ABP exceptions, skip for now
            continue
        
        # -----------------------------------------------------------------
        # Hosts-style rules - COMPRESS TO ABP FORMAT
        # -----------------------------------------------------------------
        ip, domains = extract_hosts_info(line)
        if ip and domains:
            for domain in domains:
                # Skip local hostnames
                if domain in LOCAL_HOSTNAMES:
                    stats.local_hostname_pruned += 1
                    continue
                
                # Convert to ABP format: 0.0.0.0 example.com → ||example.com^
                abp_rule = f"||{domain}^"
                if domain not in abp_rules:
                    abp_rules[domain] = (abp_rule, frozenset(), False)
                    stats.formats_compressed += 1
                else:
                    stats.duplicate_pruned += 1
            continue
        
        # -----------------------------------------------------------------
        # Plain domain - COMPRESS TO ABP FORMAT
        # -----------------------------------------------------------------
        if PLAIN_DOMAIN_PATTERN.match(line):
            domain = normalize_domain(line)
            if domain and domain not in LOCAL_HOSTNAMES:
                # Convert to ABP format: example.com → ||example.com^
                abp_rule = f"||{domain}^"
                if domain not in abp_rules:
                    abp_rules[domain] = (abp_rule, frozenset(), False)
                    stats.formats_compressed += 1
                else:
                    stats.duplicate_pruned += 1
            else:
                stats.local_hostname_pruned += 1
            continue
        
        # -----------------------------------------------------------------
        # Other (regex, etc.)
        # -----------------------------------------------------------------
        if line.startswith("/") or "|" in line or "*" in line:
            other_rules.append(line)
            continue
    
    # =========================================================================
    # PHASE 2: Build coverage lookup sets
    # =========================================================================
    
    # All ABP blocking domains (for subdomain checks)
    # Use set comprehension for efficiency
    abp_blocking_domains: set[str] = {
        domain if not is_wc else domain[2:]  # Remove "*." prefix for wildcards
        for domain, (_, _, is_wc) in abp_rules.items()
    }
    
    # TLD wildcards
    tld_wildcards: set[str] = set(abp_wildcards.keys())
    
    def is_covered_by_abp(domain: str) -> bool:
        """Check if domain is covered by any ABP rule."""
        # Direct match
        if domain in abp_blocking_domains:
            return True
        
        # TLD wildcard check
        tld = get_tld(domain)
        if tld and tld in tld_wildcards:
            return True
        
        # Parent domain check
        for parent in walk_parent_domains(domain):
            if parent in abp_blocking_domains:
                return True
        
        return False
    
    def is_whitelisted(domain: str) -> bool:
        """
        Check if domain is whitelisted.
        
        A domain is whitelisted if:
        1. It's directly in allow_domains (@@||domain^)
        2. Any parent domain is whitelisted (@@||parent^ covers subdomains)
        3. A wildcard whitelist covers it (@@||*.parent^)
        """
        if domain in allow_domains:
            return True
        # Check parent domains and wildcard whitelists
        for parent in walk_parent_domains(domain):
            # @@||parent^ whitelists parent AND all subdomains
            if parent in allow_domains:
                return True
            # @@||*.parent^ whitelists all subdomains of parent
            if f"*.{parent}" in allow_domains:
                return True
        return False
    
    # =========================================================================
    # PHASE 3: Prune ABP subdomain rules
    # =========================================================================
    
    pruned_abp: dict[str, RuleEntry] = {}
    
    for domain, (rule, modifiers, is_wildcard) in abp_rules.items():
        # Skip if whitelisted
        clean_domain = domain[2:] if domain.startswith("*.") else domain
        if is_whitelisted(clean_domain):
            stats.whitelist_conflict_pruned += 1
            continue
        
        # TLD wildcard coverage
        tld = get_tld(clean_domain)
        if tld and tld in tld_wildcards and clean_domain != tld:
            parent_mods = abp_wildcards[tld][1]
            if should_prune_by_modifiers(modifiers, parent_mods):
                stats.tld_wildcard_pruned += 1
                continue
        
        # Check if any parent domain blocks this
        should_prune = False
        
        # For wildcard rules (||*.example.com^), check if exact domain rule exists
        # ||example.com^ covers ||*.example.com^ because it blocks domain AND all subdomains
        if is_wildcard and clean_domain in abp_rules:
            parent_mods = abp_rules[clean_domain][1]
            if should_prune_by_modifiers(modifiers, parent_mods):
                should_prune = True
        
        # Check parent domains (for both regular and wildcard rules)
        if not should_prune:
            for parent in walk_parent_domains(clean_domain):
                # Check exact parent rule
                if parent in abp_rules:
                    parent_mods = abp_rules[parent][1]
                    if should_prune_by_modifiers(modifiers, parent_mods):
                        should_prune = True
                        break
                
                # Check wildcard parent rule (||*.parent^ covers ||sub.parent^)
                wildcard_key = f"*.{parent}"
                if wildcard_key in abp_rules:
                    parent_mods = abp_rules[wildcard_key][1]
                    if should_prune_by_modifiers(modifiers, parent_mods):
                        should_prune = True
                        break
        
        if should_prune:
            stats.abp_subdomain_pruned += 1
        else:
            pruned_abp[domain] = (rule, modifiers, is_wildcard)
    
    # =========================================================================
    # PHASE 4: Deduplicate other rules (regex, partial matches, etc.)
    # =========================================================================
    
    seen_other: set[str] = set()
    kept_other: list[str] = []
    for rule in other_rules:
        if rule not in seen_other:
            seen_other.add(rule)
            kept_other.append(rule)
        else:
            stats.duplicate_pruned += 1
    
    # NOTE: Whitelist/exception rules (@@) are intentionally NOT output.
    # They were only used internally to remove conflicting blocking rules.
    # The final output contains only blocking rules.
    
    # =========================================================================
    # OUTPUT (atomic write to prevent corruption on crash)
    # =========================================================================
    
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Write to temp file first, then atomically rename
    temp_path = output_path.with_suffix(".tmp")
    
    with open(temp_path, "w", encoding="utf-8", newline="\n") as f:
        # TLD wildcards (check whitelist before writing)
        for tld, (rule, mods) in abp_wildcards.items():
            if tld not in allow_domains and f"*.{tld}" not in allow_domains:
                f.write(rule + "\n")
                stats.abp_kept += 1
            else:
                stats.whitelist_conflict_pruned += 1
        
        # ABP rules (already whitelist-checked during pruning)
        for domain, (rule, mods, is_wc) in pruned_abp.items():
            f.write(rule + "\n")
            stats.abp_kept += 1
        
        # Other rules (regex, partial matches, etc.)
        for rule in kept_other:
            f.write(rule + "\n")
            stats.other_kept += 1
    
    # Atomic rename (prevents partial file on crash)
    temp_path.replace(output_path)
    
    stats.total_output = stats.abp_kept + stats.other_kept
    
    return stats


# =============================================================================
# CLI INTERFACE
# =============================================================================

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python -m scripts.compiler <input_file> <output_file>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    # Read input
    with open(input_file, encoding="utf-8-sig", errors="replace") as f:
        lines = f.readlines()
    
    stats = compile_rules(lines, output_file)
    
    print(f"\nCompilation complete:")
    print(f"  Input:  {stats.total_input:,} rules")
    print(f"  Output: {stats.total_output:,} rules")
    print(f"  Reduction: {(1 - stats.total_output / max(stats.total_input, 1)) * 100:.1f}%")
    print(f"\nBy type:")
    print(f"  ABP rules:   {stats.abp_kept:,} (incl. {stats.formats_compressed:,} compressed from hosts/plain)")
    print(f"  Other rules: {stats.other_kept:,}")
    print(f"\nPruned:")
    print(f"  ABP subdomains:     {stats.abp_subdomain_pruned:,}")
    print(f"  TLD wildcards:      {stats.tld_wildcard_pruned:,}")
    print(f"  Duplicates:         {stats.duplicate_pruned:,}")
    print(f"  Whitelist conflicts: {stats.whitelist_conflict_pruned:,}")
    print(f"  Local hostnames:    {stats.local_hostname_pruned:,}")
