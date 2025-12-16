#!/usr/bin/env python3
"""
compiler.py

Modifier-aware deduplication and cross-format optimization for AdGuard Home.

Key features:
- Two-phase ABP processing (collect all, then prune)
- TLD wildcard pruning (||*.tld^ covers all domains in that TLD)
- Cross-format optimization (ABP > hosts > plain)
- Hosts multi-domain splitting (remove only covered domains)
- Whitelist extraction to separate file
- Modifier-aware pruning (respects $important, $denyallow)
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import tldextract

# Pre-configure tldextract for better performance (no updates check)
_tld_extract = tldextract.TLDExtract(suffix_list_urls=None)

# ============================================================================
# CONFIGURATION
# ============================================================================

VERBOSE_LOGGING = False  # Set True for detailed prune logging

# ============================================================================
# REGEX PATTERNS
# ============================================================================

# ABP domain pattern: ||domain^ or ||*.domain^
# Also matches IP addresses like ||100.48.203.212^
ABP_DOMAIN_PATTERN = re.compile(
    r"^(@@)?\|\|"              # Start with || or @@||  (capture @@ for exception check)
    r"(\*\.)?"                 # Optional *. for wildcard
    r"([^^\$|*\s]+)"           # Domain/IP (anything except ^$|* or whitespace)
    r"\^"                      # Separator
)

# Hosts format: IP domain [domain2 ...]
HOSTS_PATTERN = re.compile(
    r"^([\d.:a-fA-F]+)\s+"   # IP address (IPv4 or IPv6)
    r"(.+)$"                 # Rest of line (domains)
)

# Valid domain/IP for hosts
HOSTS_DOMAIN_PATTERN = re.compile(r"^[a-zA-Z0-9][\w.-]*$")

# Plain domain (simple domain name, no special chars except . and -)
PLAIN_DOMAIN_PATTERN = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)

# Local/blocking IPs in hosts format
BLOCKING_IPS = frozenset({
    "0.0.0.0", "127.0.0.1", "::1", "::0", "::","0:0:0:0:0:0:0:0", "0:0:0:0:0:0:0:1",
})

# Local hostnames to skip
LOCAL_HOSTNAMES = frozenset({
    "localhost", "localhost.localdomain", "local", "broadcasthost",
    "ip6-localhost", "ip6-loopback", "ip6-localnet",
    "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters", "ip6-allhosts",
})


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class CompileStats:
    """Statistics from compilation."""
    total_input: int = 0
    total_output: int = 0
    
    # By format
    abp_kept: int = 0
    hosts_kept: int = 0
    plain_kept: int = 0
    allow_kept: int = 0
    other_kept: int = 0
    
    # Pruning
    abp_subdomain_pruned: int = 0
    tld_wildcard_pruned: int = 0
    cross_format_pruned: int = 0
    duplicate_pruned: int = 0
    whitelist_conflict_pruned: int = 0
    local_hostname_pruned: int = 0
    hosts_compressed: int = 0  # Hosts rules converted to ABP format


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def normalize_domain(domain: str) -> str:
    """Normalize domain to lowercase, stripped."""
    return domain.lower().strip().rstrip(".")


def extract_abp_info(rule: str) -> tuple[str | None, frozenset, bool, bool]:
    """
    Extract domain, modifiers, exception status, and wildcard status from ABP rule.
    
    Returns:
        (domain, modifiers, is_exception, is_wildcard)
    """
    match = ABP_DOMAIN_PATTERN.match(rule)
    if not match:
        return None, frozenset(), False, False
    
    # Group 1: @@ (exception marker), Group 2: *. (wildcard), Group 3: domain
    is_exception = match.group(1) is not None
    is_wildcard = match.group(2) is not None
    domain = normalize_domain(match.group(3))
    
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
    
    return domain, frozenset(modifiers), is_exception, is_wildcard


def extract_hosts_info(rule: str) -> tuple[str | None, list[str]]:
    """
    Extract IP and domains from hosts-style rule.
    
    Returns:
        (ip, [domains]) or (None, []) if not valid hosts
    """
    match = HOSTS_PATTERN.match(rule)
    if not match:
        return None, []
    
    ip = match.group(1)
    rest = match.group(2)
    
    # Only process blocking IPs
    if ip not in BLOCKING_IPS and not ip.startswith("0.") and not ip.startswith("127."):
        return None, []
    
    domains = []
    for part in rest.split():
        # Stop at comments
        if part.startswith("#"):
            break
        if HOSTS_DOMAIN_PATTERN.match(part):
            domain = normalize_domain(part)
            if domain and domain not in LOCAL_HOSTNAMES:
                domains.append(domain)
    
    return ip, domains


@lru_cache(maxsize=65536)
def _extract_domain_parts(domain: str) -> tuple[str, str, str]:
    """Cached tldextract extraction. Returns (subdomain, domain, suffix)."""
    ext = _tld_extract(domain)
    return ext.subdomain, ext.domain, ext.suffix


def get_tld(domain: str) -> str | None:
    """Get the TLD (suffix) of a domain."""
    _, _, suffix = _extract_domain_parts(domain)
    return suffix if suffix else None


def get_registered_domain(domain: str) -> str | None:
    """Get registered domain (domain.tld) from full domain."""
    _, dom, suffix = _extract_domain_parts(domain)
    if suffix and dom:
        return f"{dom}.{suffix}"
    return None


@lru_cache(maxsize=65536)
def walk_parent_domains(domain: str) -> tuple[str, ...]:
    """
    Walk up the domain hierarchy to find all parent domains.
    
    Example: "a.b.example.com" -> ("b.example.com", "example.com")
    
    Returns tuple for hashability (caching).
    """
    subdomain, dom, suffix = _extract_domain_parts(domain)
    if not suffix or not dom:
        return ()
    
    registered = f"{dom}.{suffix}"
    
    if not subdomain:
        return ()
    
    parts = subdomain.split(".")
    parents = []
    # Build parents from most specific to least
    for i in range(1, len(parts) + 1):
        if i == len(parts):
            parents.append(registered)
        else:
            suffix_parts = parts[i:]
            parents.append(f"{'.'.join(suffix_parts)}.{registered}")
    
    return tuple(parents)


def should_prune_by_modifiers(child_mods: frozenset, parent_mods: frozenset) -> bool:
    """
    Check if child rule can be pruned given parent's modifiers.
    
    Returns True if child is redundant (can be pruned).
    
    AGH Supported modifiers:
    - $important: increases priority
    - $badfilter: disables matching rules
    - $dnsrewrite: rewrites DNS responses
    - $denyallow: excludes domains from blocking
    - $dnstype: filters by DNS record type (A, AAAA, CNAME, etc.)
    - $client: client-specific (not in public lists)
    - $ctag: client tags (not in public lists)
    """
    # Never prune if child has $important but parent doesn't
    # Child's $important makes it take priority over parent
    if "important" in child_mods and "important" not in parent_mods:
        return False
    
    # Never prune if child has behavior-modifying modifiers
    # These rules have specific behaviors that parent can't cover
    if child_mods & {"badfilter", "dnsrewrite", "denyallow"}:
        return False
    
    # Never prune if child has $dnstype (unless parent has same dnstype)
    # Because ||example.com^$dnstype=A only blocks A records,
    # it doesn't cover ||sub.example.com^$dnstype=AAAA
    if "dnstype" in child_mods:
        # If parent also has dnstype, we'd need to compare values
        # For safety, if either has dnstype, don't prune unless both lack it
        # (We don't have the values here, so be conservative)
        if "dnstype" not in parent_mods:
            # Parent blocks ALL types, child blocks specific type
            # Parent DOES cover child, so pruning is OK
            pass
        else:
            # Both have dnstype - can't tell if same value, be safe
            return False
    
    # If parent has $dnstype but child doesn't:
    # Parent blocks only specific type, child blocks ALL types
    # Child is MORE restrictive, should NOT be pruned
    if "dnstype" in parent_mods and "dnstype" not in child_mods:
        return False
    
    # For other modifiers, child must not have modifiers parent lacks
    # This ensures child isn't more specific than parent
    excluded = {"important", "badfilter", "dnsrewrite", "denyallow", "dnstype"}
    child_relevant = child_mods - excluded
    parent_relevant = parent_mods - excluded
    
    if child_relevant and not child_relevant.issubset(parent_relevant):
        return False
    
    return True


# ============================================================================
# MAIN COMPILATION
# ============================================================================

def compile_rules(
    lines: list[str],
    output_file: str,
    whitelist_file: str | None = None,
) -> CompileStats:
    """
    Compile and deduplicate rules with two-phase approach.
    
    Phase 1: Collect all rules and build lookup structures
    Phase 2: Filter and deduplicate
    """
    stats = CompileStats()
    
    # =========================================================================
    # PHASE 1: Parse and categorize all rules
    # =========================================================================
    
    # ABP blocking rules: domain -> (original_rule, modifiers, is_wildcard)
    abp_rules: dict[str, tuple[str, frozenset, bool]] = {}
    abp_wildcards: dict[str, tuple[str, frozenset]] = {}  # TLD wildcards: tld -> rule
    
    # Exception rules
    allow_rules: list[str] = []
    allow_domains: set[str] = set()  # Domains covered by @@rules
    
    # Other rules (regex, partial matches, etc.)
    other_rules: list[str] = []
    
    for line in lines:
        stats.total_input += 1
        line = line.strip()
        if not line:
            continue
        
        # =====================================================================
        # ABP-style rules (highest priority)
        # =====================================================================
        if line.startswith("||") or line.startswith("@@||"):
            domain, modifiers, is_exception, is_wildcard = extract_abp_info(line)
            
            if not domain:
                other_rules.append(line)
                continue
            
            if is_exception:
                allow_rules.append(line)
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
        
        # Other exception rules
        if line.startswith("@@"):
            allow_rules.append(line)
            continue
        
        # =====================================================================
        # Hosts-style rules - COMPRESS TO ABP FORMAT
        # =====================================================================
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
                    stats.hosts_compressed += 1
                else:
                    stats.duplicate_pruned += 1
            continue
        
        # =====================================================================
        # Plain domain - COMPRESS TO ABP FORMAT
        # =====================================================================
        if PLAIN_DOMAIN_PATTERN.match(line):
            domain = normalize_domain(line)
            if domain and domain not in LOCAL_HOSTNAMES:
                # Convert to ABP format: example.com → ||example.com^
                abp_rule = f"||{domain}^"
                if domain not in abp_rules:
                    abp_rules[domain] = (abp_rule, frozenset(), False)
                    stats.hosts_compressed += 1  # Reusing stat for both hosts and plain
                else:
                    stats.duplicate_pruned += 1
            else:
                stats.local_hostname_pruned += 1
            continue
        
        # =====================================================================
        # Other (regex, etc.)
        # =====================================================================
        if line.startswith("/") or "|" in line or "*" in line:
            other_rules.append(line)
            continue
    
    # =========================================================================
    # PHASE 2: Build coverage lookup sets
    # =========================================================================
    
    # All ABP blocking domains (for subdomain checks)
    abp_blocking_domains: set[str] = set()
    for domain, (rule, mods, is_wc) in abp_rules.items():
        if not is_wc:  # Don't add wildcard keys like "*.example.com"
            abp_blocking_domains.add(domain)
        else:
            # For wildcards, add the base domain for coverage checking
            abp_blocking_domains.add(domain[2:])  # Remove "*."
    
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
        """Check if domain is whitelisted."""
        if domain in allow_domains:
            return True
        # Check wildcard whitelists
        for parent in walk_parent_domains(domain):
            if f"*.{parent}" in allow_domains:
                return True
        return False
    
    # =========================================================================
    # PHASE 3: Prune ABP subdomain rules
    # =========================================================================
    
    pruned_abp: dict[str, tuple[str, frozenset, bool]] = {}
    
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
        for parent in walk_parent_domains(clean_domain):
            if parent in abp_blocking_domains:
                # Find parent's modifiers
                if parent in abp_rules:
                    parent_mods = abp_rules[parent][1]
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
    
    # =========================================================================
    # OUTPUT
    # =========================================================================
    
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, "w", encoding="utf-8", newline="\n") as f:
        # ABP rules (including TLD wildcards)
        for tld, (rule, mods) in abp_wildcards.items():
            f.write(rule + "\n")
            stats.abp_kept += 1
        
        for domain, (rule, mods, is_wc) in pruned_abp.items():
            f.write(rule + "\n")
            stats.abp_kept += 1
        
        # Other rules (regex, partial matches, etc.)
        for rule in kept_other:
            f.write(rule + "\n")
            stats.other_kept += 1
    
    # Write whitelist file if requested
    if whitelist_file and allow_rules:
        wl_path = Path(whitelist_file)
        wl_path.parent.mkdir(parents=True, exist_ok=True)
        with open(wl_path, "w", encoding="utf-8", newline="\n") as f:
            for rule in allow_rules:
                f.write(rule + "\n")
        stats.allow_kept = len(allow_rules)
    
    stats.total_output = stats.abp_kept + stats.other_kept
    
    return stats


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python -m scripts.compiler <input_file> <output_file> [whitelist_file]")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    whitelist_file = sys.argv[3] if len(sys.argv) > 3 else None
    
    # Read input
    with open(input_file, encoding="utf-8-sig", errors="replace") as f:
        lines = f.readlines()
    
    stats = compile_rules(lines, output_file, whitelist_file)
    
    print(f"\nCompilation complete:")
    print(f"  Input:  {stats.total_input:,} rules")
    print(f"  Output: {stats.total_output:,} rules")
    print(f"  Reduction: {(1 - stats.total_output / max(stats.total_input, 1)) * 100:.1f}%")
    print(f"\nBy format:")
    print(f"  ABP:   {stats.abp_kept:,}")
    print(f"  Hosts: {stats.hosts_kept:,}")
    print(f"  Plain: {stats.plain_kept:,}")
    print(f"  Other: {stats.other_kept:,}")
    if whitelist_file:
        print(f"  Allow: {stats.allow_kept:,} (separate file)")
    print(f"\nPruned:")
    print(f"  ABP subdomains:     {stats.abp_subdomain_pruned:,}")
    print(f"  TLD wildcards:      {stats.tld_wildcard_pruned:,}")
    print(f"  Cross-format (ABP): {stats.cross_format_pruned:,}")
    print(f"  Duplicates:         {stats.duplicate_pruned:,}")
    print(f"  Whitelist conflicts:{stats.whitelist_conflict_pruned:,}")
    print(f"  Local hostnames:    {stats.local_hostname_pruned:,}")
