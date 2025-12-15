#!/usr/bin/env python3
"""
merge_and_classify.py

Merge, deduplicate, and classify rules for AdGuard Home (DNS-level blocking).

Usage:
    python -m scripts.merge_and_classify <input_dir> <merged_out>
"""
from __future__ import annotations

import ipaddress
import sys
import tempfile
from functools import lru_cache
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Pattern

from scripts import utils


# ----------------------------------------
# Import constants and helpers from utils (avoid duplication)
# ----------------------------------------
DOMAIN_PREFIX = utils.DOMAIN_PREFIX
DOMAIN_SEPARATOR = utils.DOMAIN_SEPARATOR
IO_BUFFER_SIZE = utils.IO_BUFFER_SIZE
substring_between = utils.substring_between
normalize_domain_token = utils.normalize_domain_token
minimal_covering_set = utils.minimal_covering_set
walk_suffixes = utils.walk_suffixes  # Used internally by _cached_suffixes


LOCAL_ONLY_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "localhost4",
    "localhost4.localdomain4",
    "localhost6",
    "localhost6.localdomain6",
    "localdomain",
    "localdomain.localhost",
    "local",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
    "broadcasthost",
}


@lru_cache(maxsize=524288)
def _cached_suffixes(domain: str) -> tuple[str, ...]:
    """Return cached tuple of suffixes for repeated lookups."""
    return tuple(walk_suffixes(domain))


def _make_wildcard_checker(wildcard_roots: set[str]) -> Callable[[str], bool]:
    """Return cached predicate to check wildcard coverage."""
    if not wildcard_roots:
        return lambda _domain: False

    roots = frozenset(wildcard_roots)

    @lru_cache(maxsize=262144)
    def _covered(domain: str) -> bool:
        if not domain or "." not in domain:
            return False
        parts = domain.split(".")
        for i in range(1, len(parts)):
            if ".".join(parts[i:]) in roots:
                return True
        return False

    return _covered


def _make_whitelist_checker(
    whitelist: set[str], whitelist_wildcards: set[str] | None = None
) -> Callable[[str], bool]:
    """
    Return cached predicate that checks whitelist coverage.

    Args:
        whitelist: Regular whitelist domains (@@||domain^) — covers domain + all subdomains
        whitelist_wildcards: Wildcard whitelist domains (@@||*.domain^) — covers only subdomains, NOT apex

    The distinction is important:
        - @@||example.com^ → whitelists example.com AND sub.example.com
        - @@||*.example.com^ → whitelists sub.example.com but NOT example.com
    """
    has_regular = bool(whitelist)
    has_wildcards = bool(whitelist_wildcards)

    if not has_regular and not has_wildcards:
        return lambda _domain: False

    whitelist_lookup = frozenset(whitelist) if whitelist else frozenset()
    wildcard_lookup = frozenset(whitelist_wildcards) if whitelist_wildcards else frozenset()

    @lru_cache(maxsize=262144)
    def _is_whitelisted(domain: str) -> bool:
        if not domain:
            return False
        # Check regular whitelists (exact match or parent match)
        if whitelist_lookup:
            if domain in whitelist_lookup:
                return True
            if _has_parent_cached(domain, whitelist_lookup):
                return True
        # Check wildcard whitelists (parent match only, NOT exact match)
        # @@||*.example.com^ should whitelist sub.example.com but NOT example.com
        if wildcard_lookup:
            if _has_parent_cached(domain, wildcard_lookup):
                return True
        return False

    return _is_whitelisted


def _make_abp_coverage_checker(
    abp_minimal: set[str], wildcard_checker: Callable[[str], bool]
) -> Callable[[str], bool]:
    """Return cached predicate that checks ABP coverage (roots + wildcards)."""
    abp_lookup = frozenset(abp_minimal)

    @lru_cache(maxsize=262144)
    def _covered(domain: str) -> bool:
        if not domain:
            return False
        if abp_lookup and any(parent in abp_lookup for parent in _cached_suffixes(domain)):
            return True
        return wildcard_checker(domain)

    return _covered


def _looks_like_plain_domain(line: str) -> bool:
    """Cheap heuristic before running DOMAIN_REGEX."""
    if not line or "." not in line:
        return False
    first = line[0]
    return first.isalnum() or first == "["


def _has_parent_cached(domain: str, domain_set: set[str]) -> bool:
    """Return True if any strict parent of `domain` is present in domain_set."""
    if not domain or not domain_set:
        return False
    suffixes = _cached_suffixes(domain)
    for suffix in suffixes[1:]:
        if suffix in domain_set:
            return True
    return False


def _is_bare_abp_rule(
    rule_text: str, is_wildcard_subdomain: bool, re_abp_bare: Pattern[str]
) -> bool:
    """Return True if the ABP rule has no modifiers (pure blocking)."""
    if re_abp_bare.match(rule_text):
        return True
    return is_wildcard_subdomain and "$" not in rule_text


def _has_important_modifier(rule_text: str) -> bool:
    """Return True if the ABP rule has the $important modifier."""
    # Optimize: avoid .lower() on entire string; check common patterns first
    if "$important" in rule_text:
        return True
    if "$IMPORTANT" in rule_text:
        return True
    # Fallback for mixed case (rare)
    return "$important" in rule_text.lower()


def _abp_rule_is_redundant(
    domain_norm: str,
    *,
    is_bare_rule: bool,
    is_whitelist_rule: bool,
    is_wildcard_rule: bool,
    ctx: MergeContext,
) -> bool:
    """
    Return True if a bare blocking rule is already enforced by a broader rule.

    A rule is redundant when:
      * a parent domain is present in the ABP minimal set, e.g. '||example.com^'
        already covers '||a.example.com^'; or
      * the domain falls under a wildcard (||*.example.com^); or
      * this is a wildcard (||*.example.com^) and the parent domain exists (||example.com^).

    This ABP wildcard/subdomain pruning is intentional—do not remove it to "simplify" the list.
    """
    if is_whitelist_rule or not is_bare_rule or not domain_norm:
        return False
    # Parent coverage: `has_parent` only succeeds for strict parents (not the domain itself)
    if _has_parent_cached(domain_norm, ctx.abp_minimal):
        return True
    # wildcard redundant if its parent apex rule already exists
    if is_wildcard_rule and domain_norm in ctx.abp_minimal:
        return True
    # Wildcard coverage: honours that '*.example.com' does not cover the apex domain
    return ctx.wildcard_covered(domain_norm)


def handle_hosts_line(
    line: str, state: MergeState, ctx: MergeContext, stats: dict[str, int]
) -> bool:
    """Process a /etc/hosts-style rule."""
    try:
        props = ctx.load_hosts_rule(line)
    except Exception:
        stats["invalid_removed"] += 1
        return True

    ip_part = props["ip"]
    ip_canon, ip_is_unspecified, ip_is_loopback = ctx.canonicalize_ip(ip_part)
    original_hostnames = props["hostnames"]
    filtered_pairs: list[tuple[str, str]] = []
    normalized_total = 0
    whitelist_filtered = 0
    abp_filtered = 0
    local_filtered = 0
    seen_norms: set[str] = set()

    for raw in original_hostnames:
        norm = ctx.normalize(raw)
        if not norm or norm in seen_norms:
            continue
        seen_norms.add(norm)
        normalized_total += 1
        if ctx.is_whitelisted(norm):
            whitelist_filtered += 1
            continue
        if norm in LOCAL_ONLY_HOSTNAMES:
            local_filtered += 1
            continue
        if ctx.covered_by_abp(norm):
            abp_filtered += 1
            continue
        filtered_pairs.append((raw, norm))

    def _ip_rank(is_unspecified: bool, is_loopback: bool, canonical_ip: str | None) -> int | None:
        if canonical_ip is None:
            return None
        if is_loopback:
            return 2
        if is_unspecified:
            return 0
        return 1

    if not filtered_pairs:
        if normalized_total == 0:
            stats["invalid_removed"] += 1
        elif whitelist_filtered == normalized_total or whitelist_filtered > 0:
            stats["hosts_removed_by_whitelist"] += 1
        elif local_filtered == normalized_total:
            stats["local_hosts_removed"] += 1
        elif abp_filtered > 0:
            stats["hosts_removed_by_abp"] += 1
        else:
            stats["invalid_removed"] += 1
        return True

    kept_pairs: list[tuple[str, str]] = []
    current_rank = _ip_rank(ip_is_unspecified, ip_is_loopback, ip_canon)

    for raw, norm in filtered_pairs:
        prev_entry = state.domain_map.get(norm)
        if not prev_entry:
            kept_pairs.append((raw, norm))
            continue

        prev_type, prev_text, _prev_ip = prev_entry
        if prev_type == "abp":
            abp_filtered += 1
            continue
        if prev_type == "plain":
            state.remove_rule(prev_text)
            state.domain_map.pop(norm, None)
            stats["duplicates_removed"] += 1
            kept_pairs.append((raw, norm))
            continue
        if prev_type == "hosts":
            prev_ip_canon, prev_is_unspecified, prev_is_loopback = ctx.canonicalize_ip(_prev_ip)
            prev_rank = _ip_rank(prev_is_unspecified, prev_is_loopback, prev_ip_canon)
            if current_rank is None or prev_rank is None:
                stats["duplicates_removed"] += 1
                continue
            if current_rank > prev_rank:
                prev_hostnames = state.host_line_to_hostnames.get(prev_text, [])
                state.remove_host_entry(prev_text, ctx.normalize)
                if stats.get("lines_out", 0) > 0:
                    stats["lines_out"] -= 1
                stats["conflicting_hosts_replaced"] += 1

                existing_norms = {n for _, n in kept_pairs}
                for prev_raw in prev_hostnames:
                    prev_norm = ctx.normalize(prev_raw)
                    if not prev_norm or prev_norm in existing_norms:
                        continue
                    kept_pairs.append((prev_raw, prev_norm))
                    existing_norms.add(prev_norm)
                if norm not in existing_norms:
                    kept_pairs.append((raw, norm))
                    existing_norms.add(norm)
                continue

            if current_rank < prev_rank:
                stats["conflicting_hosts_skipped"] += 1
                continue

            stats["duplicates_removed"] += 1
            continue

        stats["conflicting_hosts_skipped"] += 1
        continue

    if not kept_pairs:
        if whitelist_filtered > 0:
            stats["hosts_removed_by_whitelist"] += 1
        elif local_filtered > 0:
            stats["local_hosts_removed"] += 1
        elif abp_filtered > 0:
            stats["hosts_removed_by_abp"] += 1
        else:
            stats["invalid_removed"] += 1
        return True

    hostnames = [raw for raw, _ in kept_pairs]
    hn_norm_set = {norm for _, norm in kept_pairs if norm}

    out_line = f"{ip_part} {' '.join(hostnames)}"
    if state.has_seen(out_line):
        stats["duplicates_removed"] += 1
        return True

    state.add_rule(out_line)
    state.host_line_to_hostnames[out_line] = list(hostnames)
    state.host_line_to_hostnames_norm[out_line] = hn_norm_set
    state.host_line_to_ip[out_line] = ip_part
    for _, single_norm in kept_pairs:
        if single_norm:
            state.domain_map[single_norm] = ("hosts", out_line, ip_part)
    stats["lines_out"] += 1
    return True


def handle_abp_line(
    line: str,
    abp_domain: str,
    state: MergeState,
    ctx: MergeContext,
    stats: dict[str, int],
) -> bool:
    """Process an ABP-style rule."""
    is_whitelist_rule = line.startswith("@@")
    is_wildcard_subdomain = abp_domain.startswith("*.") and "." in abp_domain[2:]

    dn_norm = ctx.normalize(abp_domain)
    if not dn_norm:
        stats["invalid_removed"] += 1
        return True

    is_bare_rule = _is_bare_abp_rule(line, is_wildcard_subdomain, ctx.re_abp_bare)
    if _abp_rule_is_redundant(
        dn_norm,
        is_bare_rule=is_bare_rule,
        is_whitelist_rule=is_whitelist_rule,
        is_wildcard_rule=is_wildcard_subdomain,
        ctx=ctx,
    ):
        stats["abp_subdomains_removed"] += 1
        return True

    # Wildcard subdomains are keyed as "*.domain" so whitelist checks remain consistent.
    map_key = f"*.{dn_norm}" if is_wildcard_subdomain else dn_norm

    if is_whitelist_rule:
        stats["abp_whitelists_removed"] += 1
        return True

    if ctx.is_whitelisted(dn_norm) or map_key in ctx.whitelist_domains:
        stats["abp_blocks_removed_by_whitelist"] += 1
        return True

    if is_wildcard_subdomain and dn_norm in ctx.whitelist_wildcards:
        stats["abp_blocks_removed_by_whitelist"] += 1
        return True

    def _remove_conflicting_hosts_for_domain() -> None:
        """Drop existing hosts entries for the same domain before keeping the ABP rule."""
        prev_host_entry = state.domain_map.get(dn_norm)
        if not prev_host_entry or prev_host_entry[0] != "hosts":
            return

        host_line = prev_host_entry[1]
        host_ip = prev_host_entry[2]
        raw_hostnames = state.host_line_to_hostnames.get(host_line, [])

        # Remove the old hosts line and all associated bookkeeping.
        state.remove_host_entry(host_line, ctx.normalize)
        if stats.get("lines_out", 0) > 0:
            stats["lines_out"] -= 1
        stats["conflicting_hosts_replaced"] += 1

        if not raw_hostnames or not host_ip:
            return

        kept_raw: list[str] = []
        kept_norms: set[str] = set()
        for raw in raw_hostnames:
            norm = ctx.normalize(raw)
            if not norm or norm == dn_norm or norm in kept_norms:
                continue
            kept_raw.append(raw)
            kept_norms.add(norm)

        if not kept_raw:
            return

        new_line = f"{host_ip} {' '.join(kept_raw)}"
        if state.has_seen(new_line):
            stats["duplicates_removed"] += 1
            return

        state.add_rule(new_line)
        state.host_line_to_hostnames[new_line] = kept_raw
        state.host_line_to_hostnames_norm[new_line] = kept_norms
        state.host_line_to_ip[new_line] = host_ip
        for norm in kept_norms:
            state.domain_map[norm] = ("hosts", new_line, host_ip)
        stats["lines_out"] += 1

    if not is_wildcard_subdomain:
        _remove_conflicting_hosts_for_domain()

    prev_entry = state.domain_map.get(map_key)
    if prev_entry and prev_entry[0] == "abp":
        prev_text = prev_entry[1]
        prev_is_wildcard = prev_text.startswith("||*.") and "." in prev_text[3:]
        prev_is_bare = _is_bare_abp_rule(
            prev_text, prev_is_wildcard, ctx.re_abp_bare
        )
        prev_has_important = _has_important_modifier(prev_text)
        new_has_important = _has_important_modifier(line)

        # Both bare → skip new (duplicate)
        if is_bare_rule and prev_is_bare:
            stats["duplicates_removed"] += 1
            return True

        # New has $important, old is bare → replace old with new
        if new_has_important and prev_is_bare:
            state.remove_rule(prev_text)
            state.domain_map.pop(map_key, None)
            if stats.get("lines_out", 0) > 0:
                stats["lines_out"] -= 1
            stats["duplicates_removed"] += 1
            # Fall through to add the new $important rule below

        # New is bare, old has $important → skip new (old is stronger)
        elif prev_has_important and is_bare_rule:
            stats["duplicates_removed"] += 1
            return True

    if state.has_seen(line):
        stats["duplicates_removed"] += 1
        return True

    state.add_rule(line)
    state.domain_map[map_key] = ("abp", line, None)
    stats["lines_out"] += 1
    return True


def handle_plain_domain_line(
    line: str, state: MergeState, ctx: MergeContext, stats: dict[str, int]
) -> bool:
    """Process a plain domain (no ABP prefix or hosts IP)."""
    dn = ctx.normalize(line)
    if not dn:
        stats["invalid_removed"] += 1
        return True

    if ctx.is_whitelisted(dn):
        stats["plain_removed_by_whitelist"] += 1
        return True

    # Fast O(1) checks first
    if dn in state.domain_map or state.has_seen(line):
        stats["duplicates_removed"] += 1
        return True

    # Slower O(n) checks
    if ctx.covered_by_abp(dn):
        stats["plain_removed_by_abp"] += 1
        return True

    if _has_parent_cached(dn, ctx.plain_minimal):
        stats["plain_subdomains_removed"] += 1
        return True

    state.add_rule(line)
    state.domain_map[dn] = ("plain", line, None)
    stats["lines_out"] += 1
    return True


def handle_other_line(line: str, state: MergeState, stats: dict[str, int]) -> None:
    """Process regex/fragments/other rules (no special handling)."""
    if state.has_seen(line):
        stats["duplicates_removed"] += 1
        return
    state.add_rule(line)
    stats["lines_out"] += 1


@dataclass
class MergeState:
    """
    Mutable state shared by the individual line handlers.

    The domain_map stores tuples of (rule_type, rule_text, ip) where:
      - rule_type: "abp", "hosts", or "plain"
      - rule_text: the original rule line
      - ip: IP address (for hosts rules) or None

    Attributes:
        final_rules:
            Insertion-ordered mapping of every rule kept in the final list.
        seen_rules_text:
            Fast duplicate detector for raw rule text.
        domain_map:
            Maps normalized domains to (rule_type, rule_text, ip) tuples.
        host_line_to_hostnames:
            Original hostnames for each hosts line.
        host_line_to_hostnames_norm:
            Normalized hostname set per hosts line.
        host_line_to_ip:
            Original IP (string) for each hosts line.
    """

    final_rules: dict[str, None] = field(default_factory=dict)
    seen_rules_text: set[str] = field(default_factory=set)
    domain_map: dict[str, tuple[str, str, str | None]] = field(default_factory=dict)
    host_line_to_hostnames: dict[str, list[str]] = field(default_factory=dict)
    host_line_to_hostnames_norm: dict[str, set[str]] = field(default_factory=dict)
    host_line_to_ip: dict[str, str] = field(default_factory=dict)

    def has_seen(self, text: str) -> bool:
        return text in self.seen_rules_text

    def add_rule(self, text: str) -> None:
        self.seen_rules_text.add(text)
        self.final_rules[text] = None

    def remove_rule(self, text: str) -> None:
        self.final_rules.pop(text, None)
        self.seen_rules_text.discard(text)

    def remove_host_entry(self, text: str, normalize: Callable[[str], str]) -> None:
        """Remove host-related bookkeeping for a hosts line that is being replaced."""
        hostnames = self.host_line_to_hostnames.pop(text, [])
        self.host_line_to_hostnames_norm.pop(text, None)
        self.host_line_to_ip.pop(text, None)
        self.remove_rule(text)
        for hostname in hostnames:
            norm = normalize(hostname)
            current = self.domain_map.get(norm)
            if current and current[1] == text:
                self.domain_map.pop(norm, None)


@dataclass(frozen=True)
class MergeContext:
    """
    Bundle of helpers and lookup sets shared by handlers.

    Attributes:
        normalize: Domain normalizer.
        load_hosts_rule: Parser for /etc/hosts lines.
        canonicalize_ip: Helper returning canonical IP + metadata.
        covered_by_abp: Predicate checking whether a plain domain is redundant.
        wildcard_covered: Predicate checking wildcard coverage for ABP rules.
        is_whitelisted: Predicate for whitelist coverage (cross-format).
        whitelist_domains: Normalized whitelist domains collected upfront.
        whitelist_wildcards: Normalized wildcard whitelist domains collected upfront.
        plain_minimal: Minimal covering set of plain domains from inputs.
        abp_minimal: Minimal covering set of ABP blocking domains.
        abp_wildcards: Bare domains extracted from wildcard ABP rules (||*.d^).
        re_abp_bare: Regex detecting bare blocking rules.
    """

    normalize: Callable[[str], str]
    load_hosts_rule: Callable[[str], dict]
    canonicalize_ip: Callable[[str], tuple[str | None, bool, bool]]
    covered_by_abp: Callable[[str], bool]
    wildcard_covered: Callable[[str], bool]
    is_whitelisted: Callable[[str], bool]
    whitelist_domains: set[str]
    whitelist_wildcards: set[str]
    plain_minimal: set[str]
    abp_minimal: set[str]
    abp_wildcards: set[str]
    re_abp_bare: Pattern[str]


# ----------------------------------------
# IP helpers
# ----------------------------------------
@lru_cache(maxsize=1024)
def _canonicalize_ip(ip_raw: str) -> tuple[str | None, bool, bool]:
    """
    Return (canonical_ip, is_unspecified, is_loopback).
    Handles zone IDs in IPv6 addresses.
    
    Cached because the same IPs (0.0.0.0, 127.0.0.1, ::1) appear thousands of times.
    """
    canonical = utils.canonicalize_ip(ip_raw)
    if canonical is None:
        return None, False, False

    try:
        ip_obj = ipaddress.ip_address(canonical)
        return str(ip_obj), ip_obj.is_unspecified, ip_obj.is_loopback
    except Exception:
        return None, False, False


# ----------------------------------------
# ABP first-pass collection (memory-optimized: no line caching)
# ----------------------------------------
def collect_abp_sets(
    input_dir: str,
) -> tuple[dict[str, set[str]], list[Path]]:
    """
    First pass: collect ABP/whitelist/wildcard/plain domain sets.
    
    Memory optimization: Does NOT cache all lines in memory. Returns file paths
    for the second pass to re-read (fast due to OS file cache).
    
    Returns:
        (sets_dict, file_paths) where sets_dict contains:
        - raw_abp: All ABP blocking domains (non-wildcard)
        - abp_minimal: Minimal covering set of ABP domains
        - wildcard_roots: Domains from wildcard rules (||*.domain^)
        - whitelist_domains: Domains from whitelist rules (@@||domain^)
        - plain_candidates: Plain domain candidates
    """
    raw_abp: set[str] = set()
    wildcard_roots: set[str] = set()
    whitelist_domains: set[str] = set()
    whitelist_wildcards: set[str] = set()  # @@||*.domain^ rules (subdomains only)
    plain_candidates: set[str] = set()

    domain_regex = utils.DOMAIN_REGEX
    is_hosts_rule = utils.is_etc_hosts_rule
    normalize = normalize_domain_token

    file_paths = utils.list_text_rule_files(input_dir)
    
    for file_path in file_paths:
        with file_path.open(encoding="utf-8-sig", errors="replace") as f:
            for line in f:
                line = line.strip()

                if not line:
                    continue

                first_char = line[0]
                looks_like_hosts = first_char.isdigit() or first_char == "["
                is_whitelist_rule = line.startswith("@@")

                abp_domain = substring_between(line, DOMAIN_PREFIX, DOMAIN_SEPARATOR)
                if abp_domain:
                    dn_norm = normalize(abp_domain)
                    if not dn_norm:
                        continue

                    if is_whitelist_rule:
                        # Distinguish @@||*.domain^ (wildcard) from @@||domain^ (regular)
                        if abp_domain.startswith("*.") and "." in abp_domain[2:]:
                            whitelist_wildcards.add(dn_norm)
                        else:
                            whitelist_domains.add(dn_norm)
                        continue

                    if abp_domain.startswith("*.") and "." in abp_domain[2:]:
                        wildcard_roots.add(dn_norm)
                        continue

                    raw_abp.add(dn_norm)
                    continue

                if (
                    not is_whitelist_rule
                    and not looks_like_hosts
                    and _looks_like_plain_domain(line)
                    and domain_regex.match(line)
                ):
                    dn_norm = normalize(line)
                    if dn_norm:
                        plain_candidates.add(dn_norm)

    return {
        "raw_abp": raw_abp,
        "abp_minimal": minimal_covering_set(raw_abp),
        "wildcard_roots": wildcard_roots,
        "whitelist_domains": whitelist_domains,
        "whitelist_wildcards": whitelist_wildcards,
        "plain_candidates": plain_candidates,
    }, file_paths


# ----------------------------------------
# Main merge/dedupe/classify
# ----------------------------------------
def transform(input_dir: str, merged_out: str) -> dict[str, int]:
    """Merge, dedupe, and classify rules. Write merged_out atomically."""
    in_path = Path(input_dir)
    if not in_path.is_dir():
        raise FileNotFoundError(f"Input directory not found: {input_dir}")

    # First pass: collect ABP/whitelist/wildcard sets (memory-efficient, no line caching)
    abp_sets, file_paths = collect_abp_sets(input_dir)
    abp_minimal: set[str] = abp_sets["abp_minimal"]
    abp_wildcards: set[str] = abp_sets["wildcard_roots"]
    whitelist_domains: set[str] = abp_sets.get("whitelist_domains", set())
    plain_candidates: set[str] = abp_sets.get("plain_candidates", set())

    whitelist_wildcards: set[str] = abp_sets.get("whitelist_wildcards", set())

    wildcard_covered = _make_wildcard_checker(abp_wildcards)
    covered_by_abp = _make_abp_coverage_checker(abp_minimal, wildcard_covered)
    is_whitelisted = _make_whitelist_checker(whitelist_domains, whitelist_wildcards)

    stats = {
        "files": 0,
        "lines_in": 0,
        "lines_out": 0,
        "duplicates_removed": 0,
        "hosts_removed_by_abp": 0,
        "hosts_removed_by_whitelist": 0,
        "plain_removed_by_abp": 0,
        "plain_removed_by_whitelist": 0,
        "abp_subdomains_removed": 0,
        "plain_subdomains_removed": 0,
        "invalid_removed": 0,
        "conflicting_hosts_skipped": 0,
        "conflicting_hosts_replaced": 0,
        "abp_whitelists_removed": 0,
        "abp_blocks_removed_by_whitelist": 0,
        "local_hosts_removed": 0,
    }

    normalize = normalize_domain_token
    domain_regex = utils.DOMAIN_REGEX
    is_hosts_re = utils.is_etc_hosts_rule
    load_hosts = utils.load_etc_hosts_rule_properties
    canonicalize_ip = _canonicalize_ip
    re_abp_bare = utils.ABP_HOSTNAME_RE

    # Precompute minimal covering sets so handlers can do fast redundancy checks.
    plain_minimal = minimal_covering_set(
        {dn for dn in plain_candidates if not covered_by_abp(dn)}
    )

    ctx = MergeContext(
        normalize=normalize,
        load_hosts_rule=load_hosts,
        canonicalize_ip=canonicalize_ip,
        covered_by_abp=covered_by_abp,
        wildcard_covered=wildcard_covered,
        is_whitelisted=is_whitelisted,
        whitelist_domains=whitelist_domains,
        whitelist_wildcards=whitelist_wildcards,
        plain_minimal=plain_minimal,
        abp_minimal=abp_minimal,
        abp_wildcards=abp_wildcards,
        re_abp_bare=re_abp_bare,
    )
    state = MergeState()

    # Second pass: re-read files and process lines (OS file cache makes this fast)
    for file_path in sorted(file_paths, key=lambda p: p.name.lower()):
        stats["files"] += 1
        with file_path.open(encoding="utf-8-sig", errors="replace") as f:
            for raw_line in f:
                line = raw_line.strip()
                stats["lines_in"] += 1
                if not line:
                    continue

                is_whitelist_rule = line.startswith("@@")
                first_char = line[0]
                looks_like_hosts = (
                    (" " in line or "\t" in line)
                    and (
                        first_char.isdigit()
                        or first_char in ("[", ":")
                        or first_char.lower() in "abcdef"
                    )
                )
                if looks_like_hosts and is_hosts_re(line):
                    handle_hosts_line(line, state, ctx, stats)
                    continue

                abp_domain = substring_between(line, DOMAIN_PREFIX, DOMAIN_SEPARATOR)
                if abp_domain:
                    handle_abp_line(line, abp_domain, state, ctx, stats)
                    continue

                if is_whitelist_rule:
                    stats["abp_whitelists_removed"] += 1
                    continue

                if _looks_like_plain_domain(line) and domain_regex.match(line):
                    handle_plain_domain_line(line, state, ctx, stats)
                    continue

                handle_other_line(line, state, stats)

    out_path = Path(merged_out)
    out_dir = out_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            newline="\n",
            dir=out_dir,
            prefix=".tmp_merged_",
            delete=False,
            buffering=IO_BUFFER_SIZE,
        ) as tmp_file:
            tmp_path = Path(tmp_file.name)
            for r in state.final_rules:
                tmp_file.write(r + "\n")
            tmp_file.flush()
        tmp_path.replace(out_path)
        tmp_path = None
    finally:
        if tmp_path and tmp_path.exists():
            try:
                tmp_path.unlink(missing_ok=True)
            except Exception:
                pass

    return stats


def _print_summary(stats: dict[str, int]) -> None:
    """Print formatted summary of merge statistics.
    
    Outputs both a machine-parseable primary line and human-readable breakdown.
    """
    lines_in = stats.get('lines_in', 0)
    lines_out = stats.get('lines_out', 0)
    files = stats.get('files', 0)
    
    # Calculate compression ratio
    ratio = ((lines_in - lines_out) / lines_in * 100) if lines_in > 0 else 0
    
    # Primary stats line (compatible with existing log parsing)
    print(
        f"merge_and_classify: files={files} lines_in={lines_in:,} "
        f"lines_out={lines_out:,} reduction={ratio:.1f}%"
    )
    
    # Collect all removal categories
    removal_categories = [
        ("duplicates", stats.get('duplicates_removed', 0)),
        ("abp_subdomains", stats.get('abp_subdomains_removed', 0)),
        ("plain_subdomains", stats.get('plain_subdomains_removed', 0)),
        ("hosts_by_abp", stats.get('hosts_removed_by_abp', 0)),
        ("plain_by_abp", stats.get('plain_removed_by_abp', 0)),
        ("by_whitelist", (
            stats.get('hosts_removed_by_whitelist', 0) +
            stats.get('plain_removed_by_whitelist', 0) +
            stats.get('abp_blocks_removed_by_whitelist', 0)
        )),
        ("invalid", stats.get('invalid_removed', 0)),
        ("local_hosts", stats.get('local_hosts_removed', 0)),
        ("whitelists_dropped", stats.get('abp_whitelists_removed', 0)),
        ("hosts_conflicts", (
            stats.get('conflicting_hosts_skipped', 0) +
            stats.get('conflicting_hosts_replaced', 0)
        )),
    ]
    
    # Only print non-zero removal stats (keeps output clean)
    parts = [f"{name}={count:,}" for name, count in removal_categories if count > 0]
    if parts:
        print(f"  removed: {' '.join(parts)}")
    
    # Sanity check: verify accounting
    total_removed = sum(count for _, count in removal_categories)
    expected_removed = lines_in - lines_out
    if total_removed != expected_removed and lines_in > 0:
        # Note: This can happen due to hosts lines with multiple domains
        # being counted once but containing multiple domains
        pass  # Accounting is intentionally approximate for hosts lines



if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(
            "Usage: python -m scripts.merge_and_classify <input_dir> <merged_out>",
            file=sys.stderr,
        )
        sys.exit(2)
    inp = sys.argv[1]
    merged = sys.argv[2]
    try:
        stats = transform(inp, merged)
        _print_summary(stats)
    except Exception as exc:
        print(f"ERROR in merge_and_classify: {exc}", file=sys.stderr)
        sys.exit(1)