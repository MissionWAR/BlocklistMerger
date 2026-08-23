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
    $denyallow    A child CARRYING it is never pruned; children under a clean
                  $denyallow TLD wildcard are pruned when provably disjoint
                  (v1.2 denyallow-aware coverage, on by default)
    $dnstype      Only prune if parent blocks ALL types
    $client/$ctag Parent with restrictions can't prune unrestricted child
    ============  ================================================================

Whitelist Handling:
    @@rules (whitelist/exception rules) are used ONLY to remove conflicting blocking
    rules. The @@rules themselves are NOT output. This keeps the output file simple.
"""

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from sys import intern
from typing import Final, NamedTuple

import tldextract

from scripts.pruning_proof import (
    DELTA_CHANGED,
    DELTA_GAINED,
    DELTA_NOT_APPLICABLE,
    DELTA_PRESERVED,
    DELTA_UNCERTAIN,
    OUTCOME_CHANGED,
    OUTCOME_KEPT,
    OUTCOME_PRUNED,
    OUTCOME_REMOVED,
    PROOF_STATUS_NOT_APPLICABLE,
    PROOF_STATUS_PROVEN,
    PROOF_STATUS_UNCERTAIN,
    REASON_BADFILTER_DISABLED,
    REASON_CROSS_FORMAT_BROADENED,
    REASON_DENYALLOW_COVERED,
    REASON_DNSREWRITE_CHANGED,
    REASON_DUPLICATE_RULE,
    REASON_EXCEPTION_COVERED,
    REASON_IGNORED_NONBLOCKING,
    REASON_KEPT_BECAUSE_UNCERTAIN,
    REASON_PARENT_COVERED,
    REASON_REGEX_UNCERTAIN_KEPT,
    REASON_TLD_WILDCARD_COVERED,
    REASON_UNSUPPORTED_MODIFIER_REMOVED,
    REASON_WILDCARD_COVERED,
    ProofLedger,
    RuleFacet,
)
from scripts.rule_semantics import (
    EFFECT_BLOCK,
    EFFECT_DISABLE,
    EFFECT_EXCEPTION,
    EFFECT_IGNORED,
    EFFECT_REWRITE,
    EFFECT_UNCERTAIN,
    EFFECT_UNSUPPORTED,
    ParsedModifier,
    RuleEffect,
    _denyallow_allow_set,
    _domain_disjoint_from_all,
    canonical_modifier_signature,
    classify_rule_effect,
    modifier_names,
    modifier_scope_covers,
    parse_modifier_text,
)
from scripts.rule_syntax import (
    RULE_KIND_ABP,
    RULE_KIND_HOSTS,
    RULE_KIND_PLAIN_DOMAIN,
    RULE_KIND_REGEX,
    RuleSyntax,
    classify_rule_syntax,
    split_pattern_and_modifiers,
)

# =============================================================================
# TYPE ALIASES
# =============================================================================
# These make complex type signatures more readable throughout the codebase.

class AbpRuleRecord(NamedTuple):
    """
    Parsed semantic ABP rule record used by compiler internals.

    Attributes:
        rule: Original rule text preserved for output.
        domain: Normalized domain without an optional wildcard prefix.
        modifiers: Structured modifier records preserving names, values, and uncertainty.
        modifier_names: Legacy names-only view for compatibility and current coverage checks.
        semantic_signature: Canonical modifier signature for exact equivalence checks.
        is_exception: True for whitelist/exception rules.
        is_wildcard: True for `||*.domain^` rules.
        source_rule: Original cleaned input row before project-policy compression.
        source_kind: Input syntax kind before compression.
        source_effect: RuleEffect effect label for proof diagnostics.
        source_scope: RuleEffect scope label for proof diagnostics.
        source_reason: RuleEffect reason label for proof diagnostics.
        source_docs_source: RuleEffect docs source label for proof diagnostics.
    """

    rule: str
    domain: str
    modifiers: tuple[ParsedModifier, ...]
    modifier_names: frozenset[str]
    semantic_signature: tuple[object, ...]
    is_exception: bool
    is_wildcard: bool
    source_rule: str
    source_kind: str
    source_effect: str
    source_scope: str
    source_reason: str
    source_docs_source: str


RuleEntry = AbpRuleRecord
WildcardEntry = AbpRuleRecord
RuleDuplicateKey = tuple[str, bool, str, tuple[object, ...]]
RuleDuplicateIndex = dict[RuleDuplicateKey, RuleEntry]
RuleStorage = dict[str, list[RuleEntry]]
WildcardStorage = dict[str, list[WildcardEntry]]
ExceptionRules = list[RuleEntry]
#: Exception domain -> append-ordered entries bucketed once per compile.
ExceptionIndex = dict[str, list[RuleEntry]]

# =============================================================================
# CONFIGURATION CONSTANTS
# =============================================================================
# Named constants improve readability and make tuning easier.

#: LRU cache size for domain extraction (covers most unique domains in a run)
LRU_CACHE_SIZE: Final[int] = 65536

#: Pre-allocated empty frozenset to avoid repeated allocations
EMPTY_FROZENSET: Final[frozenset[str]] = frozenset()

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
        denyallow_wildcard_pruned: Rules pruned by admissible $denyallow wildcard coverage
        apex_covered_wildcard_pruned: TLD wildcard variants pruned by surviving apex coverage
        duplicate_pruned: Exact duplicate rules removed
        whitelist_conflict_pruned: Rules removed due to whitelist conflicts
        local_hostname_pruned: Local hostnames (localhost, etc.) skipped
        formats_compressed: Hosts/plain domains converted to ABP format
        malformed_discarded: Malformed rules (e.g., ||^) discarded
        abp_rule_keys: Number of ABP domain keys tracked before pruning
        abp_wildcard_keys: Number of TLD wildcard keys tracked before pruning
        exception_rule_keys: Number of exception domain keys tracked before pruning
        duplicate_index_size: Number of semantic duplicate keys tracked before pruning
        other_rule_count: Number of non-ABP rules tracked before output
        rule_effect_block: Input rows classified as blocking effect
        rule_effect_exception: Input rows classified as exception effect
        rule_effect_rewrite: Input rows classified as rewrite effect
        rule_effect_disable: Input rows classified as disabling effect
        rule_effect_ignored: Input rows classified as ignored effect
        rule_effect_unsupported: Input rows classified as unsupported effect
        rule_effect_uncertain: Input rows carrying unproven semantics
        compression_policy_broadened: Hosts/plain rows promoted under project policy
        regex_preserved_no_pruning: Regex rows preserved outside structural pruning

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
    denyallow_wildcard_pruned: int = 0
    apex_covered_wildcard_pruned: int = 0
    duplicate_pruned: int = 0
    whitelist_conflict_pruned: int = 0
    local_hostname_pruned: int = 0
    formats_compressed: int = 0
    malformed_discarded: int = 0

    # Inspect-only compiler cardinalities
    abp_rule_keys: int = 0
    abp_wildcard_keys: int = 0
    exception_rule_keys: int = 0
    duplicate_index_size: int = 0
    other_rule_count: int = 0

    # Rule-effect diagnostics
    rule_effect_block: int = 0
    rule_effect_exception: int = 0
    rule_effect_rewrite: int = 0
    rule_effect_disable: int = 0
    rule_effect_ignored: int = 0
    rule_effect_unsupported: int = 0
    rule_effect_uncertain: int = 0
    compression_policy_broadened: int = 0
    regex_preserved_no_pruning: int = 0


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def normalize_domain(domain: str) -> str:
    """
    Normalize a domain to lowercase, stripped of whitespace and trailing dots.

    Uses sys.intern() to deduplicate domain strings in memory, which also
    speeds up dictionary lookups (pointer comparison vs string comparison).

    Args:
        domain: The domain string to normalize

    Returns:
        Normalized and interned domain string

    Example:
        >>> normalize_domain("  Example.COM.  ")
        'example.com'
    """
    return intern(domain.lower().strip().rstrip("."))


def _parse_abp_rule(
    rule: str,
    *,
    source_rule: str | None = None,
    source_kind: str | None = None,
    source_effect: str | None = None,
    source_scope: str | None = None,
    source_reason: str | None = None,
    source_docs_source: str | None = None,
    parsed_effect: RuleEffect | None = None,
    parsed_syntax: RuleSyntax | None = None,
) -> AbpRuleRecord | None:
    """
    Parse an ABP domain rule into a structured compiler record.

    The public `extract_abp_info()` helper intentionally exposes the legacy
    names-only tuple. Compiler internals use this richer record so modifier
    values remain available for semantic duplicate and coverage decisions.

    Args:
        rule: ABP-style rule text to parse.
        source_rule: Original cleaned input row before compression.
        source_kind/source_effect/source_scope/source_reason/source_docs_source:
            Precomputed provenance labels; any missing field falls back to a
            fresh ``classify_rule_effect`` classification.
        parsed_effect: Precomputed effect for ``source_rule or rule``. When
            provided (and every source_* label is present), the internal
            re-classification is skipped entirely — the hot pipeline path
            always supplies it, so each row classifies exactly once.
        parsed_syntax: Precomputed ``classify_rule_syntax(rule)`` result.
            Only valid when ``rule`` is the exact same text that was
            classified (the direct-ABP path); hosts/plain callers synthesize
            a different rule string and must leave this as None.

    Returns:
        The structured record, or None when the rule has no ABP domain shape.
    """
    if parsed_syntax is not None:
        # Same-text contract: pattern/modifier_text were split from `rule`.
        pattern, modifier_text = parsed_syntax.pattern, parsed_syntax.modifier_text
    else:
        pattern, modifier_text = split_pattern_and_modifiers(rule)
    match = ABP_DOMAIN_PATTERN.match(pattern)
    if not match:
        return None

    modifiers = parse_modifier_text(modifier_text)
    names = modifier_names(modifiers)

    # proof_effect feeds only the `or` fallbacks below; the pipeline path
    # passes all six provenance labels plus parsed_effect, so it stays None
    # there and the third full classification per row disappears. Falsy (not
    # just None) labels trigger classification to preserve the legacy
    # `source_x or proof_effect.x` fallback contract exactly.
    needs_effect = (
        not source_kind
        or not source_effect
        or not source_scope
        or not source_reason
        or not source_docs_source
    )
    proof_effect: RuleEffect | None
    if parsed_effect is not None or not needs_effect:
        proof_effect = parsed_effect
    else:
        proof_effect = classify_rule_effect(source_rule or rule)

    return AbpRuleRecord(
        rule=rule,
        domain=normalize_domain(match.group(3)),
        modifiers=modifiers,
        modifier_names=names if names else EMPTY_FROZENSET,
        semantic_signature=canonical_modifier_signature(modifiers),
        is_exception=match.group(1) is not None,
        is_wildcard=match.group(2) is not None,
        source_rule=source_rule or rule,
        # Runtime-safe by construction: whenever every explicit source_* label
        # above is missing/empty, needs_effect forced a classification, so the
        # fallbacks never dereference a None proof_effect.
        source_kind=source_kind or proof_effect.syntax_kind,
        source_effect=source_effect or proof_effect.effect,
        source_scope=source_scope or proof_effect.scope,
        source_reason=source_reason or proof_effect.reason,
        source_docs_source=source_docs_source or proof_effect.docs_source,
    )


def _domain_shape(domain: str, *, is_wildcard: bool = False) -> str:
    """Return the proof-facing shape of a normalized domain pattern."""
    if not domain:
        return "none"
    if is_wildcard:
        if get_tld(domain) == domain:
            return "tld_wildcard"
        return "wildcard"
    if walk_parent_domains(domain):
        return "subdomain"
    if get_registered_domain(domain) == domain:
        return "registered_domain"
    if get_tld(domain) == domain:
        return "tld"
    return "apex"


def _priority_label(modifiers: tuple[ParsedModifier, ...]) -> str:
    """Return the proof-facing priority label for a parsed modifier tuple."""
    important, priority_safe = _important_priority_state(modifiers)
    if important and priority_safe:
        return "important"
    return "normal"


def _proof_domain_from_line(line: str, syntax: RuleSyntax) -> tuple[str, bool]:
    """Extract a normalized proof domain and wildcard flag from a raw row."""
    if syntax.kind == RULE_KIND_ABP:
        record = _parse_abp_rule(line)
        if record is not None:
            return record.domain, record.is_wildcard
    if syntax.kind == RULE_KIND_HOSTS:
        _ip, domains = extract_hosts_info(line)
        if domains:
            return domains[0], False
    if syntax.kind == RULE_KIND_PLAIN_DOMAIN:
        return normalize_domain(syntax.pattern), False
    return "", False


def _facet_from_line(
    line: str,
    *,
    effect: object,
    syntax: RuleSyntax,
    normalized_rule: str | None = None,
    domain: str | None = None,
    is_wildcard: bool | None = None,
    rule_kind: str | None = None,
) -> RuleFacet:
    """Build proof facets for a raw compiler input row."""
    proof_domain, proof_is_wildcard = _proof_domain_from_line(line, syntax)
    if domain is not None:
        proof_domain = domain
    if is_wildcard is not None:
        proof_is_wildcard = is_wildcard

    modifiers = parse_modifier_text(syntax.modifier_text)
    domain_shape = "regex" if syntax.kind == RULE_KIND_REGEX else _domain_shape(
        proof_domain,
        is_wildcard=proof_is_wildcard,
    )

    return RuleFacet(
        raw_rule=line,
        normalized_rule=normalized_rule or line,
        source_kind=effect.syntax_kind,
        rule_kind=rule_kind or syntax.kind,
        domain=proof_domain,
        domain_shape=domain_shape,
        effect=effect.effect,
        scope=effect.scope,
        modifier_signature=canonical_modifier_signature(modifiers),
        priority=_priority_label(modifiers),
        agh_behavior_basis=effect.docs_source,
    )


def _facet_from_record(record: RuleEntry) -> RuleFacet:
    """Build proof facets from an already parsed compiler rule record."""
    return RuleFacet(
        raw_rule=record.source_rule,
        normalized_rule=record.rule,
        source_kind=record.source_kind,
        rule_kind=RULE_KIND_ABP,
        domain=record.domain,
        domain_shape=_domain_shape(record.domain, is_wildcard=record.is_wildcard),
        effect=record.source_effect,
        scope=record.source_scope,
        modifier_signature=record.semantic_signature,
        priority=_priority_label(record.modifiers),
        agh_behavior_basis=record.source_docs_source,
    )


def _append_proof_record(
    proof_ledger: ProofLedger | None,
    *,
    decision_type: str,
    outcome: str,
    proof_status: str,
    reason: str,
    candidate: Callable[[], RuleFacet],
    covering: Callable[[], RuleFacet | None],
    strict_agh_delta: str,
    project_policy_delta: str,
    sample: Callable[[], dict[str, object] | None] | None = None,
) -> None:
    """Append one compiler proof record when optional proof plumbing is enabled."""
    if proof_ledger is None:
        return

    proof_ledger.append_decision(
        decision_id=f"{decision_type}:{len(proof_ledger) + 1:06d}",
        decision_type=decision_type,
        outcome=outcome,
        proof_status=proof_status,
        reason=reason,
        candidate_factory=candidate,
        covering_factory=covering,
        strict_agh_delta=strict_agh_delta,
        project_policy_delta=project_policy_delta,
        sample_factory=sample,
    )


def _record_nonblocking_proof(
    proof_ledger: ProofLedger | None,
    *,
    line: str,
    effect: object,
    syntax: RuleSyntax,
) -> None:
    """Record diagnostics-only rows that do not enter blocking indexes."""
    if proof_ledger is None:
        return

    reason: str
    outcome = OUTCOME_REMOVED
    strict_delta = DELTA_NOT_APPLICABLE
    project_delta = DELTA_NOT_APPLICABLE
    if effect.effect == EFFECT_UNSUPPORTED:
        reason = REASON_UNSUPPORTED_MODIFIER_REMOVED
    elif effect.effect == EFFECT_DISABLE:
        reason = REASON_BADFILTER_DISABLED
    elif effect.effect == EFFECT_REWRITE:
        reason = REASON_DNSREWRITE_CHANGED
        outcome = OUTCOME_CHANGED
        strict_delta = DELTA_CHANGED
        project_delta = DELTA_CHANGED
    elif effect.effect == EFFECT_IGNORED:
        reason = REASON_IGNORED_NONBLOCKING
    else:
        return

    _append_proof_record(
        proof_ledger,
        decision_type="nonblocking",
        outcome=outcome,
        proof_status=PROOF_STATUS_NOT_APPLICABLE,
        reason=reason,
        candidate=lambda: _facet_from_line(line, effect=effect, syntax=syntax),
        covering=lambda: None,
        strict_agh_delta=strict_delta,
        project_policy_delta=project_delta,
        sample=lambda: {"effect_reason": effect.reason, "docs_source": effect.docs_source},
    )


def _record_regex_uncertain_kept(
    proof_ledger: ProofLedger | None,
    *,
    line: str,
    effect: object,
    syntax: RuleSyntax,
) -> None:
    """Record preserved regex rows as uncertain structural-pruning coverage."""
    _append_proof_record(
        proof_ledger,
        decision_type="regex_uncertain",
        outcome=OUTCOME_KEPT,
        proof_status=PROOF_STATUS_UNCERTAIN,
        reason=REASON_REGEX_UNCERTAIN_KEPT,
        candidate=lambda: _facet_from_line(line, effect=effect, syntax=syntax),
        covering=lambda: None,
        strict_agh_delta=DELTA_UNCERTAIN,
        project_policy_delta=DELTA_UNCERTAIN,
        sample=lambda: {"effect_reason": effect.reason, "docs_source": effect.docs_source},
    )


def _record_cross_format_broadened(
    proof_ledger: ProofLedger | None,
    *,
    line: str,
    abp_rule: str,
    domain: str,
    effect: object,
    syntax: RuleSyntax,
) -> None:
    """Record hosts/plain-domain promotion under the project aggressive policy."""
    _append_proof_record(
        proof_ledger,
        decision_type="cross_format_broadened",
        outcome=OUTCOME_CHANGED,
        proof_status=PROOF_STATUS_PROVEN,
        reason=REASON_CROSS_FORMAT_BROADENED,
        candidate=lambda: _facet_from_line(
            line,
            effect=effect,
            syntax=syntax,
            normalized_rule=abp_rule,
            domain=domain,
            rule_kind=RULE_KIND_ABP,
        ),
        covering=lambda: None,
        strict_agh_delta=DELTA_GAINED,
        project_policy_delta=DELTA_PRESERVED,
        sample=lambda: {
            "input_scope": effect.scope,
            "output_scope": "apex_and_subdomains",
            "policy": "project_policy_promotes_to_abp",
        },
    )


def _rule_effect(record: AbpRuleRecord) -> str:
    """Return the high-level effect used for exact duplicate keys."""
    return "exception" if record.is_exception else "block"


def _duplicate_key(record: AbpRuleRecord) -> RuleDuplicateKey:
    """Return the semantic key that proves exact ABP rule equivalence."""
    return (
        record.domain,
        record.is_wildcard,
        _rule_effect(record),
        record.semantic_signature,
    )


def _rule_storage_key(record: AbpRuleRecord) -> str:
    """Return the domain lookup key used by parent and wildcard pruning."""
    if record.is_wildcard:
        return f"*.{record.domain}"
    return record.domain


def _store_rule_variant(
    storage: RuleStorage | WildcardStorage,
    storage_key: str,
    duplicate_index: RuleDuplicateIndex,
    record: RuleEntry,
    stats: CompileStats,
    proof_ledger: ProofLedger | None,
) -> bool:
    """Store a semantic rule variant, returning False when it was a duplicate."""
    duplicate_key = _duplicate_key(record)
    if duplicate_key in duplicate_index:
        stats.duplicate_pruned += 1
        _append_proof_record(
            proof_ledger,
            decision_type="duplicate",
            outcome=OUTCOME_PRUNED,
            proof_status=PROOF_STATUS_PROVEN,
            reason=REASON_DUPLICATE_RULE,
            candidate=lambda: _facet_from_record(record),
            covering=lambda: _facet_from_record(duplicate_index[duplicate_key]),
            strict_agh_delta=DELTA_PRESERVED,
            project_policy_delta=DELTA_PRESERVED,
            sample=lambda: {"duplicate_key": repr(duplicate_key)},
        )
        return False

    duplicate_index[duplicate_key] = record
    storage.setdefault(storage_key, []).append(record)
    return True


def _record_rule_effect(stats: CompileStats, effect: str, uncertain: bool) -> None:
    """Record exactly one effect bucket, plus uncertainty diagnostics when present."""
    if effect == EFFECT_BLOCK:
        stats.rule_effect_block += 1
    elif effect == EFFECT_EXCEPTION:
        stats.rule_effect_exception += 1
    elif effect == EFFECT_REWRITE:
        stats.rule_effect_rewrite += 1
    elif effect == EFFECT_DISABLE:
        stats.rule_effect_disable += 1
    elif effect == EFFECT_IGNORED:
        stats.rule_effect_ignored += 1
    elif effect == EFFECT_UNSUPPORTED:
        stats.rule_effect_unsupported += 1
    elif effect == EFFECT_UNCERTAIN:
        stats.rule_effect_uncertain += 1
        return
    else:
        stats.rule_effect_uncertain += 1
        return

    if uncertain:
        stats.rule_effect_uncertain += 1


def _is_nonblocking_effect(effect: str) -> bool:
    """Return True when a classified row must not enter blocking output indexes."""
    return effect in {
        EFFECT_REWRITE,
        EFFECT_DISABLE,
        EFFECT_IGNORED,
        EFFECT_UNSUPPORTED,
    }


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
    record = _parse_abp_rule(rule)
    if record is None:
        return None, EMPTY_FROZENSET, False, False
    return (
        record.domain,
        record.modifier_names if record.modifier_names else EMPTY_FROZENSET,
        record.is_exception,
        record.is_wildcard,
    )


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
            # Pre-check local hostnames before interning to avoid
            # wasteful sys.intern() calls on discarded entries
            lower_part = part.lower().strip().rstrip(".")
            if lower_part and lower_part not in LOCAL_HOSTNAMES:
                domains.append(intern(lower_part))

    return ip, domains


def clear_caches() -> None:
    """Clear all LRU caches. Useful for testing or memory management."""
    _extract_domain_parts.cache_clear()
    walk_parent_domains.cache_clear()


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


# =============================================================================
# HELPER FUNCTIONS FOR COMPILATION PHASES
# =============================================================================

def _parse_and_compress_lines(
    lines: Iterable[str],
    stats: CompileStats,
    abp_rules: RuleStorage,
    abp_wildcards: WildcardStorage,
    exceptions: ExceptionRules,
    other_rules: set[str],
    duplicate_index: RuleDuplicateIndex,
    proof_ledger: ProofLedger | None,
) -> None:
    """Phase 1: Parse all rules, convert formats to ABP, and categorize them."""
    for line in lines:
        stats.total_input += 1

        if not (line := line.strip()):
            continue

        # Classify the raw row once and thread the results everywhere below:
        # effect consumes the syntax object, and _parse_abp_rule receives both
        # instead of re-running the same splits/scans (profile-proven 3x/line
        # parse concentration, Phase 14 PERF-01).
        syntax = classify_rule_syntax(line)
        effect = classify_rule_effect(line, syntax=syntax)
        _record_rule_effect(stats, effect.effect, effect.uncertain)

        if syntax.has_url_path or syntax.is_invalid:
            _record_nonblocking_proof(
                proof_ledger,
                line=line,
                effect=effect,
                syntax=syntax,
            )
            stats.malformed_discarded += 1
            continue

        if _is_nonblocking_effect(effect.effect):
            _record_nonblocking_proof(
                proof_ledger,
                line=line,
                effect=effect,
                syntax=syntax,
            )
            if effect.reason == "local_hostname_ignored":
                stats.local_hostname_pruned += 1
            continue

        # ABP-style rules
        if line.startswith(("||", "@@||")):
            record = _parse_abp_rule(
                line,
                source_rule=line,
                source_kind=effect.syntax_kind,
                source_effect=effect.effect,
                source_scope=effect.scope,
                source_reason=effect.reason,
                source_docs_source=effect.docs_source,
                parsed_effect=effect,
                parsed_syntax=syntax,
            )

            if record is None:
                stats.malformed_discarded += 1
                continue

            if record.is_exception:
                exceptions.append(record)
                continue

            if record.is_wildcard:
                tld = get_tld(record.domain)
                if tld and record.domain == tld:
                    _store_rule_variant(
                        abp_wildcards,
                        tld,
                        duplicate_index,
                        record,
                        stats,
                        proof_ledger,
                    )
                else:
                    _store_rule_variant(
                        abp_rules,
                        _rule_storage_key(record),
                        duplicate_index,
                        record,
                        stats,
                        proof_ledger,
                    )
            else:
                _store_rule_variant(
                    abp_rules,
                    _rule_storage_key(record),
                    duplicate_index,
                    record,
                    stats,
                    proof_ledger,
                )
            continue

        if line.startswith("@@"):
            continue

        # Hosts-style rules
        ip, domains = extract_hosts_info(line)
        if ip and domains:
            for domain in domains:
                if domain in LOCAL_HOSTNAMES:
                    stats.local_hostname_pruned += 1
                    continue

                abp_rule = f"||{domain}^"
                record = _parse_abp_rule(
                    abp_rule,
                    source_rule=line,
                    source_kind=effect.syntax_kind,
                    source_effect=effect.effect,
                    source_scope=effect.scope,
                    source_reason=effect.reason,
                    source_docs_source=effect.docs_source,
                    parsed_effect=effect,
                )
                if record is not None and _store_rule_variant(
                    abp_rules,
                    _rule_storage_key(record),
                    duplicate_index,
                    record,
                    stats,
                    proof_ledger,
                ):
                    stats.formats_compressed += 1
                    stats.compression_policy_broadened += 1
                    _record_cross_format_broadened(
                        proof_ledger,
                        line=line,
                        abp_rule=abp_rule,
                        domain=domain,
                        effect=effect,
                        syntax=syntax,
                    )
            continue

        # Plain domain rules
        if PLAIN_DOMAIN_PATTERN.match(line):
            domain = normalize_domain(line)
            if domain and domain not in LOCAL_HOSTNAMES:
                abp_rule = f"||{domain}^"
                record = _parse_abp_rule(
                    abp_rule,
                    source_rule=line,
                    source_kind=effect.syntax_kind,
                    source_effect=effect.effect,
                    source_scope=effect.scope,
                    source_reason=effect.reason,
                    source_docs_source=effect.docs_source,
                    parsed_effect=effect,
                )
                if record is not None and _store_rule_variant(
                    abp_rules,
                    _rule_storage_key(record),
                    duplicate_index,
                    record,
                    stats,
                    proof_ledger,
                ):
                    stats.formats_compressed += 1
                    stats.compression_policy_broadened += 1
                    _record_cross_format_broadened(
                        proof_ledger,
                        line=line,
                        abp_rule=abp_rule,
                        domain=domain,
                        effect=effect,
                        syntax=syntax,
                    )
            else:
                stats.local_hostname_pruned += 1
            continue

        # Other rules (regex, inline duplicates)
        if line.startswith("/") or "|" in line or "*" in line:
            if line not in other_rules:
                other_rules.add(line)
                if effect.syntax_kind == RULE_KIND_REGEX:
                    stats.regex_preserved_no_pruning += 1
                    _record_regex_uncertain_kept(
                        proof_ledger,
                        line=line,
                        effect=effect,
                        syntax=syntax,
                    )
            else:
                stats.duplicate_pruned += 1
            continue


def _build_coverage_lookups(abp_wildcards: WildcardStorage) -> set[str]:
    """Phase 2: Create efficient lookup structures for pruning."""
    return set(abp_wildcards.keys())


def _record_compiler_cardinalities(
    stats: CompileStats,
    abp_rules: RuleStorage,
    abp_wildcards: WildcardStorage,
    exceptions: ExceptionRules,
    duplicate_index: RuleDuplicateIndex,
    other_rules: set[str],
) -> None:
    """Record inspect-only compiler structure sizes after parsing."""
    stats.abp_rule_keys = len(abp_rules)
    stats.abp_wildcard_keys = len(abp_wildcards)
    stats.exception_rule_keys = len({_rule_storage_key(record) for record in exceptions})
    stats.duplicate_index_size = len(duplicate_index)
    stats.other_rule_count = len(other_rules)


def _is_subdomain_of(domain: str, parent_domain: str) -> bool:
    """Return True when domain is below parent_domain in the DNS hierarchy."""
    return parent_domain in walk_parent_domains(domain)


def _exception_domain_scope_covers(exception: RuleEntry, block: RuleEntry) -> bool:
    """Return True when an exception's domain pattern covers a block pattern."""
    if exception.is_wildcard:
        if block.is_wildcard:
            return block.domain == exception.domain or _is_subdomain_of(
                block.domain,
                exception.domain,
            )
        return _is_subdomain_of(block.domain, exception.domain)

    if block.is_wildcard:
        return block.domain == exception.domain or _is_subdomain_of(
            block.domain,
            exception.domain,
        )

    return block.domain == exception.domain or _is_subdomain_of(block.domain, exception.domain)


def _important_priority_state(modifiers: tuple[ParsedModifier, ...]) -> tuple[bool, bool]:
    """Return (has_positive_important, is_safe_to_compare) for priority handling."""
    important_modifiers = [
        modifier
        for modifier in modifiers
        if modifier.name == "important"
    ]
    if not important_modifiers:
        return False, True
    if len(important_modifiers) != 1:
        return False, False

    modifier = important_modifiers[0]
    if modifier.negated or modifier.uncertain or modifier.raw_value is not None or modifier.values:
        return False, False

    return True, True


def _without_priority_modifiers(
    modifiers: tuple[ParsedModifier, ...],
) -> tuple[ParsedModifier, ...]:
    """Return modifiers without `$important` so exception priority can be handled separately."""
    return tuple(modifier for modifier in modifiers if modifier.name != "important")


def _exception_modifier_scope_covers(exception: RuleEntry, block: RuleEntry) -> bool:
    """Return True when exception priority and modifiers cover the block rule."""
    exception_important, exception_priority_safe = _important_priority_state(exception.modifiers)
    block_important, block_priority_safe = _important_priority_state(block.modifiers)
    if not exception_priority_safe or not block_priority_safe:
        return False
    if block_important and not exception_important:
        return False

    return modifier_scope_covers(
        _without_priority_modifiers(exception.modifiers),
        _without_priority_modifiers(block.modifiers),
    )


def _exception_covers_block(exception: RuleEntry, block: RuleEntry) -> bool:
    """Return True when an exception fully covers a block rule."""
    return (
        _exception_domain_scope_covers(exception, block)
        and _exception_modifier_scope_covers(exception, block)
    )


def _is_whitelisted(record: RuleEntry, exceptions: ExceptionRules) -> bool:
    """Check whether any exception rule fully covers a block rule."""
    return any(_exception_covers_block(exception, record) for exception in exceptions)


def _find_covering_exception(record: RuleEntry, exceptions: ExceptionRules) -> RuleEntry | None:
    """Return the first exception that proves removal for a block rule."""
    for exception in exceptions:
        if _exception_covers_block(exception, record):
            return exception
    return None


def _find_domain_scope_exception(record: RuleEntry, exceptions: ExceptionRules) -> RuleEntry | None:
    """Return the first exception with matching domain scope but unproven modifiers."""
    for exception in exceptions:
        if _exception_domain_scope_covers(exception, record):
            return exception
    return None


# ---------------------------------------------------------------------------
# Indexed exception lookups (Phase 14 PERF-01, profile-proven hotspot)
#
# The legacy helpers above scan every exception per candidate record —
# O(records x exceptions) full-coverage predicate calls dominated the Phase 14
# cProfile ranking (~1.6k cumulative seconds over ~3.55M candidates). The
# domain-scope predicate reduces to block.domain == exception.domain OR
# exception.domain in walk_parent_domains(block.domain), so bucketing each
# exception under its own normalized domain makes every candidate's probe-key
# set [domain, *walk_parent_domains(domain)] a superset of every possible
# covering exception's key (exact set-equivalence by definition).
# ---------------------------------------------------------------------------


def _build_exception_index(exceptions: ExceptionRules) -> ExceptionIndex:
    """Bucket exceptions under their own normalized domain, preserving append order."""
    index: ExceptionIndex = {}
    for exception in exceptions:
        index.setdefault(exception.domain, []).append(exception)
    return index


def _exception_probe_keys(record: RuleEntry) -> tuple[str, ...]:
    """Return index keys able to hold exceptions whose scope covers ``record``."""
    return (record.domain, *walk_parent_domains(record.domain))


def _find_covering_exception_indexed(
    record: RuleEntry,
    index: ExceptionIndex,
) -> RuleEntry | None:
    """Return the first fully-covering exception found through the index.

    Buckets keep append order and probe keys run most-specific first, so the
    returned WITNESS may differ from the legacy global-first scan when several
    differently-keyed exceptions cover one candidate. Output bytes, all stats
    counters, and ledger reason buckets are existence-based and unaffected;
    only capped ledger samples could differ (accepted per assumption A5 and
    re-verified by the slow corpus audit at the ship gate).
    """
    for key in _exception_probe_keys(record):
        bucket = index.get(key)
        if not bucket:
            continue
        for exception in bucket:
            if _exception_covers_block(exception, record):
                return exception
    return None


def _find_domain_scope_exception_indexed(
    record: RuleEntry,
    index: ExceptionIndex,
) -> RuleEntry | None:
    """Return the first domain-scope-matching exception via the index."""
    for key in _exception_probe_keys(record):
        bucket = index.get(key)
        if not bucket:
            continue
        for exception in bucket:
            if _exception_domain_scope_covers(exception, record):
                return exception
    return None


def _any_parent_record_covers(child: RuleEntry, parents: list[RuleEntry]) -> bool:
    """Return True when any parent variant proves coverage for a child variant."""
    return any(
        modifier_scope_covers(parent.modifiers, child.modifiers)
        for parent in parents
    )


def _find_covering_parent_record(child: RuleEntry, parents: list[RuleEntry]) -> RuleEntry | None:
    """Return the first parent variant that proves coverage for a child variant."""
    for parent in parents:
        if modifier_scope_covers(parent.modifiers, child.modifiers):
            return parent
    return None


def _find_denyallow_covering_variant(
    child: RuleEntry,
    variants: list[RuleEntry],
    tld: str,
) -> RuleEntry | None:
    """Return the first wildcard variant whose admissible $denyallow set covers a child.

    Iterates variants in storage (append) order so multi-variant TLD keys
    resolve deterministically. A variant proves coverage only when its parsed
    modifiers reduce to exactly one clean $denyallow record (see
    ``_denyallow_allow_set``) AND every allow-entry is fully disjoint from the
    child's normalized domain under the three-way subtree test (see
    ``_domain_disjoint_from_all``).
    """
    for variant in variants:
        allow_set = _denyallow_allow_set(variant.modifiers, tld)
        if allow_set is not None and _domain_disjoint_from_all(child.domain, allow_set):
            return variant
    return None


def _record_proven_pruning(
    proof_ledger: ProofLedger | None,
    *,
    reason: str,
    candidate: RuleEntry,
    covering: RuleEntry,
    outcome: str = OUTCOME_PRUNED,
    strict_agh_delta: str = DELTA_PRESERVED,
    project_policy_delta: str = DELTA_PRESERVED,
    modifier_scope_proven: bool | None = None,
) -> None:
    """Record a proven pruning or removal decision for active compiler coverage."""
    _append_proof_record(
        proof_ledger,
        decision_type=reason,
        outcome=outcome,
        proof_status=PROOF_STATUS_PROVEN,
        reason=reason,
        candidate=lambda: _facet_from_record(candidate),
        covering=lambda: _facet_from_record(covering),
        strict_agh_delta=strict_agh_delta,
        project_policy_delta=project_policy_delta,
        sample=lambda: {
            "candidate_rule": candidate.rule,
            "covering_rule": covering.rule,
            "modifier_scope_proven": (
                modifier_scope_proven
                if modifier_scope_proven is not None
                else modifier_scope_covers(
                    covering.modifiers,
                    candidate.modifiers,
                )
            ),
        },
    )


def _record_uncertain_keep(
    proof_ledger: ProofLedger | None,
    *,
    candidate: RuleEntry,
    covering: RuleEntry,
    reason_detail: str,
) -> None:
    """Record active coverage kept because a possible covering rule was unproven."""
    _append_proof_record(
        proof_ledger,
        decision_type="kept_because_uncertain",
        outcome=OUTCOME_KEPT,
        proof_status=PROOF_STATUS_UNCERTAIN,
        reason=REASON_KEPT_BECAUSE_UNCERTAIN,
        candidate=lambda: _facet_from_record(candidate),
        covering=lambda: _facet_from_record(covering),
        strict_agh_delta=DELTA_UNCERTAIN,
        project_policy_delta=DELTA_UNCERTAIN,
        sample=lambda: {
            "candidate_rule": candidate.rule,
            "covering_rule": covering.rule,
            "reason_detail": reason_detail,
        },
    )


def _prune_redundant_rules(
    abp_rules: RuleStorage,
    abp_wildcards: WildcardStorage,
    tld_wildcards: set[str],
    exceptions: ExceptionRules,
    stats: CompileStats,
    proof_ledger: ProofLedger | None,
    denyallow_pruning: bool = False,
    *,
    exception_index: ExceptionIndex | None = None,
) -> RuleStorage:
    """Phase 3: Remove redundant subdomain and whitelist-conflicted rules.

    Args:
        abp_rules: Blocking ABP records keyed by storage domain.
        abp_wildcards: TLD wildcard records keyed by suffix.
        tld_wildcards: Set of wildcard suffix keys for O(1) membership checks.
        exceptions: Exception (whitelist) records in input order.
        stats: Mutable compilation statistics.
        proof_ledger: Optional proof-decision ledger.
        denyallow_pruning: Attempt last-resort denyallow coverage proofs.
        exception_index: Prebuilt exception domain index; when provided both
            exception lookups use indexed probes, otherwise the legacy linear
            scans run so direct internal callers stay valid.

    Returns:
        Surviving blocking records keyed by domain.
    """
    pruned_abp: RuleStorage = {}

    for domain, records in abp_rules.items():
        for record in records:
            clean_domain = record.domain

            if exception_index is not None:
                covering_exception = _find_covering_exception_indexed(record, exception_index)
            else:
                covering_exception = _find_covering_exception(record, exceptions)
            if covering_exception is not None:
                stats.whitelist_conflict_pruned += 1
                _record_proven_pruning(
                    proof_ledger,
                    reason=REASON_EXCEPTION_COVERED,
                    candidate=record,
                    covering=covering_exception,
                    outcome=OUTCOME_REMOVED,
                    strict_agh_delta=DELTA_CHANGED,
                    project_policy_delta=DELTA_CHANGED,
                    modifier_scope_proven=_exception_modifier_scope_covers(
                        covering_exception,
                        record,
                    ),
                )
                continue
            if exception_index is not None:
                uncertain_covering = _find_domain_scope_exception_indexed(
                    record,
                    exception_index,
                )
            else:
                uncertain_covering = _find_domain_scope_exception(record, exceptions)
            uncertain_reason = "exception_domain_scope_matched_modifier_scope_unproven"

            tld = get_tld(clean_domain)
            if (
                tld
                and tld in tld_wildcards
                and clean_domain != tld
            ):
                covering_tld = _find_covering_parent_record(record, abp_wildcards[tld])
                if covering_tld is not None:
                    stats.tld_wildcard_pruned += 1
                    _record_proven_pruning(
                        proof_ledger,
                        reason=REASON_TLD_WILDCARD_COVERED,
                        candidate=record,
                        covering=covering_tld,
                    )
                    continue
                uncertain_covering = uncertain_covering or abp_wildcards[tld][0]
                uncertain_reason = "tld_wildcard_modifier_scope_unproven"

            pruning_reason: str | None = None
            covering_parent: RuleEntry | None = None
            if record.is_wildcard and clean_domain in abp_rules:
                covering_parent = _find_covering_parent_record(record, abp_rules[clean_domain])
                if covering_parent is not None:
                    pruning_reason = REASON_PARENT_COVERED
                elif uncertain_covering is None and abp_rules[clean_domain]:
                    uncertain_covering = abp_rules[clean_domain][0]
                    uncertain_reason = "wildcard_candidate_parent_modifier_scope_unproven"

            if covering_parent is None:
                for parent in walk_parent_domains(clean_domain):
                    if parent in abp_rules:
                        covering_parent = _find_covering_parent_record(
                            record,
                            abp_rules[parent],
                        )
                        if covering_parent is not None:
                            pruning_reason = REASON_PARENT_COVERED
                            break
                        if uncertain_covering is None and abp_rules[parent]:
                            uncertain_covering = abp_rules[parent][0]
                            uncertain_reason = "parent_modifier_scope_unproven"

                    wildcard_key = f"*.{parent}"
                    if wildcard_key in abp_rules:
                        covering_parent = _find_covering_parent_record(
                            record,
                            abp_rules[wildcard_key],
                        )
                        if covering_parent is not None:
                            pruning_reason = REASON_WILDCARD_COVERED
                            break
                        if uncertain_covering is None and abp_rules[wildcard_key]:
                            uncertain_covering = abp_rules[wildcard_key][0]
                            uncertain_reason = "wildcard_modifier_scope_unproven"

            if covering_parent is not None and pruning_reason is not None:
                stats.abp_subdomain_pruned += 1
                _record_proven_pruning(
                    proof_ledger,
                    reason=pruning_reason,
                    candidate=record,
                    covering=covering_parent,
                )
            else:
                # Last-resort denyallow proof (D-04 Plan A): attempted BEFORE
                # recording the uncertain keep so the shadow-gate signature
                # holds exactly — kept_because_uncertain drops by precisely
                # the denyallow count with total_records unchanged, instead of
                # double-counting one rule in both buckets. The gate on
                # uncertain_reason == "tld_wildcard_modifier_scope_unproven"
                # makes abp_wildcards[tld] safe to index: that reason is only
                # set inside the TLD branch above where tld is non-empty, the
                # key exists, and later walks cannot overwrite it because they
                # only fire while uncertain_covering is still None.
                if (
                    denyallow_pruning
                    and uncertain_reason == "tld_wildcard_modifier_scope_unproven"
                    and modifier_scope_covers((), record.modifiers)
                ):
                    denyallow_variant = _find_denyallow_covering_variant(
                        record,
                        abp_wildcards[tld],
                        tld,
                    )
                    if denyallow_variant is not None:
                        stats.denyallow_wildcard_pruned += 1
                        _record_proven_pruning(
                            proof_ledger,
                            reason=REASON_DENYALLOW_COVERED,
                            candidate=record,
                            covering=denyallow_variant,
                        )
                        continue
                if uncertain_covering is not None:
                    _record_uncertain_keep(
                        proof_ledger,
                        candidate=record,
                        covering=uncertain_covering,
                        reason_detail=uncertain_reason,
                    )
                pruned_abp.setdefault(domain, []).append(record)

    return pruned_abp


def _write_output(
    output_file: str,
    stats: CompileStats,
    abp_wildcards: WildcardStorage,
    pruned_abp: RuleStorage,
    exceptions: ExceptionRules,
    other_rules: set[str],
    proof_ledger: ProofLedger | None,
    *,
    exception_index: ExceptionIndex | None = None,
) -> None:
    """Phase 4: Write deduplicated rules to output atomically.

    Args:
        output_file: Destination path for the merged list.
        stats: Mutable compilation statistics.
        abp_wildcards: TLD wildcard records keyed by suffix.
        pruned_abp: Surviving blocking records from the pruning phase.
        exceptions: Exception (whitelist) records in input order.
        other_rules: Non-ABP rules preserved verbatim, sorted at write time.
        proof_ledger: Optional proof-decision ledger.
        exception_index: Prebuilt exception domain index; when provided the
            write-time whitelist scan uses indexed probes, otherwise the
            legacy linear scan runs so direct internal callers stay valid.
    """
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = output_path.with_suffix(".tmp")

    with open(temp_path, "w", encoding="utf-8", newline="\n") as f:
        for records in abp_wildcards.values():
            for record in records:
                if exception_index is not None:
                    covering_exception = _find_covering_exception_indexed(record, exception_index)
                else:
                    covering_exception = _find_covering_exception(record, exceptions)
                if covering_exception is not None:
                    stats.whitelist_conflict_pruned += 1
                    _record_proven_pruning(
                        proof_ledger,
                        reason=REASON_EXCEPTION_COVERED,
                        candidate=record,
                        covering=covering_exception,
                        outcome=OUTCOME_REMOVED,
                        strict_agh_delta=DELTA_CHANGED,
                        project_policy_delta=DELTA_CHANGED,
                        modifier_scope_proven=_exception_modifier_scope_covers(
                            covering_exception,
                            record,
                        ),
                    )
                    continue
                f.write(record.rule + "\n")
                stats.abp_kept += 1

        for records in pruned_abp.values():
            for record in records:
                f.write(record.rule + "\n")
                stats.abp_kept += 1

        for rule in sorted(other_rules):
            f.write(rule + "\n")
            stats.other_kept += 1

    temp_path.replace(output_path)
    stats.total_output = stats.abp_kept + stats.other_kept


# =============================================================================
# MAIN COMPILATION
# =============================================================================

def compile_rules(
    lines: Iterable[str],
    output_file: str,
    *,
    proof_ledger: ProofLedger | None = None,
    denyallow_pruning: bool = True,
) -> CompileStats:
    """
    Compile and deduplicate rules with format compression.

    This is the main entry point for the compiler. It processes input lines through
    multiple phases to produce a minimal, deduplicated output file. Streams input
    lines sequentially via iteration (Iterable[str]) to significantly reduce peak
    memory footprint during the parsing phase.

    Args:
        lines: Iterable of rule strings to compile (e.g., list, generator, or file object)
        output_file: Path to write the compiled output
        proof_ledger: Optional append-only ledger for compiler proof decisions.
        denyallow_pruning: Attempt last-resort denyallow coverage proofs at TLD
            wildcards whose modifiers reduce to exactly one clean $denyallow record;
            prunes only children fully disjoint from every allow-entry subtree.
            Production-on since v1.2 (D-04): the full-corpus shadow gate proved
            removals are exactly the provably-covered population before this default
            flipped True. Pass False to restore pre-v1.2 keep-everything behavior.

    Returns:
        CompileStats with metrics about the compilation process
    """
    stats = CompileStats()

    # Data structures to accumulate parsed rules
    abp_rules: RuleStorage = {}
    abp_wildcards: WildcardStorage = {}
    duplicate_index: RuleDuplicateIndex = {}
    exceptions: ExceptionRules = []
    other_rules: set[str] = set()

    # PHASE 1: Parse and categorize all rules
    _parse_and_compress_lines(
        lines=lines,
        stats=stats,
        abp_rules=abp_rules,
        abp_wildcards=abp_wildcards,
        exceptions=exceptions,
        other_rules=other_rules,
        duplicate_index=duplicate_index,
        proof_ledger=proof_ledger,
    )

    _record_compiler_cardinalities(
        stats=stats,
        abp_rules=abp_rules,
        abp_wildcards=abp_wildcards,
        exceptions=exceptions,
        duplicate_index=duplicate_index,
        other_rules=other_rules,
    )

    # PHASE 2: Build coverage lookup set
    tld_wildcards = _build_coverage_lookups(abp_wildcards)

    # PHASE 2b: Bucket exceptions by domain once so both exception scans
    # (prune time and write time) probe O(depth) buckets instead of scanning
    # the whole exception list per candidate (profile-proven PERF-01 slice).
    exception_index = _build_exception_index(exceptions)

    # PHASE 3: Prune ABP subdomain rules
    pruned_abp = _prune_redundant_rules(
        abp_rules=abp_rules,
        abp_wildcards=abp_wildcards,
        tld_wildcards=tld_wildcards,
        exceptions=exceptions,
        stats=stats,
        proof_ledger=proof_ledger,
        denyallow_pruning=denyallow_pruning,
        exception_index=exception_index,
    )

    # PHASE 4: Output to file
    _write_output(
        output_file=output_file,
        stats=stats,
        abp_wildcards=abp_wildcards,
        pruned_abp=pruned_abp,
        exceptions=exceptions,
        other_rules=other_rules,
        proof_ledger=proof_ledger,
        exception_index=exception_index,
    )

    return stats


# =============================================================================
# CLI INTERFACE
# =============================================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        prog="scripts.compiler",
        description="Compile and deduplicate blocklist rules.",
    )
    parser.add_argument("input_file", help="Input file containing cleaned rules")
    parser.add_argument("output_file", help="Output file for compiled rules")

    args = parser.parse_args()

    # Read input
    with open(args.input_file, encoding="utf-8-sig", errors="replace") as f:
        lines = f.readlines()

    stats = compile_rules(lines, args.output_file)

    print("\nCompilation complete:")
    print(f"  Input:  {stats.total_input:,} rules")
    print(f"  Output: {stats.total_output:,} rules")
    print(f"  Reduction: {(1 - stats.total_output / max(stats.total_input, 1)) * 100:.1f}%")
    print("\nBy type:")
    print(
        f"  ABP rules:   {stats.abp_kept:,} "
        f"(incl. {stats.formats_compressed:,} compressed from hosts/plain)"
    )
    print(f"  Other rules: {stats.other_kept:,}")
    print("\nPruned:")
    print(f"  ABP subdomains:     {stats.abp_subdomain_pruned:,}")
    print(f"  TLD wildcards:      {stats.tld_wildcard_pruned:,}")
    print(f"  Denyallow wildcards: {stats.denyallow_wildcard_pruned:,}")
    print(f"  Apex-covered wildcards: {stats.apex_covered_wildcard_pruned:,}")
    print(f"  Duplicates:         {stats.duplicate_pruned:,}")
    print(f"  Whitelist conflicts: {stats.whitelist_conflict_pruned:,}")
    print(f"  Local hostnames:    {stats.local_hostname_pruned:,}")
