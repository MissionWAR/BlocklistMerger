# AdGuard Home Semantics Matrix

This matrix is the Phase 7 baseline for AdGuard Home DNS filtering semantics.
Official AGH documentation is the primary source tier; local fixtures and compiler
diagnostics are supporting evidence only.

## Policy Baseline

- D-01: Hosts and domain-only inputs are still promoted to ABP-style rules by
  default in this project.
- D-02: That promotion is coverage-broadening compression, not strict AGH
  exact-host equivalence. AGH hosts and domain-only syntax is documented as
  exact-host behavior; this project intentionally broadens those rows for the
  default merged output.
- D-03: Fixtures and diagnostics should keep both views visible: documented AGH
  exact-host baseline and the project aggressive default.
- D-07: Regex rules remain preserved and excluded from structural pruning until a
  regex coverage oracle exists.
- D-09: Evidence tiers are ordered as official AGH docs, local fixtures, then
  optional manual smoke checks.
- D-10: Live AGH smoke checks are manual only and are not part of the scheduled
  12-hour publish path.
- D-11: Rows without documentation or fixture proof remain uncertain and must not
  justify new pruning.

## Sources

- Official AGH DNS filtering syntax:
  <https://adguard-dns.io/kb/general/dns-filtering-syntax/>
- Official AGH hosts blocklists wiki:
  <https://github.com/AdguardTeam/AdGuardHome/wiki/Hosts-Blocklists>
- Local compiler evidence: `scripts/compiler.py`, `scripts/cleaner.py`,
  `scripts/rule_semantics.py`, `tests/test_compiler.py`,
  `tests/test_rule_semantics.py`, and `tests/test_parser_contract.py`.

## Matrix

| Rule kind | Documented AGH DNS behavior | Current project policy | Evidence tier | Diagnostics key | Pruning policy |
|-----------|-----------------------------|------------------------|---------------|-----------------|----------------|
| ABP basic `||example.org^` | Blocks the apex and subdomains. | Keep as an ordinary blocking ABP rule. | Official AGH docs plus local compiler fixtures. | `effect=block`, `syntax=abp`, `scope=apex_and_subdomains` | Eligible for structural pruning only when domain shape and modifiers prove coverage. |
| ABP exception `@@||example.org^` | Unblocks matching apex and subdomains. | Consume as an exception against matching blocks; do not emit exception rules in the block-only output. | Official AGH docs plus local compiler fixtures. | `effect=exception`, `syntax=abp` | May remove only proven equivalent or broader blocks; scoped or uncertain exceptions do not justify pruning. |
| Hosts blocking IP `0.0.0.0 example.org` or `127.0.0.1 example.org` | Blocks the exact host in AGH and does not cover subdomains. | Promote to `||example.org^` by default as coverage-broadening compression. | Official AGH docs and hosts wiki plus current compiler behavior. | `effect=block`, `syntax=hosts`, `compression=coverage_broadened` | The AGH baseline is exact-host; project pruning may use the broadened ABP form only as explicit product policy. |
| Hosts real-IP rewrite `1.2.3.4 example.org` | Answers the exact host with the provided IP address. | Treat as rewrite or nonblocking-host behavior, not as ordinary block coverage. Current compiler ignores nonblocking hosts. | Official AGH docs plus local compiler behavior. | `effect=rewrite_or_ignored`, `syntax=hosts` | Not eligible for block pruning unless later fixtures prove an equivalent rewrite-safe rule effect. |
| Domain-only `example.org` | Blocks only the exact host, not `www.example.org`. | Promote to `||example.org^` by default as coverage-broadening compression. | Official AGH docs plus current compiler behavior. | `effect=block`, `syntax=plain_domain`, `compression=coverage_broadened` | Same policy as hosts blocking-IP rows: AGH exact-host baseline, project broadened default. |
| Regex `/REGEX/` | Matches hostnames by regular expression; exception regex rows may carry supported modifiers such as `$important`. | Preserve regex rules as non-structural rules. | Official AGH docs plus local parser/compiler fixtures. | `effect=block_regex` or `effect=exception_regex`, `syntax=regex` | Excluded from parent, wildcard, TLD, and domain structural pruning until a regex oracle exists. |
| Wildcard `||*.example.com^` | Wildcard behavior is documented for subdomain-style matching; local canaries keep apex behavior visible. | Preserve current wildcard/apex handling and do not expand it in Phase 7. | Official AGH docs plus local release-validator/compiler canaries. | `effect=block`, `syntax=abp`, `shape=wildcard` | Use only where existing wildcard proof applies; uncertain apex overlap does not justify pruning. |
| Unsupported or unknown modifier | AGH ignores a rule containing an unsupported modifier. | Classify as unsupported or ignored and do not count as blocking coverage. | Official AGH docs plus cleaner/release-validator behavior. | `effect=unsupported`, `reason=unknown_modifier` | Not eligible for pruning as coverage; discarded or quarantined as non-effective output. |
| Browser-only modifier such as `$script` | Not part of AGH DNS syntax. | Cleaner discards known browser-only rules; release validation rejects emitted browser-only modifiers. | Official AGH docs plus local cleaner and validator fixtures. | `effect=unsupported`, `reason=browser_only_modifier` | Not active DNS coverage and not a pruning proof source. |
| `badfilter` | Disables the matching basic rule by text without `$badfilter`; it does not apply to hosts-style rules. | Classify as a disabling directive, not a block. Full effective-rule resolution is deferred. | Official AGH docs and hosts wiki plus planned effect diagnostics. | `effect=disable`, `modifier=badfilter` | Do not emit or count as ordinary block coverage; cannot justify structural pruning. |
| `important` | Raises priority over non-important rules and affects exception interactions. | Preserve priority state in modifier signatures and diagnostics. | Official AGH docs plus local compiler priority fixtures. | `effect=block_or_exception`, `modifier=important`, `priority=important` | Pruning must respect priority; a non-important exception cannot remove an important block. |
| `denyallow` | Narrows a broader blocking rule by excluding listed domains. | Preserve structured values and classify as scoped block with exclusions. | Official AGH docs plus local modifier parser/compiler fixtures. | `effect=scoped_block`, `modifier=denyallow` | Excluded from broad structural pruning unless an exclusion-aware proof exists. |
| `dnsrewrite` | Rewrites the DNS response and has separate rewrite behavior from ordinary blocking. | Preserve as rewrite behavior, not normal block coverage. | Official AGH docs plus local modifier parser/compiler fixtures. | `effect=rewrite`, `modifier=dnsrewrite` | Not eligible for ordinary block pruning. |
| `dnstype` | Narrows matching by DNS request or response type; response-record details are version-sensitive. | Preserve values case-insensitively and mark runtime parity uncertain without fixtures or manual smoke checks. | Official AGH docs plus local modifier parser fixtures; manual smoke optional. | `effect=scoped_block_or_rewrite`, `modifier=dnstype`, `uncertain=rr_type_runtime` | Prune only when type scope is proven to cover the child rule; otherwise keep. |
| `client` | Narrows a rule to client IP, CIDR, or persistent client name; ClientIDs are not supported. | Preserve client scope and do not treat as a global block. | Official AGH docs plus local modifier parser fixtures. | `effect=scoped_block`, `modifier=client` | A scoped client rule does not prune an unscoped or differently scoped rule. |
| `ctag` | Narrows a rule to AGH client tags. | Preserve tag scope and classify as narrowed coverage. | Official AGH docs plus local modifier parser behavior. | `effect=scoped_block`, `modifier=ctag` | A tag-scoped rule does not justify global pruning. |

## Manual Smoke Notes

Optional live AGH smoke checks are useful only for rows marked uncertain, such as
version-sensitive `dnstype` response behavior or wildcard/apex overlap. They are
manual inspection aids, not release gates, scheduled workflow steps, Docker
requirements, or public configuration options.
