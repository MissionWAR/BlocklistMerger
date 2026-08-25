# Apex Shadow Gate: FAIL

- Verdict: fail
- Schema version: 1
- Report type: apex_shadow_gate
- Created at: 2026-08-24T18:59:35Z

## Closure Note: Direction A Abandoned (Option C, decided 2026-08-24)

This manifest is committed intentionally with verdict **fail**: it is the documented
CLOSURE of Direction A (`wildcard_apex_pruning`), a calibration record rather than a
machinery failure. How to read it:

1. Exactly ONE named check failed: `timing_within_bar` (DIAG-01). Every
   shadow-equivalence check is GREEN. Over 10,348,336 input rows the ON leg added
   nothing, removed exactly what the uncapped ledger witnessed (removed == tally ==
   counter == 0), kept uncertain rules identical across legs (569 == 569), left the
   whitelist-conflict bucket identical (181 == 181), produced byte-identical OFF/ON
   outputs, had its ledger totals delta equal the removal count, and showed stable
   determinism fingerprints (S1-S9 placement-specific signature).
2. The ZERO removal population is a calibration fact, not a gate failure
   (17-CONTEXT discretion clause: "near-zero results are a calibration fact, not a
   failure"; FA-1/Pitfall 11 forbids magnitude expectations in this run book). At the
   current source mix, the v1.0 TLD-wildcard-coverage branch already prunes every
   `||*.K^` / `||K^` same-key pair, so the Direction-A flagged pass finds nothing
   left to remove while adding fixed costs: ON median 308.38 s vs OFF median
   249.96 s = -23.37% improvement against the inclusive -10.0% floor (+23.4%
   overhead, dominated by `_build_apex_survivor_index` over ~8.77M records plus
   write-time scans with zero removals to amortize).
3. DECISION (maintainer, Option C, 2026-08-24): Direction A is structurally
   redundant with the existing v1.0 branch and is ABANDONED. The flag remains
   keyword-only default-OFF as a deliberate closure decision; that is NOT a stub.
4. The gate remains RE-RUNNABLE if the source mix ever produces a non-trivial
   same-key apex population: set `APEX_SHADOW_DATASET_ID=apex-shadow-v2`,
   re-run Stage A freeze + timing legs + this gate immediately before any future
   flip consideration (D-17-04 pre-flight pattern). Phase 18's consumers read the
   verdict FIELD, never file presence (D-17-08).
5. D-17-06 split-bar answer recorded mechanically below: pure-TLD share 0.0% is
   below the 1.0% bar, so `reason_split_triggered` is false and one reason
   constant stands permanently absent a source-mix change.

Provenance: run at git revision 356a349, Python 3.14.6, Windows 11; frozen corpus
86 files / 231,266,675 bytes, manifest_sha256
3bd739e891bf841b116ff17ea9e5306290c9f69bdc6d3c2ae0a41ba26b40e401.

## Signature
- input_rows: 10348336
- added_count: 0
- removed_count: 0
- ledger: {'off_total_records': 8771590, 'on_total_records': 8771590, 'delta_equals_removed': True}
- whitelist_conflict_pruned: {'off': 181, 'on': 181}
- kept_because_uncertain: {'off': 569, 'on': 569}
- other_buckets_stable: True
- off_output_sha256: 87f0ecb702a21faf3069b1b0fd129242fa2df5d26cf393d464f481ae327edabe
- on_output_sha256: 87f0ecb702a21faf3069b1b0fd129242fa2df5d26cf393d464f481ae327edabe
- leg_seconds: {'off': 249.04245850000007, 'on': 364.1683359999988}

## Population
- Total removals: 0
- Pure-TLD share percent: 0.0
- Split bar percent: 1.0 (triggered: False)
- single_label_suffix_apex: 0 (0.0%)
- multipart_suffix_apex: 0 (0.0%)

## Timing
- methodology: median-of-3 per leg, one kind per invocation
- off: {'runs': 3, 'durations_seconds': [249.963609, 215.536238, 271.341037], 'median_seconds': 249.96, 'output_sha256_stable': True}
- on: {'runs': 3, 'durations_seconds': [296.334379, 308.375702, 316.686317], 'median_seconds': 308.38, 'output_sha256_stable': True}
- relative_overhead_percent: -23.37
- bar_percent: 10.0
- passes: False
- same_corpus: True
- cross_tie_off: True
- cross_tie_on: True
- on_compile_flags: {'wildcard_apex_pruning': True}

## Source Health
- present: True
- file_count: 86
- total_bytes: 231266675
- totals_by_status: {'fresh_fetch': 62, 'stale_cache': 5, 'validated_cache': 19}
- degraded_sources: 5

## Proposed Guards (NON-BINDING)
- Data-only draft; Phase 18 wires values atomically with the flip.
- binding: False
- note: data-only draft for Phase 18 review (D-17-09/D-17-10); values derive from measured population plus headroom and bind nothing
- minimum_output_rules: {'current': 1000000, 'proposed': 3557273, 'basis': 'the ON leg IS the deterministic post-flip preview; expected floor = off_rule_count - removed_count'}
- previous_extreme_drop_ratio: {'current': 0.25, 'expected_first_post_flip_drop': 0.0, 'proposed': None}
- previous_extreme_increase_ratio: {'current': 1.0, 'expected_first_post_flip_increase': 0.0, 'proposed': None}
- previous_moderate_delta_ratio: {'current': 0.1, 'observed_first_flip_relative_delta': 0.0, 'proposed': None}
- previous_extreme_absolute_delta: {'current': 2000000, 'observed_first_flip_absolute_rule_delta': 0, 'proposed': None}
- removal_count_window: {'expected_apex_covered_wildcard_pruned': 0, 'headroom_low': 0, 'headroom_high': 1}
- counter_ledger_equality: {'expected': 'tally == counter == removed, both directions'}
- uncertain_keeps_stasis: {'expected_delta': 0}
