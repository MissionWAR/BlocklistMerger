# Dirb Shadow Gate: FAIL

- Verdict: fail
- Schema version: 1
- Report type: dirb_shadow_gate
- Created at: 2026-09-03T15:56:17Z

## Signature
- input_rows: 10257217
- added_count: 0
- removed_count: 0
- ledger: {'off_total_records': 8730804, 'on_total_records': 8730804, 'delta_equals_removed': True}
- whitelist_conflict_pruned: {'off': 181, 'on': 181}
- kept_because_uncertain: {'off': 568, 'on': 568}
- other_buckets_stable: True
- off_output_sha256: 29c78613f59048ec6d6f16d1038b0e4a15a9a718012b842941f8095c88bd2bab
- on_output_sha256: 29c78613f59048ec6d6f16d1038b0e4a15a9a718012b842941f8095c88bd2bab
- leg_seconds: {'off': 594.0931811999999, 'on': 442.3744340000012}

## Population
- Total removals: 0
- Pure-TLD share percent: None
- Split bar percent: None (triggered: None)
- single_label_suffix_apex: 0 (0.0%)
- multipart_suffix_apex: 0 (0.0%)

## Timing
- methodology: in-gate median-of-N per leg over caller-supplied lines with gc.collect plus clear_caches between every run; informational only, never gating
- runs: 3
- off: {'runs': 3, 'durations_seconds': [378.539097, 358.241102, 375.579514], 'median_seconds': 375.579514, 'output_sha256_stable': True, 'output_sha256': '29c78613f59048ec6d6f16d1038b0e4a15a9a718012b842941f8095c88bd2bab'}
- on: {'runs': 3, 'durations_seconds': [389.445956, 308.288397, 405.531376], 'median_seconds': 389.445956, 'output_sha256_stable': True, 'output_sha256': '29c78613f59048ec6d6f16d1038b0e4a15a9a718012b842941f8095c88bd2bab'}
- relative_overhead_percent: -3.69
- timing_corpus_digest: f470fcea85913281e6752385ac67ad2cb0e81e90248e6255175b83f5e6e2d604
- same_corpus: True
- cross_tie_off: True
- cross_tie_on: True
- leg_seconds: {'off': 594.0931811999999, 'on': 442.3744340000012}

## Source Health
- present: True
- file_count: 86
- total_bytes: 228954261
- totals_by_status: {'fresh_fetch': 46, 'stale_cache': 6, 'validated_cache': 34}
- degraded_sources: 6

## Proposed Guards (NON-BINDING)
- Data-only draft; Phase 18 wires values atomically with the flip.
- binding: False
- note: data-only draft; headroom derivation lands in Phase 17 plan 04
- proposals: {}
