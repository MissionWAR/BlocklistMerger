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

## Closure Note: Direction B Closed as Negative with Manifest (decided 2026-09-04)

This manifest is committed intentionally with verdict **fail**: it is the documented
CLOSURE of Direction B (`wildcard_covers_subs_pruning`), a calibration record rather
than a machinery failure. How to read it:

1. Exactly ONE named check failed: `population_nonzero`. Every other
   shadow-equivalence check is GREEN. Over 10,257,217 input rows the ON leg added
   nothing, removed exactly what the uncapped ledger witnessed (removed == tally ==
   counter == 0), kept uncertain rules identical across legs via STASIS (568 == 568),
   left the whitelist-conflict bucket identical (181 == 181), produced byte-identical
   OFF/ON outputs, had its ledger totals delta equal the removal count, and matched
   the independent audit expectation (audit_expected == total == 0; the recorded
   divergences are UNPARSABLE_SKIPPED rows, not missing pairs).
2. The ZERO removal population is a calibration fact, not a gate failure
   (17-CONTEXT discretion clause: "near-zero results are a calibration fact, not a
   failure"; FA-1/Pitfall 11 forbids magnitude expectations in this run book). At the
   current source mix, after deduplication nothing remains that only the new pass can
   remove, so the Direction-B flagged pass finds nothing left to prune while showing
   -3.69% median wall-clock overhead (ON median 389.45 s vs OFF median 375.58 s, an
   informational figure that never gates the verdict).
3. DECISION (maintainer, close-as-negative-with-manifest, 2026-09-04): Direction B is
   redundant with existing coverage and is CLOSED. The instrument stays deliberately
   default-OFF as a closure decision; that is NOT a stub.
4. The gate remains RE-RUNNABLE if the source mix ever produces a non-trivial
   wildcard-plus-sub population: set `DIRB_SHADOW_DATASET_ID=dirb-shadow-v2`,
   re-run Stage A freeze + timing legs + this gate immediately before any future
   flip consideration (D-17-04 pre-flight pattern; carried-forward D-18-09 link-only
   re-run). Consumers read the verdict FIELD, never file presence (D-17-08).
5. The verdict FIELD above stays the single source of truth: this note annotates the
   markdown rendering only and never rewrites the committed JSON verdict, whose
   identity (git revision 34d8b68, Python 3.14.6, Windows 11) plus digest provenance
   (corpus manifest_sha256
   f470fcea85913281e6752385ac67ad2cb0e81e90248e6255175b83f5e6e2d604) are cited, not
   edited.

Provenance: run at git revision 34d8b68, Python 3.14.6, Windows 11; frozen corpus
86 files / 228,954,261 bytes, manifest_sha256
f470fcea85913281e6752385ac67ad2cb0e81e90248e6255175b83f5e6e2d604.
