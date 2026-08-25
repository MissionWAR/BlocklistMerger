# Shadow Gate Evidence Home

This directory holds the **committed apex-shadow summary manifests** for the
Phase 17 full-corpus shadow-equivalence gate (SAFE-03).

Each canonical run writes a JSON manifest plus a human-readable Markdown
sibling with **versioned stems** — `apex-shadow-v1.json` / `apex-shadow-v1.md`,
then `apex-shadow-v2.*`, and so on — so later runs never clobber earlier
evidence. Every manifest carries an explicit `verdict` field evaluated during
that run; Phase 18's flip gate reads that field (never file presence), so a
stale green cannot masquerade as fresh.

The bulk OFF/ON compiled outputs (~43 MB each) and the frozen corpus datasets
stay **local-only** runtime artifacts per the generated-artifacts constraint in
PROJECT.md; only these summary manifests are tracked. Every other `reports/`
subtree remains gitignored.

Related decisions: `.planning` Phase 17 D-17-02, D-17-05, D-17-07, D-17-08,
D-17-09.
