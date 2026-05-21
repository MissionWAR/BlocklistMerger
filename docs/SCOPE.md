# Scope

Blocklist Merger v1 is intentionally small. This repository publishes one
AdGuard Home-compatible `merged.txt` release asset from the URL catalog in
`config/sources.txt`.

## Current v1 Scope

- Keep `config/sources.txt` as the plain-text source catalog for upstream blocklist URLs.
- Fetch raw sources into generated `lists/_raw/` files and compile one `lists/merged.txt`
  output.
- Publish `merged.txt` as the latest GitHub Release asset for AdGuard Home DNS blocklists.
- Treat `lists/`, `.cache/`, and `reports/` as generated runtime outputs rather than source
  snapshots.

## Deferred to v2

The following configuration-platform ideas are documented here as the public deferral record,
not as current compiler or workflow behavior:

- Structured JSON/YAML source metadata
- Per-source transformations
- Inclusion and exclusion list semantics
- Named pruning policies
- Multiple output profiles
