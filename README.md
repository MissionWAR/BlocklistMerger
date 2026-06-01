# Blocklist Merger

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A tool that merges public DNS blocklists into a single, deduplicated file optimized for [AdGuard Home](https://adguard.com/adguard-home/overview.html).

> [!NOTE]
> Made for personal use, but feel free to use it if you find it useful.

---

## ✨ Features

- **Fetches** 80+ public DNS blocklists automatically
- **Cleans** rules (removes comments, cosmetic rules, browser-only modifiers)
- **Deduplicates** intelligently: subdomains covered by parent rules are removed
- **Outputs** only AdGuard Home compatible rules
- **Updates** every 12 hours via GitHub Actions

---

## 📥 Usage

1. Open **AdGuard Home**
2. Go to **Filters → DNS blocklists**
3. Click **Add blocklist**
4. Paste this URL:

```
https://github.com/MissionWAR/BlocklistMerger/releases/download/latest/merged.txt
```

---

## Scope and Non-Goals

This repository publishes one AdGuard Home-compatible `merged.txt` release asset from the
URLs in `config/sources.txt`. Broader configuration-platform ideas are deferred; see
[`docs/SCOPE.md`](docs/SCOPE.md).
The AdGuard Home DNS semantics baseline is documented in
[`docs/AGH_SEMANTICS.md`](docs/AGH_SEMANTICS.md).
The Python-first runtime and language decision gate is documented in
[`docs/RUNTIME_LANGUAGE_GATE.md`](docs/RUNTIME_LANGUAGE_GATE.md).

---

## 📋 Sources

Upstream blocklist URLs are listed in [`config/sources.txt`](config/sources.txt).

Each list is maintained by its original author. This project only merges and deduplicates them.

---

## 🔧 Forking This Workflow

Fork maintainers can keep the current one-artifact workflow and only change the source
catalog:

1. Edit [`config/sources.txt`](config/sources.txt). Use one URL per line; blank lines and
   comments are ignored.
2. Keep Python 3.14 for local parity with the scheduled GitHub Actions release job.
3. Install and run the existing module commands:

```bash
pip install .

# Download blocklists
python -m scripts.downloader --sources config/sources.txt --outdir lists/_raw --cache .cache --health-report reports/source-health.json

# Merge and deduplicate
python -m scripts.pipeline lists/_raw lists/merged.txt --json-stats reports/pipeline-stats.json
```

The workflow also runs on `workflow_dispatch` and every 12 hours (`0 */12 * * *`) using
`SOURCES=config/sources.txt`, `RAW_DIR=lists/_raw`, and `OUTPUT=lists/merged.txt`.
Generated paths such as `lists/_raw/`, `.cache`, `lists/merged.txt`, and `reports/` are
runtime outputs, not source files to edit or commit.

For a fork, replace `<owner>/<repo>` with your repository:

```text
https://github.com/<owner>/<repo>/releases/download/latest/merged.txt
```

Diagnostics are written during workflow runs as `reports/source-health.json`,
`reports/pipeline-stats.json`, and `reports/validation-summary.md`, then uploaded with the
release-candidate artifact. The scheduled release install is pinned by
[`constraints/release-py314.txt`](constraints/release-py314.txt).

| Setting | Existing surface | Notes |
| ------- | ---------------- | ----- |
| Source catalog | `SOURCES=config/sources.txt`, `--sources config/sources.txt` | Public v1 edit point for upstream URLs. |
| Raw downloads | `RAW_DIR=lists/_raw`, `--outdir lists/_raw` | Generated input for compilation. |
| Cache | `--cache .cache` | Generated HTTP cache and state. |
| Merged output | `OUTPUT=lists/merged.txt`, pipeline output argument | Published as the release asset. |
| Downloader concurrency | `--concurrency` | Existing local CLI knob; workflow currently uses `10`. |
| Downloader timeout | `--timeout` | Existing local CLI knob; workflow currently uses `25`. |
| Downloader retries | `--retries` | Existing local CLI knob. |
| Source health report | `--health-report reports/source-health.json` | Workflow diagnostic artifact. |
| Pipeline stats | `--json-stats reports/pipeline-stats.json` | Workflow diagnostic artifact. |

---

## ⭐ Acknowledgments

- [AdGuard Team](https://adguard.com) for AdGuard Home, their documentation, and [HostlistCompiler](https://github.com/AdguardTeam/HostlistCompiler)
- Blocklist maintainers for keeping their lists updated
- Open-source community for the tools that made this possible

> [!CAUTION]
> Please respect the licenses of the original blocklists if you fork this project.

---

## 📄 License

[MIT](LICENSE)
