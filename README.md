# Blocklist Merger

[![Update Status](https://github.com/MissionWAR/BlocklistMerger/actions/workflows/update.yml/badge.svg)](https://github.com/MissionWAR/BlocklistMerger/actions/workflows/update.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A tool that merges public DNS blocklists into a single, deduplicated file optimized for [AdGuard Home](https://adguard.com/adguard-home/overview.html).

> [!NOTE]
> Made for personal use, but feel free to use it if you find it useful.

---

## Features

- **Fetches** 80+ public DNS blocklists automatically
- **Cleans** rules (removes comments, cosmetic rules, browser-only modifiers)
- **Deduplicates** intelligently — subdomains covered by parent rules are removed
- **Outputs** only AdGuard Home compatible rules
- **Updates** every 12 hours via GitHub Actions

---

## Usage

1. Open **AdGuard Home**
2. Go to **Filters → DNS blocklists**
3. Click **Add blocklist**
4. Paste this URL:

```
https://github.com/MissionWAR/BlocklistMerger/releases/download/latest/merged.txt
```

---

## Sources

Upstream blocklist URLs are listed in [`config/sources.txt`](config/sources.txt).

Each list is maintained by its original author — this project only merges and deduplicates them.

---

## Building Locally

```bash
pip install .
python run.py all
```

---

## Acknowledgments

- [AdGuard Team](https://adguard.com) — for AdGuard Home and their documentation
- Blocklist maintainers — for keeping their lists updated
- Open-source community — for the tools that made this possible

> [!CAUTION]
> Please respect the licenses of the original blocklists if you fork this project.

---

## License

[MIT](LICENSE)
