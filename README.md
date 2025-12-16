# Blocklist Merger

> [!NOTE]  
> Made for personal use, but feel free to use it too.

## What It Does

- Fetches 80+ public DNS blocklists
- Removes comments, cosmetic rules, and invalid entries
- Deduplicates intelligently (subdomains covered by parent rules are removed)
- Keeps only rules compatible with AdGuard Home
- Updates automatically every 12 hours

## Usage

1. Open **AdGuard Home**
2. Go to **Filters → DNS blocklists**
3. Click **Add blocklist**
4. Paste this URL:

```
https://github.com/MissionWAR/Blocklist-Merger/releases/download/latest/merged.txt
```

## Sources

Upstream blocklist URLs are in [`config/sources.txt`](config/sources.txt).

Each list is maintained by its original author.

## Building Locally

```bash
pip install .
python run.py all
```

## Thanks

- **AdGuard Team** — for the idea and documentation
- **Blocklist maintainers** — for keeping lists updated
- **Open-source community** — tools that made this possible

> [!CAUTION]  
> Please respect the licenses of the original blocklists if you fork this project.

## License

MIT
