# AdGuard Home Blocklist Compiler

Merges 70+ DNS blocklists into a single, optimized list for [AdGuard Home](https://adguard.com/en/adguard-home/overview.html).

## Features

- 🚀 **66% size reduction** via intelligent deduplication
- 🌐 **TLD wildcard support** - `||*.autos^` covers entire TLDs
- ⚡ **Fast** - Async downloads, LRU-cached domain parsing
- 🔄 **Auto-updates** - GitHub Actions runs every 12 hours

## Subscribe

Add this URL to AdGuard Home → Filters → DNS Blocklists:

```
https://github.com/YOUR_USERNAME/YOUR_REPO/releases/download/latest/merged.txt
```

## How It Works

| Format | Coverage | Deduplication |
|--------|----------|---------------|
| `\|\|example.com^` | Domain + subdomains | ✅ Prunes redundant subdomains |
| `\|\|*.tld^` | Entire TLD | ✅ Prunes all domains in TLD |
| `0.0.0.0 domain` | Exact domain only | ❌ No subdomain pruning |

## Local Usage

```bash
# Install
pip install .

# Run
python run.py all        # Fetch + compile
python run.py fetch      # Download only
python run.py compile    # Compile only
```

## Project Structure

```
├── config/sources.txt   # Blocklist URLs
├── scripts/             # Python modules
├── run.py               # Local entry point
├── pyproject.toml       # Dependencies
└── .github/workflows/   # Auto-update
```

## License

MIT - do whatever you want with this.
