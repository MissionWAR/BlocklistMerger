# Blocklist Merger

Combines multiple DNS blocklists into one optimized file for AdGuard Home.

## How to Use

Add this URL to **AdGuard Home** → **Filters** → **DNS Blocklists**:

```
https://github.com/YOUR_USERNAME/YOUR_REPO/releases/download/latest/merged.txt
```

The list updates automatically every 12 hours.

## What It Does

1. Downloads 70+ public blocklists
2. Removes duplicates and redundant rules
3. Outputs a single clean file

### Smart Deduplication

If `||example.com^` exists, it already blocks all subdomains like `ads.example.com`. So those subdomain rules are removed - they're redundant.

Same with TLD wildcards: `||*.xyz^` covers every `.xyz` domain, so individual rules aren't needed.

## Building Locally

```bash
pip install .
python run.py all
```

## License

MIT
