#!/usr/bin/env python3
"""
downloader.py - Async Blocklist Downloader with Smart Caching

Downloads blocklists with ETag/Last-Modified caching and concurrent fetching.
Falls back to cached files if download fails.

Usage:
    python -m scripts.downloader --sources sources.txt --outdir data/ --cache .cache
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import NamedTuple

import aiohttp
import aiofiles


# Default configuration
DEFAULT_TIMEOUT = 30
DEFAULT_RETRIES = 3
DEFAULT_CONCURRENCY = 8

# State file for ETag/Last-Modified tracking
STATE_FILE = "state.json"


class FetchResult(NamedTuple):
    """Result of a single fetch operation."""
    url: str
    success: bool
    changed: bool
    error: str | None = None


def url_to_filename(url: str) -> str:
    """Generate a safe, unique filename from a URL."""
    # Use SHA256 hash for uniqueness, take first 16 chars
    url_hash = hashlib.sha256(url.encode()).hexdigest()[:16]
    # Extract domain for readability
    try:
        from urllib.parse import urlparse
        domain = urlparse(url).netloc.replace(".", "_")[:30]
    except Exception:
        domain = "unknown"
    return f"{domain}_{url_hash}.txt"


def load_sources(sources_file: str) -> list[str]:
    """Load URLs from sources file, skipping comments and empty lines."""
    urls = []
    path = Path(sources_file)
    if not path.exists():
        print(f"ERROR: Sources file not found: {sources_file}", file=sys.stderr)
        return urls
    
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue
            urls.append(line)
    
    return urls


def load_state(cache_dir: Path) -> dict:
    """Load state.json containing ETag/Last-Modified cache."""
    state_path = cache_dir / STATE_FILE
    if state_path.exists():
        try:
            with open(state_path, encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            print(f"Warning: Could not load state.json: {e}", file=sys.stderr)
    return {}


def save_state(cache_dir: Path, state: dict) -> None:
    """Save state.json atomically."""
    state_path = cache_dir / STATE_FILE
    temp_path = state_path.with_suffix(".tmp")
    try:
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
        temp_path.replace(state_path)
    except OSError as e:
        print(f"Warning: Could not save state.json: {e}", file=sys.stderr)


async def fetch_url(
    session: aiohttp.ClientSession,
    url: str,
    output_dir: Path,
    cache_dir: Path,
    state: dict,
    timeout: int,
    retries: int,
) -> FetchResult:
    """
    Fetch a single URL with ETag/Last-Modified caching.
    
    Returns:
        FetchResult with success/changed status
    """
    filename = url_to_filename(url)
    output_path = output_dir / filename
    cache_path = cache_dir / filename
    
    # Get cached headers
    url_state = state.get(url, {})
    etag = url_state.get("etag")
    last_modified = url_state.get("last_modified")
    
    headers = {}
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified
    
    for attempt in range(retries):
        try:
            async with session.get(
                url, 
                headers=headers, 
                timeout=aiohttp.ClientTimeout(total=timeout),
                allow_redirects=True,
            ) as response:
                
                # 304 Not Modified - use cached version
                if response.status == 304:
                    if cache_path.exists():
                        # Copy from cache to output
                        async with aiofiles.open(cache_path, "rb") as src:
                            content = await src.read()
                        async with aiofiles.open(output_path, "wb") as dst:
                            await dst.write(content)
                        return FetchResult(url, success=True, changed=False)
                    # Cache file missing, need to re-download
                    headers = {}  # Reset conditional headers
                    continue
                
                # Error responses
                if response.status >= 400:
                    if attempt < retries - 1:
                        await asyncio.sleep(2 ** attempt)  # Exponential backoff
                        continue
                    
                    # Use cached/local file as fallback
                    if cache_path.exists():
                        async with aiofiles.open(cache_path, "rb") as src:
                            content = await src.read()
                        async with aiofiles.open(output_path, "wb") as dst:
                            await dst.write(content)
                        return FetchResult(
                            url, 
                            success=True, 
                            changed=False,
                            error=f"HTTP {response.status}, using cached version"
                        )
                    return FetchResult(url, success=False, changed=False, error=f"HTTP {response.status}")
                
                # Successful response - download content
                content = await response.read()
                
                # Save to output
                async with aiofiles.open(output_path, "wb") as f:
                    await f.write(content)
                
                # Update cache
                async with aiofiles.open(cache_path, "wb") as f:
                    await f.write(content)
                
                # Update state with new ETag/Last-Modified
                new_state = {}
                if "ETag" in response.headers:
                    new_state["etag"] = response.headers["ETag"]
                if "Last-Modified" in response.headers:
                    new_state["last_modified"] = response.headers["Last-Modified"]
                new_state["filename"] = filename
                new_state["fetched_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                state[url] = new_state
                
                return FetchResult(url, success=True, changed=True)
                
        except asyncio.TimeoutError:
            if attempt < retries - 1:
                await asyncio.sleep(2 ** attempt)
                continue
            # Fallback to cache
            if cache_path.exists():
                async with aiofiles.open(cache_path, "rb") as src:
                    content = await src.read()
                async with aiofiles.open(output_path, "wb") as dst:
                    await dst.write(content)
                return FetchResult(url, success=True, changed=False, error="Timeout, using cached version")
            return FetchResult(url, success=False, changed=False, error="Timeout")
            
        except Exception as e:
            if attempt < retries - 1:
                await asyncio.sleep(2 ** attempt)
                continue
            # Fallback to cache
            if cache_path.exists():
                try:
                    async with aiofiles.open(cache_path, "rb") as src:
                        content = await src.read()
                    async with aiofiles.open(output_path, "wb") as dst:
                        await dst.write(content)
                    return FetchResult(url, success=True, changed=False, error=f"{e}, using cached version")
                except Exception:
                    pass
            return FetchResult(url, success=False, changed=False, error=str(e))
    
    return FetchResult(url, success=False, changed=False, error="Max retries exceeded")


async def fetch_all(
    urls: list[str],
    output_dir: Path,
    cache_dir: Path,
    concurrency: int,
    timeout: int,
    retries: int,
) -> list[FetchResult]:
    """Fetch all URLs concurrently with rate limiting."""
    # Ensure directories exist
    output_dir.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)
    
    # Load state
    state = load_state(cache_dir)
    
    # Create semaphore for concurrency control
    semaphore = asyncio.Semaphore(concurrency)
    
    async def fetch_with_semaphore(url: str) -> FetchResult:
        async with semaphore:
            return await fetch_url(
                session, url, output_dir, cache_dir, state, timeout, retries
            )
    
    # Create session with connection pooling
    connector = aiohttp.TCPConnector(limit=concurrency, limit_per_host=2)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [fetch_with_semaphore(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Handle exceptions in results
    final_results = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            final_results.append(FetchResult(urls[i], success=False, changed=False, error=str(result)))
        else:
            final_results.append(result)
    
    # Save updated state
    save_state(cache_dir, state)
    
    return final_results


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Fetch blocklist sources with caching")
    parser.add_argument("--sources", required=True, help="Path to sources.txt file")
    parser.add_argument("--outdir", required=True, help="Output directory for fetched files")
    parser.add_argument("--cache", required=True, help="Cache directory for ETag state")
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY, help="Max concurrent downloads")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Request timeout in seconds")
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES, help="Number of retries per URL")
    
    args = parser.parse_args()
    
    # Load sources
    urls = load_sources(args.sources)
    if not urls:
        print("No URLs found in sources file", file=sys.stderr)
        return 1
    
    print(f"🔄 Fetching {len(urls)} sources...")
    
    # Run async fetch
    results = asyncio.run(fetch_all(
        urls,
        Path(args.outdir),
        Path(args.cache),
        args.concurrency,
        args.timeout,
        args.retries,
    ))
    
    # Print summary
    success = sum(1 for r in results if r.success)
    changed = sum(1 for r in results if r.changed)
    failed = sum(1 for r in results if not r.success)
    
    print(f"✅ Fetched: {success}/{len(urls)} (changed: {changed}, cached: {success - changed})")
    
    if failed > 0:
        print(f"⚠️  Failed: {failed}")
        for r in results:
            if not r.success:
                print(f"   - {r.url}: {r.error}")
    
    # Return error if too many failures (>50%)
    if failed > len(urls) // 2:
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
