#!/usr/bin/env python3
"""
downloader.py - Async Blocklist Downloader with Smart Caching

Downloads blocklists with ETag/Last-Modified caching and concurrent fetching.
Falls back to cached files if download fails.

Features:
    - Async downloads with aiohttp for high concurrency
    - ETag/Last-Modified caching to avoid re-downloading unchanged files
    - Automatic retry with exponential backoff
    - Graceful fallback to cached files on error
    - Progress tracking and detailed statistics

Usage:
    python -m scripts.downloader --sources sources.txt --outdir data/ --cache .cache

Example:
    >>> from scripts.downloader import fetch_all
    >>> import asyncio
    >>> results = asyncio.run(fetch_all(urls, output_dir, cache_dir, 8, 30, 3))
    >>> print(f"Downloaded {sum(r.success for r in results)} of {len(results)} sources")

See Also:
    - docs/ARCHITECTURE.md for caching strategy details
"""

import argparse
import asyncio
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Final, NamedTuple

import aiohttp
import aiofiles


# =============================================================================
# CONFIGURATION CONSTANTS
# =============================================================================

#: Default timeout per HTTP request in seconds
DEFAULT_TIMEOUT: Final[int] = 30

#: Default number of retry attempts before giving up
DEFAULT_RETRIES: Final[int] = 3

#: Default number of simultaneous HTTP connections
DEFAULT_CONCURRENCY: Final[int] = 8

#: State file name for ETag/Last-Modified tracking
STATE_FILE: Final[str] = "state.json"


# =============================================================================
# DATA STRUCTURES
# =============================================================================

class FetchResult(NamedTuple):
    """
    Result of a single fetch operation.
    
    Attributes:
        url: The URL that was fetched
        success: True if fetch succeeded (includes cache fallback)
        changed: True if content changed (False for 304 Not Modified)
        error: Error message if something went wrong, None otherwise
        
    Example:
        >>> result = FetchResult("https://example.com/list.txt", True, True, None)
        >>> result.success
        True
    """
    url: str
    success: bool
    changed: bool
    error: str | None = None


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def url_to_filename(url: str) -> str:
    """
    Generate a safe, unique filename from a URL.
    
    Uses SHA256 hash for uniqueness and extracts domain for readability.
    
    Args:
        url: The source URL
        
    Returns:
        Safe filename like "example_com_a1b2c3d4.txt"
        
    Example:
        >>> url_to_filename("https://example.com/blocklist.txt")
        'example_com_a1b2c3d4e5f6g7h8.txt'
    """
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
    """
    Load URLs from sources file, skipping comments and empty lines.
    
    Args:
        sources_file: Path to the sources.txt file
        
    Returns:
        List of URLs to fetch
        
    Note:
        Lines starting with # are treated as comments.
        Inline comments (after #) are also stripped.
        
    Example:
        >>> urls = load_sources("config/sources.txt")
        >>> len(urls)
        80
    """
    urls: list[str] = []
    path = Path(sources_file)
    if not path.exists():
        print(f"ERROR: Sources file not found: {sources_file}", file=sys.stderr)
        return urls
    
    with open(path, encoding="utf-8") as f:
        for line in f:
            # Strip comments and whitespace
            line = line.split("#", 1)[0].strip()
            
            if not line:
                continue
            urls.append(line)
    
    return urls


def load_state(cache_dir: Path) -> dict[str, dict[str, str]]:
    """
    Load state.json containing ETag/Last-Modified cache.
    
    Args:
        cache_dir: Directory containing the state file
        
    Returns:
        State dictionary mapping URLs to their cached headers
        
    Example:
        >>> state = load_state(Path(".cache"))
        >>> state.get("https://example.com/list.txt", {}).get("etag")
        '"abc123"'
    """
    state_path = cache_dir / STATE_FILE
    if state_path.exists():
        try:
            with open(state_path, encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            print(f"Warning: Could not load state.json: {e}", file=sys.stderr)
    return {}


def save_state(cache_dir: Path, state: dict[str, dict[str, str]]) -> None:
    """
    Save state.json atomically.
    
    Uses a temporary file and atomic rename to prevent corruption if
    the process is interrupted during write.
    
    Args:
        cache_dir: Directory to save state file in
        state: State dictionary to save
    """
    state_path = cache_dir / STATE_FILE
    temp_path = state_path.with_suffix(".tmp")
    try:
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
        temp_path.replace(state_path)
    except OSError as e:
        print(f"Warning: Could not save state.json: {e}", file=sys.stderr)


# =============================================================================
# ASYNC FETCH FUNCTIONS
# =============================================================================

async def fetch_url(
    session: aiohttp.ClientSession,
    url: str,
    output_dir: Path,
    cache_dir: Path,
    state: dict[str, dict[str, str]],
    timeout: int,
    retries: int,
) -> FetchResult:
    """
    Fetch a single URL with ETag/Last-Modified caching.
    
    Uses conditional requests (If-None-Match, If-Modified-Since) to avoid
    re-downloading unchanged content. Falls back to cached files on error.
    
    Args:
        session: aiohttp session for connection pooling
        url: URL to fetch
        output_dir: Directory to save fetched files
        cache_dir: Directory for cached files and state
        state: Mutable state dict for tracking ETags
        timeout: Request timeout in seconds
        retries: Number of retry attempts
        
    Returns:
        FetchResult with success/changed status
        
    Note:
        This function modifies `state` in-place when new ETags are received.
    """
    filename = url_to_filename(url)
    output_path = output_dir / filename
    cache_path = cache_dir / filename
    
    # Get cached headers for conditional request
    url_state = state.get(url, {})
    etag = url_state.get("etag")
    last_modified = url_state.get("last_modified")
    
    headers: dict[str, str] = {}
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
                new_state: dict[str, str] = {}
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
    """
    Fetch all URLs concurrently with rate limiting.
    
    Uses a semaphore to control maximum concurrent connections,
    preventing overwhelming the network or servers.
    
    Args:
        urls: List of URLs to fetch
        output_dir: Directory to save fetched files
        cache_dir: Directory for cached files and state
        concurrency: Maximum concurrent connections
        timeout: Request timeout in seconds per URL
        retries: Number of retry attempts per URL
        
    Returns:
        List of FetchResult for each URL
        
    Example:
        >>> results = await fetch_all(urls, Path("data"), Path(".cache"), 8, 30, 3)
        >>> success_count = sum(r.success for r in results)
    """
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
    final_results: list[FetchResult] = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            final_results.append(FetchResult(urls[i], success=False, changed=False, error=str(result)))
        else:
            final_results.append(result)
    
    # Save updated state
    save_state(cache_dir, state)
    
    return final_results


# =============================================================================
# CLI INTERFACE
# =============================================================================

def main() -> int:
    """
    Main entry point for CLI usage.
    
    Returns:
        Exit code (0 for success, 1 for failure)
    """
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
