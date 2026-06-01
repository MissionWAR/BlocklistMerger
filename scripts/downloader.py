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
"""

import argparse
import asyncio
import calendar
import hashlib
import json
import sys
import time
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from typing import Final, NamedTuple, TypedDict
from urllib.parse import urlparse

import aiofiles
import aiohttp

from scripts import __version__

# =============================================================================
# CONFIGURATION CONSTANTS
# =============================================================================

#: Default timeout per HTTP request in seconds
DEFAULT_TIMEOUT: Final[int] = 30

#: Default number of retry attempts before giving up
DEFAULT_RETRIES: Final[int] = 3

#: Default number of simultaneous HTTP connections
DEFAULT_CONCURRENCY: Final[int] = 8

#: Bounded chunk size for response streaming and cache/raw file copies
DOWNLOAD_CHUNK_SIZE: Final[int] = 1024 * 1024

#: State file name for ETag/Last-Modified tracking
STATE_FILE: Final[str] = "state.json"

#: Source-health report schema version
SOURCE_HEALTH_SCHEMA_VERSION: Final[int] = 1

#: Cache fallback age threshold before a source is considered stale
STALE_CACHE_SECONDS: Final[int] = 48 * 60 * 60

SOURCE_HEALTH_STATUSES: Final[tuple[str, ...]] = (
    "fresh_fetch",
    "validated_cache",
    "fallback_cache",
    "stale_cache",
    "failed",
)


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


class SourceHealth(NamedTuple):
    """
    Machine-readable health record for one configured source URL.

    Attributes:
        url: Configured upstream URL.
        filename: Deterministic raw/cache filename for the URL.
        status: One of fresh_fetch, validated_cache, fallback_cache, stale_cache, failed.
        changed: True when fresh content was downloaded in this run.
        byte_size: Content size for successful fresh/cache-backed records, otherwise 0.
        sha256: Content checksum for successful fresh/cache-backed records.
        cache_age_seconds: Age of cache content when cache freshness is applicable.
        failure_reason: HTTP/network/cache failure detail when applicable.
    """

    url: str
    filename: str
    status: str
    changed: bool
    byte_size: int
    sha256: str | None
    cache_age_seconds: int | None
    failure_reason: str | None


class SourceHealthReport(NamedTuple):
    """Versioned source-health report written for release validation."""

    schema_version: int
    version: str
    generated_at: str
    source_count: int
    totals_by_status: dict[str, int]
    sources: list[SourceHealth]


class SourceHealthRuntimeSummary(TypedDict):
    """Compact source-health/cache projection for default runtime evidence."""

    available: bool
    report_path: str | None
    schema_version: int | None
    source_count: int
    totals_by_status: dict[str, int]
    cache_backed_sources: int
    failed_sources: int
    total_byte_size: int


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


def _utc_timestamp() -> str:
    """Return the current UTC timestamp in report/state format."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _cache_age_seconds(
    url_state: dict[str, str],
    now: float,
) -> int | None:
    """Return cache age in seconds when state contains a valid UTC fetched_at value."""
    fetched_at = url_state.get("fetched_at")
    if not fetched_at:
        return None

    try:
        fetched_epoch = calendar.timegm(time.strptime(fetched_at, "%Y-%m-%dT%H:%M:%SZ"))
    except ValueError:
        return None

    return max(0, int(now - fetched_epoch))


def _temp_path_for(path: Path) -> Path:
    """Return the sibling temp path used for atomic downloader promotion."""
    return path.with_suffix(".tmp")


def _cleanup_temp_file(path: Path) -> None:
    """Remove an abandoned temp file if it exists."""
    with suppress(FileNotFoundError):
        path.unlink()


async def _copy_file_bounded(source_path: Path, destination_path: Path) -> None:
    """Copy one file to another through a bounded sibling temp file."""
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = _temp_path_for(destination_path)
    try:
        async with (
            aiofiles.open(source_path, "rb") as src,
            aiofiles.open(temp_path, "wb") as dst,
        ):
            while chunk := await src.read(DOWNLOAD_CHUNK_SIZE):
                await dst.write(chunk)
        temp_path.replace(destination_path)
    except Exception:
        _cleanup_temp_file(temp_path)
        raise


async def _stream_response_to_file(
    response: aiohttp.ClientResponse,
    destination_path: Path,
) -> None:
    """Stream an HTTP response body to a file through a bounded sibling temp file."""
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = _temp_path_for(destination_path)
    try:
        async with aiofiles.open(temp_path, "wb") as dst:
            async for chunk in response.content.iter_chunked(DOWNLOAD_CHUNK_SIZE):
                await dst.write(chunk)
        temp_path.replace(destination_path)
    except Exception:
        _cleanup_temp_file(temp_path)
        raise


def _content_identity(path: Path | None) -> tuple[int, str | None]:
    """Return byte size and SHA-256 digest for an existing content file."""
    if path is None or not path.exists():
        return 0, None

    byte_size = 0
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(DOWNLOAD_CHUNK_SIZE):
            byte_size += len(chunk)
            digest.update(chunk)
    return byte_size, digest.hexdigest()


async def _copy_cache_to_output(cache_path: Path, output_path: Path) -> None:
    """Promote cached content into the raw output path through the bounded copy helper."""
    await _copy_file_bounded(cache_path, output_path)


def source_health_from_fetch_result(
    result: FetchResult,
    output_dir: Path,
    cache_dir: Path,
    state: dict[str, dict[str, str]],
    *,
    now: float | None = None,
) -> SourceHealth:
    """
    Convert one fetch result into a source-health record.

    Args:
        result: Fetch result from ``fetch_url()`` or ``fetch_all()``.
        output_dir: Directory where fetched raw files are written.
        cache_dir: Directory where cache files are stored.
        state: Loaded downloader state keyed by source URL.
        now: Optional epoch timestamp for deterministic tests.

    Returns:
        SourceHealth record with status, cache age, and content identity.
    """
    filename = url_to_filename(result.url)
    output_path = output_dir / filename
    cache_path = cache_dir / filename
    current_time = time.time() if now is None else now

    cache_age = None
    if result.success and not result.changed:
        cache_age = _cache_age_seconds(state.get(result.url, {}), current_time)

    if result.success and result.changed:
        status = "fresh_fetch"
    elif result.success and result.error is None:
        status = "validated_cache"
    elif result.success:
        if cache_age is None or cache_age > STALE_CACHE_SECONDS:
            status = "stale_cache"
        else:
            status = "fallback_cache"
    else:
        status = "failed"

    content_path: Path | None = None
    if result.success:
        content_path = output_path if output_path.exists() else cache_path

    byte_size, sha256 = _content_identity(content_path)

    return SourceHealth(
        url=result.url,
        filename=filename,
        status=status,
        changed=result.changed,
        byte_size=byte_size,
        sha256=sha256,
        cache_age_seconds=cache_age,
        failure_reason=result.error,
    )


def build_source_health_report(
    sources: list[SourceHealth],
    *,
    generated_at: str | None = None,
) -> SourceHealthReport:
    """
    Build a versioned source-health report from per-source records.

    Args:
        sources: One health record per configured URL.
        generated_at: Optional deterministic report timestamp for tests.

    Returns:
        SourceHealthReport with stable totals by status.
    """
    totals = {status: 0 for status in SOURCE_HEALTH_STATUSES}
    for source in sources:
        totals[source.status] = totals.get(source.status, 0) + 1

    return SourceHealthReport(
        schema_version=SOURCE_HEALTH_SCHEMA_VERSION,
        version=__version__,
        generated_at=generated_at or _utc_timestamp(),
        source_count=len(sources),
        totals_by_status=totals,
        sources=sources,
    )


def _safe_non_negative_int(value: object) -> int:
    """Return a non-negative integer from trusted JSON-style numeric values."""
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return max(0, value)


def _zero_source_health_totals() -> dict[str, int]:
    """Return a stable zero-filled source-health status dictionary."""
    return {status: 0 for status in SOURCE_HEALTH_STATUSES}


def _compact_source_health_report_path(
    report_path: str | Path | None,
    *,
    base_dir: str | Path | None = None,
) -> str | None:
    """Return a compact report reference that never serializes absolute or parent paths."""
    if report_path is None:
        return None

    report_path_text = str(report_path).strip()
    if not report_path_text:
        return None

    path = Path(report_path_text)
    if ".." in path.parts:
        msg = "source-health report path must not contain '..' segments"
        raise ValueError(msg)

    if path.is_absolute():
        root = Path.cwd() if base_dir is None else Path(base_dir)
        try:
            relative = path.resolve(strict=False).relative_to(root.resolve(strict=False))
        except ValueError:
            if "reports" in path.parts:
                reports_index = path.parts.index("reports")
                return Path(*path.parts[reports_index:]).as_posix()
            return path.name
        if ".." in relative.parts:
            msg = "source-health report path must not resolve outside the base directory"
            raise ValueError(msg)
        return relative.as_posix()

    return path.as_posix()


def _report_schema_version(
    report: SourceHealthReport | Mapping[str, object],
) -> int | None:
    """Return a report schema version when the source-health object exposes one."""
    if isinstance(report, SourceHealthReport):
        return report.schema_version

    schema_version = report.get("schema_version")
    if isinstance(schema_version, bool) or not isinstance(schema_version, int):
        return None
    return schema_version


def _report_source_count(report: SourceHealthReport | Mapping[str, object]) -> int:
    """Return source_count from a SourceHealthReport or JSON report dictionary."""
    if isinstance(report, SourceHealthReport):
        return max(0, report.source_count)

    source_count = _safe_non_negative_int(report.get("source_count"))
    if source_count:
        return source_count

    sources = report.get("sources")
    return len(sources) if isinstance(sources, list) else 0


def _report_totals_by_status(
    report: SourceHealthReport | Mapping[str, object],
) -> dict[str, int]:
    """Return status totals without exposing any per-source diagnostics."""
    raw_totals: Mapping[str, object]
    if isinstance(report, SourceHealthReport):
        raw_totals = report.totals_by_status
    else:
        totals = report.get("totals_by_status")
        raw_totals = totals if isinstance(totals, Mapping) else {}

    return {
        status: _safe_non_negative_int(raw_totals.get(status, 0))
        for status in SOURCE_HEALTH_STATUSES
    }


def _report_total_byte_size(report: SourceHealthReport | Mapping[str, object]) -> int:
    """Return aggregate byte size from rich source records without copying them."""
    if isinstance(report, SourceHealthReport):
        return sum(max(0, source.byte_size) for source in report.sources)

    sources = report.get("sources")
    if not isinstance(sources, list):
        return 0

    total = 0
    for source in sources:
        if isinstance(source, Mapping):
            total += _safe_non_negative_int(source.get("byte_size"))
    return total


def source_health_runtime_summary(
    report: SourceHealthReport | Mapping[str, object] | None,
    report_path: str | Path | None = None,
    *,
    base_dir: str | Path | None = None,
) -> SourceHealthRuntimeSummary:
    """
    Return compact source-health/cache evidence for default runtime stats.

    The rich ``SourceHealthReport.sources`` records remain in the source-health
    sidecar. This summary intentionally exposes only aggregate counts and a safe
    report reference.
    """
    compact_report_path = _compact_source_health_report_path(
        report_path,
        base_dir=base_dir,
    )
    if report is None:
        return {
            "available": False,
            "report_path": compact_report_path,
            "schema_version": None,
            "source_count": 0,
            "totals_by_status": _zero_source_health_totals(),
            "cache_backed_sources": 0,
            "failed_sources": 0,
            "total_byte_size": 0,
        }

    totals = _report_totals_by_status(report)
    return {
        "available": True,
        "report_path": compact_report_path,
        "schema_version": _report_schema_version(report),
        "source_count": _report_source_count(report),
        "totals_by_status": totals,
        "cache_backed_sources": (
            totals["validated_cache"] + totals["fallback_cache"] + totals["stale_cache"]
        ),
        "failed_sources": totals["failed"],
        "total_byte_size": _report_total_byte_size(report),
    }


def _source_health_report_to_dict(report: SourceHealthReport) -> dict[str, object]:
    """Convert a SourceHealthReport into a JSON object shape."""
    return {
        "schema_version": report.schema_version,
        "version": report.version,
        "generated_at": report.generated_at,
        "source_count": report.source_count,
        "totals_by_status": report.totals_by_status,
        "sources": [source._asdict() for source in report.sources],
    }


def save_source_health_report(
    report: SourceHealthReport,
    output_path: str | Path,
) -> None:
    """
    Save a source-health report atomically.

    Args:
        report: Report to write.
        output_path: Destination JSON path.

    Raises:
        OSError: If the report cannot be written.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(".tmp")

    with open(temp_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(_source_health_report_to_dict(report), f, indent=2, sort_keys=True)
        f.write("\n")

    temp_path.replace(path)


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
                        await _copy_cache_to_output(cache_path, output_path)
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
                        await _copy_cache_to_output(cache_path, output_path)
                        return FetchResult(
                            url,
                            success=True,
                            changed=False,
                            error=f"HTTP {response.status}, using cached version"
                        )
                    return FetchResult(
                        url,
                        success=False,
                        changed=False,
                        error=f"HTTP {response.status}",
                    )

                # Successful response - stream into cache first, then promote to raw output.
                await _stream_response_to_file(response, cache_path)
                await _copy_cache_to_output(cache_path, output_path)

                # Update state with new ETag/Last-Modified
                new_state: dict[str, str] = {}
                if "ETag" in response.headers:
                    new_state["etag"] = response.headers["ETag"]
                if "Last-Modified" in response.headers:
                    new_state["last_modified"] = response.headers["Last-Modified"]
                new_state["filename"] = filename
                new_state["fetched_at"] = _utc_timestamp()
                state[url] = new_state

                return FetchResult(url, success=True, changed=True)

        except TimeoutError:
            if attempt < retries - 1:
                await asyncio.sleep(2 ** attempt)
                continue
            # Fallback to cache
            if cache_path.exists():
                await _copy_cache_to_output(cache_path, output_path)
                return FetchResult(
                    url,
                    success=True,
                    changed=False,
                    error="Timeout, using cached version",
                )
            return FetchResult(url, success=False, changed=False, error="Timeout")

        except Exception as e:
            if attempt < retries - 1:
                await asyncio.sleep(2 ** attempt)
                continue
            # Fallback to cache
            if cache_path.exists():
                try:
                    await _copy_cache_to_output(cache_path, output_path)
                    return FetchResult(
                        url,
                        success=True,
                        changed=False,
                        error=f"{e}, using cached version",
                    )
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
            final_results.append(
                FetchResult(urls[i], success=False, changed=False, error=str(result))
            )
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
    parser.add_argument(
        "--concurrency",
        type=int,
        default=DEFAULT_CONCURRENCY,
        help="Max concurrent downloads",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help="Request timeout in seconds",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=DEFAULT_RETRIES,
        help="Number of retries per URL",
    )
    parser.add_argument(
        "--health-report",
        metavar="PATH",
        help="Write per-source health report JSON to PATH",
    )

    args = parser.parse_args()

    # Load sources
    urls = load_sources(args.sources)
    if not urls:
        print("No URLs found in sources file", file=sys.stderr)
        return 1

    print(f"🔄 Fetching {len(urls)} sources...")

    # Run async fetch
    output_dir = Path(args.outdir)
    cache_dir = Path(args.cache)
    results = asyncio.run(fetch_all(
        urls,
        output_dir,
        cache_dir,
        args.concurrency,
        args.timeout,
        args.retries,
    ))

    if args.health_report:
        state = load_state(cache_dir)
        now = time.time()
        health_sources = [
            source_health_from_fetch_result(result, output_dir, cache_dir, state, now=now)
            for result in results
        ]
        report = build_source_health_report(health_sources)
        try:
            save_source_health_report(report, args.health_report)
        except OSError as e:
            print(f"ERROR: Could not write source health report: {e}", file=sys.stderr)
            return 1
        print(f"🩺 Source health report: {args.health_report}")

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

    return 0


if __name__ == "__main__":
    sys.exit(main())
