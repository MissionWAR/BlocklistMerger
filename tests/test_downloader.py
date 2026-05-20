#!/usr/bin/env python3
"""
test_downloader.py

Tests for the downloader module's helper functions.
Tests pure functions (url_to_filename, load_sources, load_state, save_state)
without making real HTTP requests.
"""
import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

import scripts.downloader as downloader
from scripts.downloader import (
    FetchResult,
    SourceHealth,
    SourceHealthReport,
    build_source_health_report,
    load_sources,
    load_state,
    save_source_health_report,
    save_state,
    source_health_from_fetch_result,
    url_to_filename,
)


class TestUrlToFilename:
    """Test URL to filename conversion."""

    def test_basic_url(self):
        """Should produce a deterministic .txt filename."""
        result = url_to_filename("https://example.com/blocklist.txt")
        assert result.endswith(".txt")
        assert len(result) > 10  # Has hash component

    def test_deterministic(self):
        """Same URL should always produce the same filename."""
        url = "https://example.com/list.txt"
        assert url_to_filename(url) == url_to_filename(url)

    def test_different_urls_different_names(self):
        """Different URLs should produce different filenames."""
        name1 = url_to_filename("https://example.com/list1.txt")
        name2 = url_to_filename("https://example.com/list2.txt")
        assert name1 != name2

    def test_domain_in_filename(self):
        """Domain should be included for readability."""
        result = url_to_filename("https://example.com/blocklist.txt")
        assert "example_com" in result

    def test_long_domain_truncated(self):
        """Very long domains should be truncated."""
        result = url_to_filename("https://very-long-subdomain.very-long-domain.example.com/list.txt")
        # Domain part should be at most 30 chars
        domain_part = result.rsplit("_", 1)[0]
        assert len(domain_part) <= 30


class TestLoadSources:
    """Test source file loading."""

    def test_basic_loading(self):
        """Should load URLs from a file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("https://example.com/list1.txt\n")
            f.write("https://example.com/list2.txt\n")
        try:
            urls = load_sources(f.name)
            assert len(urls) == 2
            assert "https://example.com/list1.txt" in urls
        finally:
            os.unlink(f.name)

    def test_comments_skipped(self):
        """Lines starting with # should be skipped."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("# This is a comment\n")
            f.write("https://example.com/list.txt\n")
            f.write("# Another comment\n")
        try:
            urls = load_sources(f.name)
            assert len(urls) == 1
            assert urls[0] == "https://example.com/list.txt"
        finally:
            os.unlink(f.name)

    def test_empty_lines_skipped(self):
        """Empty/whitespace lines should be skipped."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n")
            f.write("  \n")
            f.write("https://example.com/list.txt\n")
            f.write("\n")
        try:
            urls = load_sources(f.name)
            assert len(urls) == 1
        finally:
            os.unlink(f.name)

    def test_missing_file_returns_empty(self):
        """Non-existent file should return empty list, not crash."""
        urls = load_sources("/nonexistent/sources.txt")
        assert urls == []

    def test_inline_comments_stripped(self):
        """Inline comments should be stripped from URLs."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("https://example.com/list.txt # main blocklist\n")
        try:
            urls = load_sources(f.name)
            assert len(urls) == 1
            assert urls[0] == "https://example.com/list.txt"
        finally:
            os.unlink(f.name)


class TestLoadState:
    """Test state file loading."""

    def test_load_existing_state(self):
        """Should load valid state.json."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            state_data = {
                "https://example.com/list.txt": {
                    "etag": '"abc123"',
                    "last_modified": "Mon, 01 Jan 2025 00:00:00 GMT",
                }
            }
            with open(state_path, "w") as f:
                json.dump(state_data, f)

            state = load_state(Path(tmpdir))
            assert "https://example.com/list.txt" in state
            assert state["https://example.com/list.txt"]["etag"] == '"abc123"'

    def test_missing_state_returns_empty(self):
        """Missing state.json should return empty dict."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state = load_state(Path(tmpdir))
            assert state == {}

    def test_corrupt_state_returns_empty(self):
        """Corrupt state.json should return empty dict, not crash."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            with open(state_path, "w") as f:
                f.write("{ invalid json }")

            state = load_state(Path(tmpdir))
            assert state == {}


class TestSaveState:
    """Test state file saving."""

    def test_save_and_load_roundtrip(self):
        """Saved state should be loadable."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state = {
                "https://example.com/list.txt": {
                    "etag": '"xyz789"',
                }
            }
            save_state(Path(tmpdir), state)

            loaded = load_state(Path(tmpdir))
            assert loaded == state

    def test_atomic_write(self):
        """Save should use atomic write (no .tmp file left behind)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            save_state(Path(tmpdir), {"test": {"key": "value"}})

            files = os.listdir(tmpdir)
            assert "state.json" in files
            assert "state.tmp" not in files


class TestFetchResult:
    """Test FetchResult named tuple."""

    def test_success_result(self):
        result = FetchResult("https://example.com", True, True)
        assert result.url == "https://example.com"
        assert result.success
        assert result.changed
        assert result.error is None

    def test_error_result(self):
        result = FetchResult("https://example.com", False, False, "timeout")
        assert not result.success
        assert result.error == "timeout"


class TestSourceHealth:
    """Test per-source health records derived from fetch outcomes."""

    def test_fresh_fetch_records_content_identity(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            url = "https://example.com/fresh.txt"
            output_dir = Path(tmpdir) / "out"
            cache_dir = Path(tmpdir) / "cache"
            output_dir.mkdir()
            cache_dir.mkdir()
            content = b"fresh content\n"
            filename = url_to_filename(url)
            (output_dir / filename).write_bytes(content)

            health = source_health_from_fetch_result(
                FetchResult(url, success=True, changed=True),
                output_dir,
                cache_dir,
                {url: {"fetched_at": "2026-05-17T15:00:00Z"}},
                now=1779030000,
            )

            assert health.url == url
            assert health.filename == filename
            assert health.status == "fresh_fetch"
            assert health.changed is True
            assert health.byte_size == len(content)
            assert (
                health.sha256
                == "aded7777eeac966af185f2b048d53fda75c4b4eac1950590e3c7ceb178671691"
            )
            assert health.cache_age_seconds is None
            assert health.failure_reason is None

    def test_validated_cache_records_cache_age_when_state_has_timestamp(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            url = "https://example.com/cached.txt"
            output_dir = Path(tmpdir) / "out"
            cache_dir = Path(tmpdir) / "cache"
            output_dir.mkdir()
            cache_dir.mkdir()
            filename = url_to_filename(url)
            (output_dir / filename).write_bytes(b"cached content\n")

            health = source_health_from_fetch_result(
                FetchResult(url, success=True, changed=False),
                output_dir,
                cache_dir,
                {url: {"fetched_at": "2026-05-17T15:00:00Z"}},
                now=1779030120,
            )

            assert health.status == "validated_cache"
            assert health.changed is False
            assert health.cache_age_seconds == 120
            assert health.failure_reason is None

    @pytest.mark.parametrize(
        "fetched_at, expected_status, expected_age",
        [
            ("2026-05-17T15:00:00Z", "fallback_cache", 60),
            ("2026-05-15T14:59:59Z", "stale_cache", 172_861),
            (None, "stale_cache", None),
        ],
        ids=["recent-cache", "over-threshold-cache", "timestamp-missing-cache"],
    )
    def test_error_fallback_cache_status_reflects_freshness(
        self, fetched_at, expected_status, expected_age
    ):
        with tempfile.TemporaryDirectory() as tmpdir:
            url = "https://example.com/fallback.txt"
            output_dir = Path(tmpdir) / "out"
            cache_dir = Path(tmpdir) / "cache"
            output_dir.mkdir()
            cache_dir.mkdir()
            filename = url_to_filename(url)
            (output_dir / filename).write_bytes(b"fallback content\n")
            state = {url: {"fetched_at": fetched_at}} if fetched_at else {url: {}}

            health = source_health_from_fetch_result(
                FetchResult(url, success=True, changed=False, error="HTTP 500"),
                output_dir,
                cache_dir,
                state,
                now=1779030060,
            )

            assert health.status == expected_status
            assert health.cache_age_seconds == expected_age
            assert health.failure_reason == "HTTP 500"

    def test_failed_source_records_failure_without_content_identity(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            url = "https://example.com/missing.txt"
            output_dir = Path(tmpdir) / "out"
            cache_dir = Path(tmpdir) / "cache"
            output_dir.mkdir()
            cache_dir.mkdir()

            health = source_health_from_fetch_result(
                FetchResult(url, success=False, changed=False, error="Timeout"),
                output_dir,
                cache_dir,
                {},
                now=1779030060,
            )

            assert health.status == "failed"
            assert health.changed is False
            assert health.byte_size == 0
            assert health.sha256 is None
            assert health.cache_age_seconds is None
            assert health.failure_reason == "Timeout"


class TestSourceHealthReport:
    """Test source-health report schema and atomic JSON writing."""

    def test_save_source_health_report_writes_versioned_totals(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sources = [
                SourceHealth(
                    url="https://example.com/fresh.txt",
                    filename="fresh.txt",
                    status="fresh_fetch",
                    changed=True,
                    byte_size=12,
                    sha256="abc",
                    cache_age_seconds=None,
                    failure_reason=None,
                ),
                SourceHealth(
                    url="https://example.com/failed.txt",
                    filename="failed.txt",
                    status="failed",
                    changed=False,
                    byte_size=0,
                    sha256=None,
                    cache_age_seconds=None,
                    failure_reason="HTTP 500",
                ),
            ]
            report = build_source_health_report(
                sources,
                generated_at="2026-05-17T15:00:00Z",
            )
            output_path = Path(tmpdir) / "reports" / "source-health.json"

            assert isinstance(report, SourceHealthReport)

            save_source_health_report(report, output_path)

            data = json.loads(output_path.read_text(encoding="utf-8"))
            assert data["schema_version"] == 1
            assert data["version"] == "1.5.0"
            assert data["generated_at"] == "2026-05-17T15:00:00Z"
            assert data["source_count"] == 2
            assert data["totals_by_status"] == {
                "failed": 1,
                "fallback_cache": 0,
                "fresh_fetch": 1,
                "stale_cache": 0,
                "validated_cache": 0,
            }
            assert [source["url"] for source in data["sources"]] == [
                "https://example.com/fresh.txt",
                "https://example.com/failed.txt",
            ]
            assert {
                "url",
                "filename",
                "status",
                "changed",
                "byte_size",
                "sha256",
                "cache_age_seconds",
                "failure_reason",
            } <= set(data["sources"][0])
            assert not output_path.with_suffix(".tmp").exists()

    def test_cli_health_report_mode_writes_report_without_legacy_failure_gate(
        self, monkeypatch, tmp_path
    ):
        urls = [f"https://example.com/list-{index}.txt" for index in range(5)]
        sources_file = tmp_path / "sources.txt"
        sources_file.write_text("\n".join(urls), encoding="utf-8")
        output_dir = tmp_path / "raw"
        cache_dir = tmp_path / "cache"
        report_path = tmp_path / "reports" / "source-health.json"

        async def fake_fetch_all(urls, output_dir, cache_dir, concurrency, timeout, retries):
            output_dir.mkdir(parents=True, exist_ok=True)
            cache_dir.mkdir(parents=True, exist_ok=True)
            filename = url_to_filename(urls[0])
            (output_dir / filename).write_bytes(b"only successful source\n")
            return [
                FetchResult(urls[0], success=True, changed=True),
                *[
                    FetchResult(url, success=False, changed=False, error="HTTP 500")
                    for url in urls[1:]
                ],
            ]

        monkeypatch.setattr(downloader, "fetch_all", fake_fetch_all)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "scripts.downloader",
                "--sources",
                str(sources_file),
                "--outdir",
                str(output_dir),
                "--cache",
                str(cache_dir),
                "--health-report",
                str(report_path),
            ],
        )

        assert downloader.main() == 0

        data = json.loads(report_path.read_text(encoding="utf-8"))
        assert data["source_count"] == 5
        assert [source["url"] for source in data["sources"]] == urls
        assert data["totals_by_status"]["fresh_fetch"] == 1
        assert data["totals_by_status"]["failed"] == 4


class _FakeResponseContent:
    def __init__(
        self,
        chunks: list[bytes],
        *,
        error_after_chunks: int | None = None,
    ) -> None:
        self._chunks = chunks
        self._error_after_chunks = error_after_chunks
        self.iter_chunked_sizes: list[int] = []

    async def iter_chunked(self, chunk_size: int):
        self.iter_chunked_sizes.append(chunk_size)
        for index, chunk in enumerate(self._chunks):
            if self._error_after_chunks is not None and index >= self._error_after_chunks:
                raise OSError("stream interrupted")
            yield chunk
        if self._error_after_chunks == len(self._chunks):
            raise OSError("stream interrupted")


class _FakeResponse:
    def __init__(
        self,
        status: int,
        *,
        chunks: list[bytes] | None = None,
        read_bytes: bytes = b"",
        headers: dict[str, str] | None = None,
        fail_on_read: bool = False,
        stream_error_after_chunks: int | None = None,
    ) -> None:
        self.status = status
        self.headers = headers or {}
        self.content = _FakeResponseContent(
            chunks if chunks is not None else [read_bytes],
            error_after_chunks=stream_error_after_chunks,
        )
        self._read_bytes = read_bytes
        self._fail_on_read = fail_on_read
        self.read_called = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        return None

    async def read(self) -> bytes:
        self.read_called = True
        if self._fail_on_read:
            raise AssertionError("D-01 success path must not call response.read()")
        return self._read_bytes


class _FakeSession:
    def __init__(self, outcomes: list[_FakeResponse | BaseException]) -> None:
        self._outcomes = list(outcomes)
        self.requests: list[dict[str, object]] = []

    def get(self, url, *, headers, timeout, allow_redirects):
        self.requests.append(
            {
                "url": url,
                "headers": headers,
                "timeout": timeout,
                "allow_redirects": allow_redirects,
            }
        )
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


class TestFetchUrlStreamingAtomicity:
    """Pin RUN-01 downloader streaming and atomic promotion behavior."""

    def test_d01_success_streams_chunks_without_response_read(self, tmp_path):
        url = "https://example.com/streamed.txt"
        output_dir = tmp_path / "raw"
        cache_dir = tmp_path / "cache"
        output_dir.mkdir()
        cache_dir.mkdir()
        response = _FakeResponse(
            200,
            chunks=[b"||one.example^\n", b"||two.example^\n"],
            fail_on_read=True,
            headers={"ETag": '"streamed"', "Last-Modified": "Mon, 18 May 2026 00:00:00 GMT"},
        )
        state: dict[str, dict[str, str]] = {}

        result = asyncio.run(
            downloader.fetch_url(
                _FakeSession([response]),
                url,
                output_dir,
                cache_dir,
                state,
                timeout=5,
                retries=1,
            )
        )

        filename = url_to_filename(url)
        expected = b"||one.example^\n||two.example^\n"
        assert result == FetchResult(url, success=True, changed=True)
        assert response.read_called is False
        assert response.content.iter_chunked_sizes
        assert (cache_dir / filename).read_bytes() == expected
        assert (output_dir / filename).read_bytes() == expected
        assert state[url]["etag"] == '"streamed"'

    def test_d02_partial_stream_failure_keeps_old_files_and_state(self, tmp_path):
        url = "https://example.com/partial.txt"
        output_dir = tmp_path / "raw"
        cache_dir = tmp_path / "cache"
        output_dir.mkdir()
        cache_dir.mkdir()
        filename = url_to_filename(url)
        old_cache = b"||old-cache.example^\n"
        old_raw = b"||old-raw.example^\n"
        (cache_dir / filename).write_bytes(old_cache)
        (output_dir / filename).write_bytes(old_raw)
        response = _FakeResponse(
            200,
            chunks=[b"||new-one.example^\n", b"||new-two.example^\n"],
            read_bytes=b"||unbounded-read-would-corrupt.example^\n",
            stream_error_after_chunks=1,
            headers={"ETag": '"new"'},
        )
        state = {
            url: {
                "etag": '"old"',
                "filename": filename,
                "fetched_at": "2026-05-17T00:00:00Z",
            }
        }

        result = asyncio.run(
            downloader.fetch_url(
                _FakeSession([response]),
                url,
                output_dir,
                cache_dir,
                state,
                timeout=5,
                retries=1,
            )
        )

        assert result.success is True
        assert result.changed is False
        assert result.error and "using cached version" in result.error
        assert (cache_dir / filename).read_bytes() == old_cache
        assert (output_dir / filename).read_bytes() == old_cache
        assert state == {
            url: {
                "etag": '"old"',
                "filename": filename,
                "fetched_at": "2026-05-17T00:00:00Z",
            }
        }
        assert list(cache_dir.glob("*.tmp")) == []
        assert list(output_dir.glob("*.tmp")) == []

    def test_d02_state_updates_only_after_cache_and_raw_replacement(
        self,
        monkeypatch,
        tmp_path,
    ):
        url = "https://example.com/state-order.txt"
        output_dir = tmp_path / "raw"
        cache_dir = tmp_path / "cache"
        output_dir.mkdir()
        cache_dir.mkdir()
        filename = url_to_filename(url)
        expected = b"||state-order.example^\n"
        response = _FakeResponse(
            200,
            chunks=[expected],
            read_bytes=expected,
            headers={"ETag": '"ordered"'},
        )
        observed = {"checked": False}

        def checked_timestamp() -> str:
            observed["checked"] = True
            assert (cache_dir / filename).read_bytes() == expected
            assert (output_dir / filename).read_bytes() == expected
            return "2026-05-18T00:00:00Z"

        monkeypatch.setattr(downloader, "_utc_timestamp", checked_timestamp)
        state: dict[str, dict[str, str]] = {}

        result = asyncio.run(
            downloader.fetch_url(
                _FakeSession([response]),
                url,
                output_dir,
                cache_dir,
                state,
                timeout=5,
                retries=1,
            )
        )

        assert result.success is True
        assert observed["checked"] is True
        assert state[url]["fetched_at"] == "2026-05-18T00:00:00Z"

    @pytest.mark.parametrize(
        ("case_name", "outcome", "expected_error"),
        [
            ("d03_304_validated_cache", _FakeResponse(304), None),
            ("d03_http_error_fallback_cache", _FakeResponse(503), "HTTP 503"),
            ("d03_timeout_fallback_cache", TimeoutError("timed out"), "Timeout"),
            ("d03_exception_fallback_cache", RuntimeError("boom"), "boom"),
        ],
    )
    def test_d03_cache_fallbacks_use_shared_bounded_copy_helper(
        self,
        monkeypatch,
        tmp_path,
        case_name,
        outcome,
        expected_error,
    ):
        url = f"https://example.com/{case_name}.txt"
        output_dir = tmp_path / "raw"
        cache_dir = tmp_path / "cache"
        output_dir.mkdir()
        cache_dir.mkdir()
        filename = url_to_filename(url)
        cached = b"||cached.example^\n"
        (cache_dir / filename).write_bytes(cached)
        calls: list[tuple[Path, Path]] = []

        async def spy_copy(source_path: Path, destination_path: Path) -> None:
            calls.append((source_path, destination_path))
            destination_path.write_bytes(source_path.read_bytes())

        monkeypatch.setattr(downloader, "_copy_file_bounded", spy_copy)

        result = asyncio.run(
            downloader.fetch_url(
                _FakeSession([outcome]),
                url,
                output_dir,
                cache_dir,
                state={url: {"etag": '"cached"', "fetched_at": "2026-05-17T00:00:00Z"}},
                timeout=5,
                retries=1,
            )
        )

        assert result.success is True
        assert result.changed is False
        assert calls == [(cache_dir / filename, output_dir / filename)]
        assert (output_dir / filename).read_bytes() == cached
        if expected_error is None:
            assert result.error is None
        else:
            assert result.error and expected_error in result.error

    def test_d04_d05_no_source_size_or_content_type_gate_on_success(self, tmp_path):
        url = "https://example.com/odd-content-type.txt"
        output_dir = tmp_path / "raw"
        cache_dir = tmp_path / "cache"
        output_dir.mkdir()
        cache_dir.mkdir()
        body = b"||accepted-without-hard-gate.example^\n"
        response = _FakeResponse(
            200,
            chunks=[body],
            read_bytes=body,
            headers={"Content-Type": "application/octet-stream"},
        )

        result = asyncio.run(
            downloader.fetch_url(
                _FakeSession([response]),
                url,
                output_dir,
                cache_dir,
                state={},
                timeout=5,
                retries=1,
            )
        )

        assert result.success is True
        assert result.changed is True
        assert (output_dir / url_to_filename(url)).read_bytes() == body


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
