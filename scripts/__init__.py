"""
scripts package - AdGuard Home Blocklist Compiler

A high-performance blocklist compiler that merges 80+ DNS blocklists into a single,
deduplicated output optimized for AdGuard Home.

Modules:
    downloader: Async blocklist downloader with ETag/Last-Modified caching
    cleaner: Rule filtering and validation for AdGuard Home compatibility
    compiler: Format compression and modifier-aware deduplication engine
    pipeline: Main processing pipeline orchestrator

Example:
    >>> from scripts.pipeline import process_files
    >>> stats = process_files("lists/_raw", "lists/merged.txt")
"""

from typing import Final

__version__: Final[str] = "1.3.0"
__author__: Final[str] = "MissionWAR"

__all__ = [
    "__version__",
    "__author__",
    "downloader",
    "cleaner", 
    "compiler",
    "pipeline",
]
