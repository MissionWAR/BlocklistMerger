"""
scripts package - AdGuard Home Blocklist Compiler

Modules:
    fetch_sources: Download blocklists with ETag/Last-Modified caching
    cleaner: Clean and validate rules for AGH compatibility
    compiler: Modifier-aware deduplication
    pipeline: Main processing pipeline
"""

__version__ = "1.0.0"
