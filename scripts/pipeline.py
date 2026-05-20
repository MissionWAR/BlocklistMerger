#!/usr/bin/env python3
"""
pipeline.py - Main Processing Pipeline for Blocklist Compilation

This is the orchestrator that ties together the cleaning and compilation stages.
It reads raw blocklist files, processes them through the pipeline, and outputs
a unified, deduplicated blocklist.

Pipeline Stages:
    1. **Read**: Load all .txt files from input directory
    2. **Clean**: Remove comments, cosmetic rules, unsupported modifiers
    3. **Compile**: Compress formats, deduplicate, prune subdomains
    4. **Write**: Output merged blocklist with statistics

Usage:
    python -m scripts.pipeline <input_dir> <output_file>

Example:
    >>> from scripts.pipeline import process_files
    >>> stats = process_files("lists/_raw", "lists/merged.txt")
    >>> print(f"Output {stats['lines_output']:,} rules")
"""

import json
import os
import sys
import time
import tracemalloc
from collections.abc import Iterator
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Final, NamedTuple, TypedDict

from scripts import __version__
from scripts.cleaner import (
    DISCARD_REASON_COMMENT,
    DISCARD_REASON_COSMETIC,
    DISCARD_REASON_EMPTY,
    DISCARD_REASON_INVALID,
    DISCARD_REASON_UNSUPPORTED_MODIFIER,
    DISCARD_REASON_URL_PATH,
    clean_line,
)
from scripts.compiler import CompileStats, compile_rules

# =============================================================================
# CONFIGURATION CONSTANTS
# =============================================================================

PIPELINE_STATS_SCHEMA_VERSION: Final[int] = 2

# =============================================================================
# DATA STRUCTURES
# =============================================================================

class PipelineStats(TypedDict):
    """
    Statistics collected during pipeline execution.

    Provides detailed metrics about each stage of processing,
    useful for monitoring and debugging.
    """
    files_processed: int
    lines_raw: int
    lines_clean: int
    lines_output: int
    comments_removed: int
    cosmetic_removed: int
    unsupported_removed: int
    empty_removed: int
    url_path_removed: int
    invalid_removed: int
    trimmed: int
    abp_subdomain_pruned: int
    tld_wildcard_pruned: int
    duplicate_pruned: int
    whitelist_conflict_pruned: int
    local_hostname_pruned: int
    formats_compressed: int
    malformed_discarded: int
    abp_kept: int
    other_kept: int


class StageDurations(TypedDict):
    """Coarse runtime durations for the pipeline stages."""

    clean_seconds: float
    compile_seconds: float


class ByteSizes(TypedDict):
    """Runtime byte-size observations for pipeline inputs and output."""

    raw_input_bytes: int
    output_bytes: int


class CompilerCardinalities(TypedDict):
    """Inspect-only sizes of compiler structures after parsing."""

    abp_rule_keys: int
    abp_wildcard_keys: int
    exception_rule_keys: int
    duplicate_index_size: int
    other_rule_count: int


class MemoryProfile(TypedDict):
    """Best-effort memory observations for the current process."""

    tracemalloc_current_bytes: int | None
    tracemalloc_peak_bytes: int | None
    resource_ru_maxrss: int | None


class RuntimeProfile(TypedDict):
    """Inspect-only runtime profile stored in the pipeline stats report."""

    worker_count: int | None
    stage_durations_seconds: StageDurations
    byte_sizes: ByteSizes
    compiler_cardinalities: CompilerCardinalities
    memory: MemoryProfile


class CleanWorkerResult(NamedTuple):
    """
    Bounded metadata returned from a cleaning worker.

    The cleaned rule payload stays in the spool file so process results do not
    serialize a full cleaned list back to the parent process.
    """
    source_index: int
    spool_path: Path
    stats: dict[str, int]


class PipelineRunResult(NamedTuple):
    """Pipeline stats paired with inspect-only runtime profile data."""

    stats: PipelineStats
    runtime_profile: RuntimeProfile


CLEANER_REASON_STAT_KEYS: Final[dict[str, str]] = {
    DISCARD_REASON_COMMENT: "comments_removed",
    DISCARD_REASON_COSMETIC: "cosmetic_removed",
    DISCARD_REASON_UNSUPPORTED_MODIFIER: "unsupported_removed",
    DISCARD_REASON_EMPTY: "empty_removed",
    DISCARD_REASON_URL_PATH: "url_path_removed",
    DISCARD_REASON_INVALID: "invalid_removed",
}


# =============================================================================
# WORKER FUNCTIONS
# =============================================================================

def _new_clean_file_stats() -> dict[str, int]:
    """Return a fresh cleaner stats dictionary for one source file."""
    return {
        "lines_raw": 0,
        "lines_clean": 0,
        "comments_removed": 0,
        "cosmetic_removed": 0,
        "unsupported_removed": 0,
        "empty_removed": 0,
        "url_path_removed": 0,
        "invalid_removed": 0,
        "trimmed": 0,
    }


def _cleaner_worker_count() -> int | None:
    """Return the worker count used for process-pool cleaning."""
    return os.cpu_count()


def _clean_single_file_to_spool(
    source_index: int,
    file_path: Path,
    spool_dir: Path,
) -> CleanWorkerResult:
    """Clean a single file into a bounded spool and return only metadata."""
    file_stats = _new_clean_file_stats()
    spool_path = spool_dir / f"{source_index:08d}.txt"

    try:
        with (
            open(file_path, encoding="utf-8-sig", errors="replace") as src,
            open(spool_path, "w", encoding="utf-8", newline="\n") as dst,
        ):
            for line in src:
                file_stats["lines_raw"] += 1
                result, was_trimmed = clean_line(line)

                if was_trimmed:
                    file_stats["trimmed"] += 1

                if result.discarded:
                    if result.reason not in CLEANER_REASON_STAT_KEYS:
                        raise ValueError(f"Unknown cleaner discard reason: {result.reason!r}")
                    file_stats[CLEANER_REASON_STAT_KEYS[result.reason]] += 1
                else:
                    if result.line is None:
                        raise ValueError("Cleaner returned no line for a kept rule")
                    dst.write(result.line + "\n")
                    file_stats["lines_clean"] += 1
    except Exception:
        spool_path.unlink(missing_ok=True)
        raise

    return CleanWorkerResult(source_index, spool_path, file_stats)


def _clean_files_to_spools(files: list[Path], spool_dir: Path) -> dict[int, CleanWorkerResult]:
    """Run cleaner workers and return their spool metadata keyed by source index."""
    results: dict[int, CleanWorkerResult] = {}
    worker_count = _cleaner_worker_count()

    # Use optimal number of workers (max cores) while keeping parent results bounded.
    with ProcessPoolExecutor(max_workers=worker_count) as executor:
        futures = [
            executor.submit(_clean_single_file_to_spool, source_index, file_path, spool_dir)
            for source_index, file_path in enumerate(files)
        ]
        for future in as_completed(futures):
            result = future.result()
            results[result.source_index] = result

    return results


def _merge_file_stats(stats: PipelineStats, file_stats: dict[str, int]) -> None:
    """Transfer one worker's file stats into aggregate pipeline stats."""
    stats["lines_raw"] += file_stats["lines_raw"]
    stats["comments_removed"] += file_stats["comments_removed"]
    stats["cosmetic_removed"] += file_stats["cosmetic_removed"]
    stats["unsupported_removed"] += file_stats["unsupported_removed"]
    stats["empty_removed"] += file_stats["empty_removed"]
    stats["url_path_removed"] += file_stats["url_path_removed"]
    stats["invalid_removed"] += file_stats["invalid_removed"]
    stats["trimmed"] += file_stats["trimmed"]
    stats["lines_clean"] += file_stats["lines_clean"]


def _iter_spool_lines(spool_path: Path) -> Iterator[str]:
    """Yield cleaned lines from a worker spool without loading the whole file."""
    with open(spool_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            yield line.rstrip("\n")


def _new_pipeline_stats() -> PipelineStats:
    """Return a fresh aggregate pipeline stats dictionary."""
    return {
        "files_processed": 0,
        "lines_raw": 0,
        "lines_clean": 0,
        "lines_output": 0,
        "comments_removed": 0,
        "cosmetic_removed": 0,
        "unsupported_removed": 0,
        "empty_removed": 0,
        "url_path_removed": 0,
        "invalid_removed": 0,
        "trimmed": 0,
        "abp_subdomain_pruned": 0,
        "tld_wildcard_pruned": 0,
        "duplicate_pruned": 0,
        "whitelist_conflict_pruned": 0,
        "local_hostname_pruned": 0,
        "formats_compressed": 0,
        "malformed_discarded": 0,
        "abp_kept": 0,
        "other_kept": 0,
    }


def _compiler_cardinalities(compile_stats: CompileStats) -> CompilerCardinalities:
    """Return compiler cardinalities from a CompileStats instance."""
    return {
        "abp_rule_keys": compile_stats.abp_rule_keys,
        "abp_wildcard_keys": compile_stats.abp_wildcard_keys,
        "exception_rule_keys": compile_stats.exception_rule_keys,
        "duplicate_index_size": compile_stats.duplicate_index_size,
        "other_rule_count": compile_stats.other_rule_count,
    }


def _empty_compiler_cardinalities() -> CompilerCardinalities:
    """Return zeroed compiler cardinalities for compatibility callers."""
    return {
        "abp_rule_keys": 0,
        "abp_wildcard_keys": 0,
        "exception_rule_keys": 0,
        "duplicate_index_size": 0,
        "other_rule_count": 0,
    }


def _memory_profile() -> MemoryProfile:
    """Return best-effort memory observations with graceful unsupported values."""
    tracemalloc_current_bytes: int | None = None
    tracemalloc_peak_bytes: int | None = None
    if tracemalloc.is_tracing():
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc_current_bytes = current
        tracemalloc_peak_bytes = peak

    resource_ru_maxrss: int | None = None
    try:
        import resource
    except ImportError:
        pass
    else:
        try:
            resource_ru_maxrss = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        except (AttributeError, OSError, ValueError):
            resource_ru_maxrss = None

    return {
        "tracemalloc_current_bytes": tracemalloc_current_bytes,
        "tracemalloc_peak_bytes": tracemalloc_peak_bytes,
        "resource_ru_maxrss": resource_ru_maxrss,
    }


def _empty_runtime_profile() -> RuntimeProfile:
    """Return a runtime profile shape for callers that do not collect one."""
    return {
        "worker_count": None,
        "stage_durations_seconds": {
            "clean_seconds": 0.0,
            "compile_seconds": 0.0,
        },
        "byte_sizes": {
            "raw_input_bytes": 0,
            "output_bytes": 0,
        },
        "compiler_cardinalities": _empty_compiler_cardinalities(),
        "memory": {
            "tracemalloc_current_bytes": None,
            "tracemalloc_peak_bytes": None,
            "resource_ru_maxrss": None,
        },
    }


# =============================================================================
# PIPELINE FUNCTIONS
# =============================================================================

def process_files(input_dir: str, output_file: str) -> PipelineStats:
    """
    Run the full pipeline on input directory.

    Orchestrates the complete blocklist compilation process:
    1. Reads all .txt files from input_dir
    2. Cleans each line (removes comments, cosmetic, unsupported modifiers)
    3. Compiles all lines (compresses formats, deduplicates)
    4. Writes output and returns statistics

    Args:
        input_dir: Directory containing raw blocklist files
        output_file: Path to output merged list

    Returns:
        PipelineStats with detailed metrics from all stages

    Raises:
        FileNotFoundError: If input_dir doesn't exist

    Example:
        >>> stats = process_files("lists/_raw", "lists/merged.txt")
        >>> print(f"Reduced {stats['lines_raw']:,} to {stats['lines_output']:,}")
    """
    return process_files_with_profile(input_dir, output_file).stats


def process_files_with_profile(input_dir: str, output_file: str) -> PipelineRunResult:
    """
    Run the full pipeline and return stats plus inspect-only runtime profile data.

    This keeps `process_files()` compatible for existing callers while the CLI can
    attach runtime-size observations to the versioned JSON report.
    """
    input_path = Path(input_dir)

    if not input_path.is_dir():
        raise FileNotFoundError(f"Input directory not found: {input_dir}")

    stats = _new_pipeline_stats()

    # =========================================================================
    # STAGE 1 & 2: Read, clean, compile, and deduplicate
    # =========================================================================
    print("📖 Stage 1 & 2: Reading, cleaning, compiling, and deduplicating...")
    pipeline_start = time.time()

    files = sorted(input_path.glob("*.txt"))
    stats["files_processed"] = len(files)
    raw_input_bytes = sum(file_path.stat().st_size for file_path in files)

    stop_tracemalloc = not tracemalloc.is_tracing()
    if stop_tracemalloc:
        tracemalloc.start()

    try:
        with TemporaryDirectory(prefix="blocklist-merger-clean-") as spool_dir_name:
            spool_dir = Path(spool_dir_name)
            clean_start = time.time()
            results = _clean_files_to_spools(files, spool_dir)
            clean_seconds = time.time() - clean_start

            def _get_cleaned_lines() -> Iterator[str]:
                try:
                    for source_index in range(len(files)):
                        result = results[source_index]
                        _merge_file_stats(stats, result.stats)
                        yield from _iter_spool_lines(result.spool_path)
                finally:
                    for result in results.values():
                        result.spool_path.unlink(missing_ok=True)

            compile_start = time.time()
            compile_stats = compile_rules(_get_cleaned_lines(), output_file)
            compile_seconds = time.time() - compile_start

        memory = _memory_profile()
    finally:
        if stop_tracemalloc:
            tracemalloc.stop()

    pipeline_time = time.time() - pipeline_start
    print(f"   Processed {stats['files_processed']} files, {stats['lines_raw']:,} raw lines")
    print(f"   Kept {stats['lines_clean']:,} clean rules")
    print(f"   Output: {compile_stats.total_output:,} rules ({pipeline_time:.1f}s)")

    # Transfer compilation stats
    stats["lines_output"] = compile_stats.total_output
    stats["abp_subdomain_pruned"] = compile_stats.abp_subdomain_pruned
    stats["tld_wildcard_pruned"] = compile_stats.tld_wildcard_pruned
    stats["duplicate_pruned"] = compile_stats.duplicate_pruned
    stats["whitelist_conflict_pruned"] = compile_stats.whitelist_conflict_pruned
    stats["local_hostname_pruned"] = compile_stats.local_hostname_pruned
    stats["formats_compressed"] = compile_stats.formats_compressed
    stats["malformed_discarded"] = compile_stats.malformed_discarded

    # Format breakdown
    stats["abp_kept"] = compile_stats.abp_kept
    stats["other_kept"] = compile_stats.other_kept

    runtime_profile: RuntimeProfile = {
        "worker_count": _cleaner_worker_count(),
        "stage_durations_seconds": {
            "clean_seconds": round(clean_seconds, 6),
            "compile_seconds": round(compile_seconds, 6),
        },
        "byte_sizes": {
            "raw_input_bytes": raw_input_bytes,
            "output_bytes": Path(output_file).stat().st_size if Path(output_file).exists() else 0,
        },
        "compiler_cardinalities": _compiler_cardinalities(compile_stats),
        "memory": memory,
    }

    return PipelineRunResult(stats, runtime_profile)


def print_summary(stats: PipelineStats) -> None:
    """
    Print formatted summary of pipeline execution.

    Displays a comprehensive breakdown of what was processed,
    what was removed at each stage, and the final output.

    Args:
        stats: PipelineStats from process_files()
    """
    print("\n" + "=" * 60)
    print("📊 PIPELINE SUMMARY")
    print("=" * 60)

    raw = stats["lines_raw"]
    clean = stats["lines_clean"]
    output = stats["lines_output"]

    # Calculate reductions
    clean_reduction = ((raw - clean) / max(raw, 1)) * 100
    compile_reduction = ((clean - output) / max(clean, 1)) * 100
    total_reduction = ((raw - output) / max(raw, 1)) * 100

    print(f"\n📁 Files:  {stats['files_processed']}")
    print("\n📈 Lines:")
    print(f"   Raw input:    {raw:>12,}")
    print(f"   After clean:  {clean:>12,} (-{clean_reduction:.1f}%)")
    print(f"   Final output: {output:>12,} (-{compile_reduction:.1f}% from clean)")
    print(f"   Total reduction: {total_reduction:.1f}%")

    print("\n🧹 Cleaning removed:")
    print(f"   Comments:          {stats['comments_removed']:>10,}")
    print(f"   Cosmetic rules:    {stats['cosmetic_removed']:>10,}")
    print(f"   Unsupported mods:  {stats['unsupported_removed']:>10,}")
    print(f"   Empty lines:       {stats['empty_removed']:>10,}")
    print(f"   URL paths:         {stats['url_path_removed']:>10,}")
    print(f"   Invalid rules:     {stats['invalid_removed']:>10,}")
    print(f"   Trimmed:           {stats['trimmed']:>10,}")

    print("\n🔧 Compilation pruned:")
    print(f"   ABP subdomains:    {stats['abp_subdomain_pruned']:>10,}")
    print(f"   TLD wildcards:     {stats['tld_wildcard_pruned']:>10,}")
    print(f"   Duplicates:        {stats['duplicate_pruned']:>10,}")
    print(f"   Whitelist conflict:{stats['whitelist_conflict_pruned']:>10,}")
    print(f"   Local hostnames:   {stats['local_hostname_pruned']:>10,}")
    print(f"   Malformed rules:   {stats['malformed_discarded']:>10,}")

    print("\n📦 Output breakdown:")
    print(
        f"   ABP rules:   {stats['abp_kept']:>10,} "
        f"(incl. {stats['formats_compressed']:,} compressed)"
    )
    print(f"   Other rules: {stats['other_kept']:>10,}")


def save_stats_json(
    stats: PipelineStats,
    output_path: str,
    total_time: float,
    runtime_profile: RuntimeProfile | None = None,
) -> None:
    """
    Save pipeline statistics to a JSON file.

    Args:
        stats: Pipeline statistics dictionary
        output_path: Path to write JSON file
        total_time: Total execution time in seconds
        runtime_profile: Optional runtime-size observations for this run
    """
    output = {
        "schema_version": PIPELINE_STATS_SCHEMA_VERSION,
        "version": __version__,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "execution_time_seconds": round(total_time, 2),
        "statistics": dict(stats),
        "runtime_profile": runtime_profile or _empty_runtime_profile(),
    }

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(".tmp")
    with open(temp_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(output, f, indent=2, sort_keys=True)
    temp_path.replace(path)


# =============================================================================
# CLI INTERFACE
# =============================================================================

def main() -> int:
    """
    Main entry point for CLI usage.

    Returns:
        Exit code (0 for success, 1 for error, 2 for usage error)
    """
    import argparse

    parser = argparse.ArgumentParser(
        prog="scripts.pipeline",
        description="Blocklist compilation pipeline — clean, compress, and deduplicate.",
    )
    parser.add_argument("input_dir", help="Directory containing raw blocklist .txt files")
    parser.add_argument("output_file", help="Path for the merged output file")
    parser.add_argument(
        "--json-stats", dest="json_stats", metavar="PATH",
        help="Save detailed statistics to a JSON file",
    )

    parsed = parser.parse_args()
    input_dir = parsed.input_dir
    output_file = parsed.output_file
    json_stats_path = parsed.json_stats

    try:
        print("🚀 Starting blocklist pipeline...")
        print("-" * 60)

        start_time = time.time()
        result = process_files_with_profile(input_dir, output_file)
        stats = result.stats
        total_time = time.time() - start_time

        print_summary(stats)
        print(f"\n⏱️  Total time: {total_time:.1f}s")

        # Save JSON stats if requested
        if json_stats_path:
            save_stats_json(
                stats,
                json_stats_path,
                total_time,
                runtime_profile=result.runtime_profile,
            )
            print(f"📊 Stats saved to: {json_stats_path}")

        print("✅ Pipeline completed successfully!")

        return 0

    except Exception as e:
        print(f"\n❌ ERROR: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
