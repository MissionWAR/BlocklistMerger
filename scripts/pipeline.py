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
from scripts.downloader import SourceHealthRuntimeSummary, source_health_runtime_summary
from scripts.pruning_proof import (
    DEFAULT_SAMPLE_CAP,
    CappedProofLedger,
    render_capped_report,
    write_report_json,
)
from scripts.stage_diagnostics import (
    StageSummaries,
    cleaner_stage_summaries_from_stats,
    compiler_stage_summaries_from_stats,
)

# =============================================================================
# CONFIGURATION CONSTANTS
# =============================================================================

PIPELINE_STATS_SCHEMA_VERSION: Final[int] = 4

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
    rule_effect_block: int
    rule_effect_exception: int
    rule_effect_rewrite: int
    rule_effect_disable: int
    rule_effect_ignored: int
    rule_effect_unsupported: int
    rule_effect_uncertain: int
    compression_policy_broadened: int
    regex_preserved_no_pruning: int


class RuleEffectCounts(TypedDict):
    """Inspect-only counts of compiler rule-effect classifications."""

    block: int
    exception: int
    rewrite: int
    disable: int
    ignored: int
    unsupported: int
    uncertain: int


class CompressionPolicyDiagnostics(TypedDict):
    """Inspect-only counters for project compression policy decisions."""

    hosts_plain_promoted_to_abp: int
    regex_preserved_no_pruning: int


class SemanticsDiagnostics(TypedDict):
    """Nested semantics view for the versioned pipeline stats JSON report."""

    rule_effect_counts: RuleEffectCounts
    compression_policy: CompressionPolicyDiagnostics


class StageDiagnostics(TypedDict):
    """Nested inspect-only stage summaries for the versioned stats report."""

    cleaner: StageSummaries
    compiler: StageSummaries


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


class ChildResourceUsage(TypedDict):
    """Best-effort aggregate resource usage for completed child processes."""

    available: bool
    platform: str
    user_cpu_seconds: float | None
    system_cpu_seconds: float | None
    resource_ru_maxrss: int | None
    minor_page_faults: int | None
    major_page_faults: int | None
    voluntary_context_switches: int | None
    involuntary_context_switches: int | None


class RuntimeProfile(TypedDict):
    """Inspect-only runtime profile stored in the pipeline stats report."""

    worker_count: int | None
    stage_durations_seconds: StageDurations
    byte_sizes: ByteSizes
    compiler_cardinalities: CompilerCardinalities
    memory: MemoryProfile
    child_resources: ChildResourceUsage
    source_health: SourceHealthRuntimeSummary


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
        "rule_effect_block": 0,
        "rule_effect_exception": 0,
        "rule_effect_rewrite": 0,
        "rule_effect_disable": 0,
        "rule_effect_ignored": 0,
        "rule_effect_unsupported": 0,
        "rule_effect_uncertain": 0,
        "compression_policy_broadened": 0,
        "regex_preserved_no_pruning": 0,
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


def _empty_child_resource_usage() -> ChildResourceUsage:
    """Return a stable unavailable child resource shape."""
    return {
        "available": False,
        "platform": sys.platform,
        "user_cpu_seconds": None,
        "system_cpu_seconds": None,
        "resource_ru_maxrss": None,
        "minor_page_faults": None,
        "major_page_faults": None,
        "voluntary_context_switches": None,
        "involuntary_context_switches": None,
    }


def _child_resource_usage_snapshot() -> object | None:
    """Return a best-effort child resource usage snapshot when supported."""
    try:
        import resource
    except ImportError:
        return None

    try:
        return resource.getrusage(resource.RUSAGE_CHILDREN)
    except (AttributeError, OSError, ValueError):
        return None


def _resource_float_delta(before: object, after: object, field: str) -> float | None:
    """Return a rounded non-negative float delta from two resource snapshots."""
    try:
        return round(max(0.0, float(getattr(after, field)) - float(getattr(before, field))), 6)
    except (AttributeError, TypeError, ValueError):
        return None


def _resource_int_delta(before: object, after: object, field: str) -> int | None:
    """Return a non-negative integer delta from two resource snapshots."""
    try:
        return max(0, int(getattr(after, field)) - int(getattr(before, field)))
    except (AttributeError, TypeError, ValueError):
        return None


def _child_resource_usage_delta(
    before: object | None,
    after: object | None,
) -> ChildResourceUsage:
    """Return aggregate resource deltas for child processes, or unavailable data."""
    if before is None or after is None:
        return _empty_child_resource_usage()

    return {
        "available": True,
        "platform": sys.platform,
        "user_cpu_seconds": _resource_float_delta(before, after, "ru_utime"),
        "system_cpu_seconds": _resource_float_delta(before, after, "ru_stime"),
        "resource_ru_maxrss": _resource_int_delta(before, after, "ru_maxrss"),
        "minor_page_faults": _resource_int_delta(before, after, "ru_minflt"),
        "major_page_faults": _resource_int_delta(before, after, "ru_majflt"),
        "voluntary_context_switches": _resource_int_delta(before, after, "ru_nvcsw"),
        "involuntary_context_switches": _resource_int_delta(before, after, "ru_nivcsw"),
    }


def _source_health_summary_from_report(
    report_path: str | Path | None,
) -> SourceHealthRuntimeSummary:
    """Load compact source-health runtime evidence from an optional report path."""
    unavailable = source_health_runtime_summary(None, report_path)
    if report_path is None:
        return unavailable

    try:
        with open(report_path, encoding="utf-8") as f:
            report = json.load(f)
    except (OSError, json.JSONDecodeError):
        return unavailable

    if not isinstance(report, dict):
        return unavailable

    return source_health_runtime_summary(report, report_path)


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
        "child_resources": _empty_child_resource_usage(),
        "source_health": source_health_runtime_summary(None),
    }


def _semantics_diagnostics(stats: PipelineStats) -> SemanticsDiagnostics:
    """Return the nested inspect-only semantics view derived from flat counters."""
    return {
        "rule_effect_counts": {
            "block": stats["rule_effect_block"],
            "exception": stats["rule_effect_exception"],
            "rewrite": stats["rule_effect_rewrite"],
            "disable": stats["rule_effect_disable"],
            "ignored": stats["rule_effect_ignored"],
            "unsupported": stats["rule_effect_unsupported"],
            "uncertain": stats["rule_effect_uncertain"],
        },
        "compression_policy": {
            "hosts_plain_promoted_to_abp": stats["compression_policy_broadened"],
            "regex_preserved_no_pruning": stats["regex_preserved_no_pruning"],
        },
    }


def _stage_summaries(
    stats: PipelineStats,
    runtime_profile: RuntimeProfile | None = None,
) -> StageDiagnostics:
    """Return inspect-only stage summaries derived from aggregate counters."""
    compiler_stats: dict[str, object] = dict(stats)
    if runtime_profile is not None:
        compiler_stats.update(runtime_profile["compiler_cardinalities"])

    return {
        "cleaner": cleaner_stage_summaries_from_stats(stats),
        "compiler": compiler_stage_summaries_from_stats(compiler_stats),
    }


# =============================================================================
# PIPELINE FUNCTIONS
# =============================================================================

def process_files(
    input_dir: str,
    output_file: str,
    *,
    coverage_proof_report: str | Path | None = None,
    coverage_proof_sample_cap: int = DEFAULT_SAMPLE_CAP,
) -> PipelineStats:
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
        coverage_proof_report: Optional explicit path for a capped proof report
        coverage_proof_sample_cap: Maximum samples per proof report bucket

    Returns:
        PipelineStats with detailed metrics from all stages

    Raises:
        FileNotFoundError: If input_dir doesn't exist

    Example:
        >>> stats = process_files("lists/_raw", "lists/merged.txt")
        >>> print(f"Reduced {stats['lines_raw']:,} to {stats['lines_output']:,}")
    """
    return process_files_with_profile(
        input_dir,
        output_file,
        coverage_proof_report=coverage_proof_report,
        coverage_proof_sample_cap=coverage_proof_sample_cap,
    ).stats


def process_files_with_profile(
    input_dir: str,
    output_file: str,
    *,
    coverage_proof_report: str | Path | None = None,
    coverage_proof_sample_cap: int = DEFAULT_SAMPLE_CAP,
    source_health_report: str | Path | None = None,
) -> PipelineRunResult:
    """
    Run the full pipeline and return stats plus inspect-only runtime profile data.

    This keeps `process_files()` compatible for existing callers while the CLI can
    attach runtime-size observations to the versioned JSON report. Coverage proof
    reports are manual-only and written only when an explicit path is provided.
    """
    input_path = Path(input_dir)

    if not input_path.is_dir():
        raise FileNotFoundError(f"Input directory not found: {input_dir}")

    stats = _new_pipeline_stats()
    proof_ledger = (
        CappedProofLedger(sample_cap=coverage_proof_sample_cap)
        if coverage_proof_report is not None
        else None
    )

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
            child_resources_before = _child_resource_usage_snapshot()
            results = _clean_files_to_spools(files, spool_dir)
            child_resources_after = _child_resource_usage_snapshot()
            child_resources = _child_resource_usage_delta(
                child_resources_before,
                child_resources_after,
            )
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
            if proof_ledger is None:
                compile_stats = compile_rules(_get_cleaned_lines(), output_file)
            else:
                compile_stats = compile_rules(
                    _get_cleaned_lines(),
                    output_file,
                    proof_ledger=proof_ledger,
                )
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

    # Semantic diagnostics from compiler classification.
    stats["rule_effect_block"] = compile_stats.rule_effect_block
    stats["rule_effect_exception"] = compile_stats.rule_effect_exception
    stats["rule_effect_rewrite"] = compile_stats.rule_effect_rewrite
    stats["rule_effect_disable"] = compile_stats.rule_effect_disable
    stats["rule_effect_ignored"] = compile_stats.rule_effect_ignored
    stats["rule_effect_unsupported"] = compile_stats.rule_effect_unsupported
    stats["rule_effect_uncertain"] = compile_stats.rule_effect_uncertain
    stats["compression_policy_broadened"] = compile_stats.compression_policy_broadened
    stats["regex_preserved_no_pruning"] = compile_stats.regex_preserved_no_pruning

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
        "child_resources": child_resources,
        "source_health": _source_health_summary_from_report(source_health_report),
    }

    if coverage_proof_report is not None and proof_ledger is not None:
        write_report_json(
            coverage_proof_report,
            render_capped_report(proof_ledger),
        )

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

    print("\nSemantic diagnostics:")
    print(
        "   Rule effects: "
        f"block={stats['rule_effect_block']:,}, "
        f"exception={stats['rule_effect_exception']:,}, "
        f"rewrite={stats['rule_effect_rewrite']:,}, "
        f"disable={stats['rule_effect_disable']:,}, "
        f"ignored={stats['rule_effect_ignored']:,}, "
        f"unsupported={stats['rule_effect_unsupported']:,}, "
        f"uncertain={stats['rule_effect_uncertain']:,}"
    )
    print("   Compression policy:")
    print(
        "     Hosts/plain promoted to ABP: "
        f"{stats['compression_policy_broadened']:>10,}"
    )
    print(
        "     Regex preserved without pruning: "
        f"{stats['regex_preserved_no_pruning']:>10,}"
    )


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
        "stage_summaries": _stage_summaries(stats, runtime_profile),
        "semantics": _semantics_diagnostics(stats),
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
    parser.add_argument(
        "--coverage-proof",
        dest="coverage_proof",
        metavar="PATH",
        help="Save a capped coverage proof report to an explicit JSON path",
    )
    parser.add_argument(
        "--source-health-report",
        dest="source_health_report",
        metavar="PATH",
        help="Read source-health JSON and store compact cache evidence in runtime stats",
    )

    parsed = parser.parse_args()
    input_dir = parsed.input_dir
    output_file = parsed.output_file
    json_stats_path = parsed.json_stats
    coverage_proof_path = parsed.coverage_proof
    source_health_report_path = parsed.source_health_report

    try:
        print("🚀 Starting blocklist pipeline...")
        print("-" * 60)

        start_time = time.time()
        result = process_files_with_profile(
            input_dir,
            output_file,
            coverage_proof_report=coverage_proof_path,
            source_health_report=source_health_report_path,
        )
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

        if coverage_proof_path:
            print(f"🧾 Coverage proof saved to: {coverage_proof_path}")

        print("✅ Pipeline completed successfully!")

        return 0

    except Exception as e:
        print(f"\n❌ ERROR: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
