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
import sys
import time
from pathlib import Path
from typing import TypedDict

from scripts.cleaner import clean_line
from scripts.compiler import compile_rules


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
    trimmed: int
    abp_subdomain_pruned: int
    tld_wildcard_pruned: int
    duplicate_pruned: int
    whitelist_conflict_pruned: int
    local_hostname_pruned: int
    formats_compressed: int
    abp_kept: int
    other_kept: int


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
    input_path = Path(input_dir)
    
    if not input_path.is_dir():
        raise FileNotFoundError(f"Input directory not found: {input_dir}")
    
    stats: PipelineStats = {
        "files_processed": 0,
        "lines_raw": 0,
        "lines_clean": 0,
        "lines_output": 0,
        "comments_removed": 0,
        "cosmetic_removed": 0,
        "unsupported_removed": 0,
        "empty_removed": 0,
        "trimmed": 0,
        "abp_subdomain_pruned": 0,
        "tld_wildcard_pruned": 0,
        "duplicate_pruned": 0,
        "whitelist_conflict_pruned": 0,
        "local_hostname_pruned": 0,
        "formats_compressed": 0,
        "abp_kept": 0,
        "other_kept": 0,
    }
    
    # =========================================================================
    # STAGE 1: Read and clean all files
    # =========================================================================
    print("📖 Stage 1: Reading and cleaning files...")
    stage1_start = time.time()
    
    all_cleaned: list[str] = []
    
    # Process .txt files in sorted order for deterministic results
    for file in sorted(input_path.glob("*.txt")):
        stats["files_processed"] += 1
        
        with open(file, encoding="utf-8-sig", errors="replace") as f:
            for line in f:
                stats["lines_raw"] += 1
                
                # Clean the line
                result, was_trimmed = clean_line(line)
                
                if was_trimmed:
                    stats["trimmed"] += 1
                
                if result.discarded:
                    if result.reason == "comment":
                        stats["comments_removed"] += 1
                    elif result.reason == "cosmetic":
                        stats["cosmetic_removed"] += 1
                    elif result.reason == "unsupported_modifier":
                        stats["unsupported_removed"] += 1
                    elif result.reason == "empty":
                        stats["empty_removed"] += 1
                else:
                    all_cleaned.append(result.line)  # type: ignore[arg-type]
    
    stats["lines_clean"] = len(all_cleaned)
    stage1_time = time.time() - stage1_start
    print(f"   Processed {stats['files_processed']} files, {stats['lines_raw']:,} lines")
    print(f"   Kept {stats['lines_clean']:,} clean rules ({stage1_time:.1f}s)")
    
    # =========================================================================
    # STAGE 2: Compile and deduplicate
    # =========================================================================
    print("\n⚙️  Stage 2: Compiling and deduplicating...")
    stage2_start = time.time()
    
    compile_stats = compile_rules(all_cleaned, output_file)
    
    # Transfer compilation stats
    stats["lines_output"] = compile_stats.total_output
    stats["abp_subdomain_pruned"] = compile_stats.abp_subdomain_pruned
    stats["tld_wildcard_pruned"] = compile_stats.tld_wildcard_pruned
    stats["duplicate_pruned"] = compile_stats.duplicate_pruned
    stats["whitelist_conflict_pruned"] = compile_stats.whitelist_conflict_pruned
    stats["local_hostname_pruned"] = compile_stats.local_hostname_pruned
    stats["formats_compressed"] = compile_stats.formats_compressed
    
    # Format breakdown
    stats["abp_kept"] = compile_stats.abp_kept
    stats["other_kept"] = compile_stats.other_kept
    
    stage2_time = time.time() - stage2_start
    print(f"   Output: {stats['lines_output']:,} rules ({stage2_time:.1f}s)")
    
    return stats


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
    print(f"\n📈 Lines:")
    print(f"   Raw input:    {raw:>12,}")
    print(f"   After clean:  {clean:>12,} (-{clean_reduction:.1f}%)")
    print(f"   Final output: {output:>12,} (-{compile_reduction:.1f}% from clean)")
    print(f"   Total reduction: {total_reduction:.1f}%")
    
    print(f"\n🧹 Cleaning removed:")
    print(f"   Comments:          {stats['comments_removed']:>10,}")
    print(f"   Cosmetic rules:    {stats['cosmetic_removed']:>10,}")
    print(f"   Unsupported mods:  {stats['unsupported_removed']:>10,}")
    print(f"   Empty lines:       {stats['empty_removed']:>10,}")
    print(f"   Trimmed:           {stats['trimmed']:>10,}")
    
    print(f"\n🔧 Compilation pruned:")
    print(f"   ABP subdomains:    {stats['abp_subdomain_pruned']:>10,}")
    print(f"   TLD wildcards:     {stats['tld_wildcard_pruned']:>10,}")
    print(f"   Duplicates:        {stats['duplicate_pruned']:>10,}")
    print(f"   Whitelist conflict:{stats['whitelist_conflict_pruned']:>10,}")
    print(f"   Local hostnames:   {stats['local_hostname_pruned']:>10,}")
    
    print(f"\n📦 Output breakdown:")
    print(f"   ABP rules:   {stats['abp_kept']:>10,} (incl. {stats['formats_compressed']:,} compressed)")
    print(f"   Other rules: {stats['other_kept']:>10,}")


def save_stats_json(stats: PipelineStats, output_path: str, total_time: float) -> None:
    """
    Save pipeline statistics to a JSON file.
    
    Args:
        stats: Pipeline statistics dictionary
        output_path: Path to write JSON file
        total_time: Total execution time in seconds
    """
    output = {
        "version": "1.4.0",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "execution_time_seconds": round(total_time, 2),
        "statistics": dict(stats),
    }
    
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


# =============================================================================
# CLI INTERFACE
# =============================================================================

def main() -> int:
    """
    Main entry point for CLI usage.
    
    Returns:
        Exit code (0 for success, 1 for error, 2 for usage error)
    """
    # Parse arguments
    args = sys.argv[1:]
    json_stats_path: str | None = None
    
    # Check for --json-stats flag
    if "--json-stats" in args:
        idx = args.index("--json-stats")
        if idx + 1 < len(args):
            json_stats_path = args[idx + 1]
            args = args[:idx] + args[idx + 2:]
        else:
            print("Error: --json-stats requires a path argument", file=sys.stderr)
            return 2
    
    if len(args) < 2:
        print("Usage: python -m scripts.pipeline <input_dir> <output_file> [--json-stats <path>]")
        return 2
    
    input_dir = args[0]
    output_file = args[1]
    
    try:
        print("🚀 Starting blocklist pipeline...")
        print("-" * 60)
        
        start_time = time.time()
        stats = process_files(input_dir, output_file)
        total_time = time.time() - start_time
        
        print_summary(stats)
        print(f"\n⏱️  Total time: {total_time:.1f}s")
        
        # Save JSON stats if requested
        if json_stats_path:
            save_stats_json(stats, json_stats_path, total_time)
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
