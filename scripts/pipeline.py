#!/usr/bin/env python3
"""
pipeline.py

Main processing pipeline for blocklist compilation.

Usage:
    python -m scripts.pipeline <input_dir> <output_file>

Pipeline stages:
1. Read all files from input_dir
2. Clean each rule (remove comments, cosmetic, unsupported modifiers)
3. Compile (deduplicate, prune subdomains, cross-format optimization)
4. Write merged output
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

from scripts.cleaner import clean_line, CleanStats
from scripts.compiler import compile_rules, CompileStats


def process_files(input_dir: str, output_file: str) -> dict[str, int]:
    """
    Run the full pipeline on input directory.
    
    Args:
        input_dir: Directory containing raw blocklist files
        output_file: Path to output merged list
    
    Returns:
        Statistics dictionary
    """
    input_path = Path(input_dir)
    output_path = Path(output_file)
    
    if not input_path.is_dir():
        raise FileNotFoundError(f"Input directory not found: {input_dir}")
    
    stats = {
        "files_processed": 0,
        "lines_raw": 0,
        "lines_clean": 0,
        "lines_output": 0,
        "comments_removed": 0,
        "cosmetic_removed": 0,
        "unsupported_removed": 0,
        "empty_removed": 0,
        "subdomain_pruned": 0,
        "cross_format_pruned": 0,
        "duplicate_pruned": 0,
        "cautious_kept": 0,
    }
    
    # -------------------------------------------------------------------------
    # Stage 1: Read and clean all files
    # -------------------------------------------------------------------------
    print("📖 Stage 1: Reading and cleaning files...")
    stage1_start = time.time()
    
    all_cleaned: list[str] = []
    
    # Process .txt files
    for file in sorted(input_path.glob("*.txt")):
        stats["files_processed"] += 1
        
        with open(file, encoding="utf-8-sig", errors="replace") as f:
            for line in f:
                stats["lines_raw"] += 1
                
                # Clean the line
                result = clean_line(line)
                
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
                    all_cleaned.append(result.line)
    
    stats["lines_clean"] = len(all_cleaned)
    stage1_time = time.time() - stage1_start
    print(f"   Processed {stats['files_processed']} files, {stats['lines_raw']:,} lines")
    print(f"   Kept {stats['lines_clean']:,} clean rules ({stage1_time:.1f}s)")
    
    # -------------------------------------------------------------------------
    # Stage 2: Compile and deduplicate
    # -------------------------------------------------------------------------
    print("\n⚙️  Stage 2: Compiling and deduplicating...")
    stage2_start = time.time()
    
    output_rules, compile_stats = compile_rules(all_cleaned)
    
    stats["lines_output"] = compile_stats.total_output
    stats["subdomain_pruned"] = compile_stats.subdomain_pruned
    stats["cross_format_pruned"] = compile_stats.cross_format_pruned
    stats["duplicate_pruned"] = compile_stats.duplicate_pruned
    stats["cautious_kept"] = compile_stats.cautious_kept
    
    stage2_time = time.time() - stage2_start
    print(f"   Output: {stats['lines_output']:,} rules ({stage2_time:.1f}s)")
    
    # -------------------------------------------------------------------------
    # Stage 3: Write output
    # -------------------------------------------------------------------------
    print("\n💾 Stage 3: Writing output...")
    stage3_start = time.time()
    
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, "w", encoding="utf-8", newline="\n") as f:
        for rule in output_rules:
            f.write(rule + "\n")
    
    stage3_time = time.time() - stage3_start
    print(f"   Written to {output_file} ({stage3_time:.1f}s)")
    
    return stats


def print_summary(stats: dict[str, int]) -> None:
    """Print formatted summary."""
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
    
    print(f"\n🔧 Compilation:")
    print(f"   Subdomain pruned:  {stats['subdomain_pruned']:>10,}")
    print(f"   Cross-format:      {stats['cross_format_pruned']:>10,}")
    print(f"   Duplicates:        {stats['duplicate_pruned']:>10,}")
    if stats["cautious_kept"] > 0:
        print(f"   ⚠️  Cautious keeps: {stats['cautious_kept']:>10,}")


def main() -> int:
    """Main entry point."""
    if len(sys.argv) < 3:
        print("Usage: python -m scripts.pipeline <input_dir> <output_file>")
        return 2
    
    input_dir = sys.argv[1]
    output_file = sys.argv[2]
    
    try:
        print("🚀 Starting blocklist pipeline...")
        print("-" * 60)
        
        start_time = time.time()
        stats = process_files(input_dir, output_file)
        total_time = time.time() - start_time
        
        print_summary(stats)
        print(f"\n⏱️  Total time: {total_time:.1f}s")
        print("✅ Pipeline completed successfully!")
        
        return 0
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
