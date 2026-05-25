#!/usr/bin/env python3
"""
test_pipeline.py

Tests for the pipeline module's end-to-end processing.
Tests process_files() with real temp directories to verify the full
clean -> compile pipeline produces correct output.
"""
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

import scripts.pipeline as pipeline_module
from scripts.compiler import CompileStats
from scripts.pipeline import print_summary, process_files, save_stats_json
from scripts.pruning_proof import (
    DELTA_PRESERVED,
    OUTCOME_PRUNED,
    PROOF_STATUS_PROVEN,
    REASON_DUPLICATE_RULE,
    CappedProofLedger,
    ProofLedger,
    RuleFacet,
    make_proof_record,
)


def _proof_facet(domain: str = "ads.example.com") -> RuleFacet:
    """Return a compact proof facet for pipeline report tests."""
    return RuleFacet(
        raw_rule=f"||{domain}^",
        normalized_rule=f"||{domain}^",
        source_kind="abp",
        rule_kind="abp",
        domain=domain,
        domain_shape="subdomain",
        effect="block",
        scope="apex_and_subdomains",
        modifier_signature=(),
        priority="normal",
        agh_behavior_basis="adguard_dns_filtering_syntax",
    )


def _proof_record(decision_id: str, *, index: int = 0):
    """Return one deterministic proof record in the duplicate bucket."""
    return make_proof_record(
        decision_id=decision_id,
        decision_type="duplicate",
        outcome=OUTCOME_PRUNED,
        proof_status=PROOF_STATUS_PROVEN,
        reason=REASON_DUPLICATE_RULE,
        candidate=_proof_facet(f"ads-{index}.example.com"),
        covering=_proof_facet("example.com"),
        strict_agh_delta=DELTA_PRESERVED,
        project_policy_delta=DELTA_PRESERVED,
        sample={"index": index},
    )


class TestProcessFiles:
    """Test the full pipeline from raw files to merged output."""

    def _run(self, make_input_dir, file_contents: dict[str, str]):
        """Helper: run pipeline and return (rules, stats)."""
        input_dir, output_file = make_input_dir(file_contents)
        stats = process_files(input_dir, output_file)
        with open(output_file) as f:
            rules = [line.strip() for line in f if line.strip()]
        return rules, stats

    def test_basic_pipeline(self, make_input_dir):
        """Simple ABP rules should pass through the pipeline."""
        rules, stats = self._run(make_input_dir, {
            "list1.txt": "||example.com^\n||other.com^\n",
        })
        assert "||example.com^" in rules
        assert "||other.com^" in rules
        assert stats["files_processed"] == 1
        assert stats["lines_output"] == 2

    def test_comments_filtered(self, make_input_dir):
        """Comments should be removed during cleaning stage."""
        rules, stats = self._run(make_input_dir, {
            "list1.txt": "! This is a comment\n# Another comment\n||example.com^\n",
        })
        assert len(rules) == 1
        assert "||example.com^" in rules
        assert stats["comments_removed"] == 2

    def test_cosmetic_filtered(self, make_input_dir):
        """Cosmetic rules should be removed during cleaning stage."""
        rules, stats = self._run(make_input_dir, {
            "list1.txt": "||example.com^\nexample.com##.ad-banner\n",
        })
        assert len(rules) == 1
        assert stats["cosmetic_removed"] == 1

    def test_subdomain_pruning(self, make_input_dir):
        """Subdomains should be pruned when parent exists."""
        rules, stats = self._run(make_input_dir, {
            "list1.txt": "||example.com^\n||sub.example.com^\n",
        })
        assert len(rules) == 1
        assert "||example.com^" in rules
        assert stats["abp_subdomain_pruned"] == 1

    def test_cross_file_deduplication(self, make_input_dir):
        """Duplicate rules across files should be deduplicated."""
        rules, stats = self._run(make_input_dir, {
            "list1.txt": "||example.com^\n",
            "list2.txt": "||example.com^\n",
        })
        assert len(rules) == 1
        assert stats["duplicate_pruned"] == 1

    @pytest.mark.parametrize("input_rule,expected", [
        ("0.0.0.0 example.com", "||example.com^"),
        ("127.0.0.1 example.com", "||example.com^"),
        ("tracking.com", "||tracking.com^"),
    ], ids=["hosts-zeros", "hosts-loopback", "plain-domain"])
    def test_format_compression(self, make_input_dir, input_rule, expected):
        """Various input formats should all compress to ABP."""
        rules, stats = self._run(make_input_dir, {
            "list1.txt": f"{input_rule}\n",
        })
        assert expected in rules
        assert stats["formats_compressed"] >= 1

    def test_cross_file_subdomain_pruning(self, make_input_dir):
        """Subdomain pruning should work across files."""
        rules, stats = self._run(make_input_dir, {
            "list1.txt": "||example.com^\n",
            "list2.txt": "0.0.0.0 sub.example.com\n",
        })
        assert len(rules) == 1
        assert "||example.com^" in rules

    def test_empty_input(self, tmp_dir):
        """Empty directory should produce empty output without errors."""
        input_dir = os.path.join(tmp_dir, "empty_input")
        os.makedirs(input_dir)
        output_file = os.path.join(tmp_dir, "output.txt")

        stats = process_files(input_dir, output_file)

        assert stats["files_processed"] == 0
        assert stats["lines_output"] == 0
        assert stats["url_path_removed"] == 0
        assert stats["invalid_removed"] == 0

    def test_missing_input_dir_raises(self, tmp_dir):
        """Non-existent input directory should raise FileNotFoundError."""
        output_file = os.path.join(tmp_dir, "output.txt")
        with pytest.raises(FileNotFoundError):
            process_files("/nonexistent/dir", output_file)

    def test_multiple_files_deterministic(self, make_input_dir):
        """Output should be deterministic regardless of file system ordering."""
        rules1, _ = self._run(make_input_dir, {
            "aaa.txt": "||a.com^\n",
            "zzz.txt": "||z.com^\n",
        })
        # Re-create input dir for second run (fixture is already consumed)
        with tempfile.TemporaryDirectory() as tmpdir:
            input_dir = os.path.join(tmpdir, "input")
            os.makedirs(input_dir)
            output_file = os.path.join(tmpdir, "output.txt")
            for name, content in {"aaa.txt": "||a.com^\n", "zzz.txt": "||z.com^\n"}.items():
                with open(os.path.join(input_dir, name), "w") as f:
                    f.write(content)
            process_files(input_dir, output_file)
            with open(output_file) as f:
                rules2 = [line.strip() for line in f if line.strip()]
        assert rules1 == rules2

    def test_unsupported_modifiers_filtered(self, make_input_dir):
        """Rules with unsupported modifiers should be discarded."""
        rules, stats = self._run(make_input_dir, {
            "list1.txt": "||example.com^$script,third-party\n||keep.com^\n",
        })
        assert len(rules) == 1
        assert "||keep.com^" in rules
        assert stats["unsupported_removed"] == 1

    def test_cleaner_discard_reasons_project_to_flat_stats(self, make_input_dir):
        """Every cleaner-owned discard reason should surface in pipeline stats."""
        rules, stats = self._run(make_input_dir, {
            "list1.txt": "\n".join([
                "! comment",
                "example.com##.ad",
                "||bad-modifier.com^$script",
                "",
                "   ",
                "||path.example.com/ads/",
                "||^",
                "||keep.com^",
                "",
            ]),
        })

        assert rules == ["||keep.com^"]
        assert stats["lines_clean"] == 1
        assert stats["comments_removed"] == 1
        assert stats["cosmetic_removed"] == 1
        assert stats["unsupported_removed"] == 1
        assert stats["empty_removed"] == 2
        assert stats["url_path_removed"] == 1
        assert stats["invalid_removed"] == 1

    def test_compiler_malformed_discards_project_to_pipeline_stats(
        self,
        make_input_dir,
        monkeypatch,
    ):
        """Compiler-owned malformed discard totals should surface in pipeline stats."""
        input_dir, output_file = make_input_dir({
            "list1.txt": "||keep.com^\n",
        })

        def fake_compile_rules(lines, output_file):
            assert list(lines) == ["||keep.com^"]
            with open(output_file, "w", encoding="utf-8", newline="\n") as f:
                f.write("||keep.com^\n")
            return CompileStats(total_output=1, abp_kept=1, malformed_discarded=3)

        monkeypatch.setattr(pipeline_module, "compile_rules", fake_compile_rules)

        stats = process_files(input_dir, output_file)

        assert stats["lines_output"] == 1
        assert stats["malformed_discarded"] == 3

    def test_compiler_semantic_diagnostics_project_to_pipeline_stats(
        self,
        make_input_dir,
        monkeypatch,
    ):
        """Compiler-owned semantic diagnostics should surface in pipeline stats."""
        input_dir, output_file = make_input_dir({
            "list1.txt": "||keep.com^\n",
        })

        def fake_compile_rules(lines, output_file):
            assert list(lines) == ["||keep.com^"]
            with open(output_file, "w", encoding="utf-8", newline="\n") as f:
                f.write("||keep.com^\n")
            return CompileStats(
                total_output=1,
                abp_kept=1,
                rule_effect_block=2,
                rule_effect_exception=3,
                rule_effect_rewrite=4,
                rule_effect_disable=5,
                rule_effect_ignored=6,
                rule_effect_unsupported=7,
                rule_effect_uncertain=8,
                compression_policy_broadened=9,
                regex_preserved_no_pruning=10,
            )

        monkeypatch.setattr(pipeline_module, "compile_rules", fake_compile_rules)

        stats = process_files(input_dir, output_file)

        assert stats["lines_output"] == 1
        assert stats["rule_effect_block"] == 2
        assert stats["rule_effect_exception"] == 3
        assert stats["rule_effect_rewrite"] == 4
        assert stats["rule_effect_disable"] == 5
        assert stats["rule_effect_ignored"] == 6
        assert stats["rule_effect_unsupported"] == 7
        assert stats["rule_effect_uncertain"] == 8
        assert stats["compression_policy_broadened"] == 9
        assert stats["regex_preserved_no_pruning"] == 10

    def test_default_process_files_does_not_create_proof_report_and_uses_two_arg_compile(
        self,
        make_input_dir,
        monkeypatch,
    ):
        """Default processing should not construct proof output or change compile call shape."""
        input_dir, output_file = make_input_dir({
            "list1.txt": "||keep.com^\n",
        })
        report_path = Path(output_file).with_name("coverage-proof.json")
        reports_dir = Path(output_file).parent / "reports"

        def fake_compile_rules(lines, output_file):
            assert list(lines) == ["||keep.com^"]
            with open(output_file, "w", encoding="utf-8", newline="\n") as f:
                f.write("||keep.com^\n")
            return CompileStats(total_output=1, abp_kept=1)

        monkeypatch.setattr(pipeline_module, "compile_rules", fake_compile_rules)

        stats = process_files(input_dir, output_file)

        assert stats["lines_output"] == 1
        assert not report_path.exists()
        assert not reports_dir.exists()

    def test_explicit_process_files_with_profile_writes_capped_coverage_proof_report(
        self,
        make_input_dir,
        monkeypatch,
        tmp_path: Path,
    ):
        """Explicit proof reports should be capped, fingerprinted, and stats-compatible."""
        input_dir, output_file = make_input_dir({
            "list1.txt": "||keep.com^\n",
        })
        report_path = tmp_path / "reports" / "coverage-proof.json"
        expected_records = [
            _proof_record(f"decision:{index:03d}", index=index)
            for index in range(3)
        ]

        def fake_compile_rules(lines, output_file, *, proof_ledger=None):
            assert list(lines) == ["||keep.com^"]
            assert isinstance(proof_ledger, CappedProofLedger)
            assert isinstance(proof_ledger, ProofLedger)
            for record in expected_records:
                proof_ledger.append(record)
            with open(output_file, "w", encoding="utf-8", newline="\n") as f:
                f.write("||keep.com^\n")
            return CompileStats(total_output=1, abp_kept=1, duplicate_pruned=3)

        monkeypatch.setattr(pipeline_module, "compile_rules", fake_compile_rules)

        result = pipeline_module.process_files_with_profile(
            input_dir,
            output_file,
            coverage_proof_report=report_path,
            coverage_proof_sample_cap=2,
        )

        data = json.loads(report_path.read_text(encoding="utf-8"))
        sample_bucket = data["sample_buckets"][0]
        sample_records = sample_bucket["records"]
        assert result.stats["lines_output"] == 1
        assert result.stats["duplicate_pruned"] == 3
        assert data["report_type"] == "capped"
        assert data["sample_cap"] == 2
        assert data["summary"]["total_records"] == 3
        assert data["summary"]["by_reason"] == {"duplicate_rule": 3}
        assert sample_bucket["total_records"] == 3
        assert sample_bucket["sampled_records"] == 2
        assert [record["fingerprint"] for record in sample_records] == [
            expected_records[0].fingerprint,
            expected_records[1].fingerprint,
        ]
        assert {record["candidate_domain"] for record in sample_records} == {
            "ads-0.example.com",
            "ads-1.example.com",
        }

    def test_clean_worker_spools_lines_without_returning_list_payload(self, tmp_path: Path):
        """Worker results should return bounded spool metadata, not cleaned line lists."""
        input_file = tmp_path / "input.txt"
        input_file.write_text(
            "! comment\n||keep.com^\n||other.com^\n",
            encoding="utf-8",
        )
        spool_dir = tmp_path / "spools"
        spool_dir.mkdir()

        result = pipeline_module._clean_single_file_to_spool(2, input_file, spool_dir)

        assert result.source_index == 2
        assert not any(isinstance(value, list) for value in result)
        assert result.spool_path.exists()
        assert result.spool_path.read_text(encoding="utf-8").splitlines() == [
            "||keep.com^",
            "||other.com^",
        ]
        assert result.stats["lines_raw"] == 3
        assert result.stats["lines_clean"] == 2
        assert result.stats["comments_removed"] == 1

    def test_spooled_worker_results_feed_compiler_in_sorted_file_order(
        self,
        make_input_dir,
        monkeypatch,
    ):
        """Compiler input should follow sorted filenames, not worker completion order."""
        input_dir, output_file = make_input_dir({
            "b-list.txt": "||b.com^\n",
            "a-list.txt": "||a.com^\n",
            "c-list.txt": "||c.com^\n",
        })
        submitted_futures = []
        compiled_lines: list[str] = []

        class FakeFuture:
            def __init__(self, result):
                self._result = result

            def result(self):
                return self._result

        class CompletionOrderExecutor:
            def __init__(self, max_workers=None):
                self.max_workers = max_workers

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            def submit(self, fn, *args):
                future = FakeFuture(fn(*args))
                submitted_futures.append(future)
                return future

            def map(self, fn, files):
                return list(reversed([fn(file_path) for file_path in files]))

        def fake_as_completed(futures):
            assert list(futures) == submitted_futures
            return reversed(submitted_futures)

        def fake_compile_rules(lines, output_file):
            compiled_lines.extend(lines)
            with open(output_file, "w", encoding="utf-8", newline="\n") as f:
                for line in compiled_lines:
                    f.write(line + "\n")
            return CompileStats(total_output=len(compiled_lines), abp_kept=len(compiled_lines))

        monkeypatch.setattr(pipeline_module, "ProcessPoolExecutor", CompletionOrderExecutor)
        monkeypatch.setattr(pipeline_module, "as_completed", fake_as_completed, raising=False)
        monkeypatch.setattr(pipeline_module, "compile_rules", fake_compile_rules)

        stats = process_files(input_dir, output_file)

        assert compiled_lines == ["||a.com^", "||b.com^", "||c.com^"]
        assert stats["lines_clean"] == 3
        assert stats["lines_output"] == 3

    @pytest.mark.parametrize("compile_fails", [False, True], ids=["success", "compile-failure"])
    def test_clean_spool_directory_is_removed_after_compile(
        self,
        make_input_dir,
        monkeypatch,
        tmp_path: Path,
        compile_fails: bool,
    ):
        """Temporary cleaned spools should be cleaned up on success and compile failure."""
        input_dir, output_file = make_input_dir({
            "one.txt": "||one.com^\n",
            "two.txt": "||two.com^\n",
        })
        spool_root = tmp_path / "recorded-spools"
        entered_spool_context = False

        class RecordingTemporaryDirectory:
            def __init__(self, prefix):
                self.prefix = prefix
                self.name = str(spool_root)

            def __enter__(self):
                nonlocal entered_spool_context
                entered_spool_context = True
                if spool_root.exists():
                    shutil.rmtree(spool_root)
                spool_root.mkdir()
                return self.name

            def __exit__(self, exc_type, exc, traceback):
                shutil.rmtree(spool_root, ignore_errors=True)
                return False

        def fake_compile_rules(lines, output_file):
            consumed = list(lines)
            assert consumed == ["||one.com^", "||two.com^"]
            if compile_fails:
                raise RuntimeError("forced compile failure")
            with open(output_file, "w", encoding="utf-8", newline="\n") as f:
                for line in consumed:
                    f.write(line + "\n")
            return CompileStats(total_output=len(consumed), abp_kept=len(consumed))

        monkeypatch.setattr(pipeline_module, "TemporaryDirectory", RecordingTemporaryDirectory)
        monkeypatch.setattr(pipeline_module, "compile_rules", fake_compile_rules)

        if compile_fails:
            with pytest.raises(RuntimeError, match="forced compile failure"):
                process_files(input_dir, output_file)
        else:
            process_files(input_dir, output_file)

        assert entered_spool_context
        assert not spool_root.exists()

    def test_process_files_with_profile_returns_inspect_only_runtime_profile(
        self,
        make_input_dir,
    ):
        """Profiled processing should preserve stats and expose runtime-size metadata."""
        input_dir, output_file = make_input_dir({
            "b-list.txt": "||b.com^\n",
            "a-list.txt": "||a.com^\n",
        })

        stats, runtime_profile = pipeline_module.process_files_with_profile(input_dir, output_file)

        assert stats["lines_output"] == 2
        assert runtime_profile["worker_count"] == os.cpu_count()
        assert set(runtime_profile["stage_durations_seconds"]) == {
            "clean_seconds",
            "compile_seconds",
        }
        assert runtime_profile["byte_sizes"]["raw_input_bytes"] == sum(
            path.stat().st_size for path in Path(input_dir).glob("*.txt")
        )
        assert runtime_profile["byte_sizes"]["output_bytes"] == Path(output_file).stat().st_size
        assert runtime_profile["compiler_cardinalities"] == {
            "abp_rule_keys": 2,
            "abp_wildcard_keys": 0,
            "exception_rule_keys": 0,
            "duplicate_index_size": 2,
            "other_rule_count": 0,
        }
        assert set(runtime_profile["memory"]) == {
            "tracemalloc_current_bytes",
            "tracemalloc_peak_bytes",
            "resource_ru_maxrss",
        }

    def test_print_summary_includes_new_cleaner_categories(self, capsys):
        """Pipeline summary should make URL-path and invalid drops visible."""
        stats = {
            "files_processed": 1,
            "lines_raw": 7,
            "lines_clean": 1,
            "lines_output": 1,
            "comments_removed": 1,
            "cosmetic_removed": 1,
            "unsupported_removed": 1,
            "empty_removed": 1,
            "url_path_removed": 1,
            "invalid_removed": 1,
            "trimmed": 0,
            "abp_subdomain_pruned": 0,
            "tld_wildcard_pruned": 0,
            "duplicate_pruned": 0,
            "whitelist_conflict_pruned": 0,
            "local_hostname_pruned": 0,
            "formats_compressed": 0,
            "malformed_discarded": 0,
            "abp_kept": 1,
            "other_kept": 0,
            "rule_effect_block": 1,
            "rule_effect_exception": 2,
            "rule_effect_rewrite": 3,
            "rule_effect_disable": 4,
            "rule_effect_ignored": 5,
            "rule_effect_unsupported": 6,
            "rule_effect_uncertain": 7,
            "compression_policy_broadened": 8,
            "regex_preserved_no_pruning": 9,
        }

        print_summary(stats)

        output = capsys.readouterr().out
        assert "URL paths:" in output
        assert "Invalid rules:" in output
        assert "Semantic diagnostics:" in output
        assert "Rule effects:" in output
        assert "Compression policy:" in output


class TestSaveStatsJson:
    """Test JSON stats export."""

    def test_save_stats(self, tmp_dir):
        """Should save stats as valid JSON with dynamic version."""
        json_path = os.path.join(tmp_dir, "stats.json")
        stats = {
            "files_processed": 10,
            "lines_raw": 1000,
            "lines_clean": 800,
            "lines_output": 500,
            "comments_removed": 100,
            "cosmetic_removed": 50,
            "unsupported_removed": 50,
            "url_path_removed": 0,
            "invalid_removed": 0,
            "empty_removed": 0,
            "trimmed": 10,
            "abp_subdomain_pruned": 200,
            "tld_wildcard_pruned": 50,
            "duplicate_pruned": 50,
            "whitelist_conflict_pruned": 0,
            "local_hostname_pruned": 0,
            "formats_compressed": 100,
            "abp_kept": 400,
            "other_kept": 100,
            "malformed_discarded": 7,
            "rule_effect_block": 11,
            "rule_effect_exception": 12,
            "rule_effect_rewrite": 13,
            "rule_effect_disable": 14,
            "rule_effect_ignored": 15,
            "rule_effect_unsupported": 16,
            "rule_effect_uncertain": 17,
            "compression_policy_broadened": 18,
            "regex_preserved_no_pruning": 19,
        }
        runtime_profile = {
            "worker_count": 4,
            "stage_durations_seconds": {
                "clean_seconds": 1.25,
                "compile_seconds": 2.5,
            },
            "byte_sizes": {
                "raw_input_bytes": 2048,
                "output_bytes": 1024,
            },
            "compiler_cardinalities": {
                "abp_rule_keys": 100,
                "abp_wildcard_keys": 2,
                "exception_rule_keys": 3,
                "duplicate_index_size": 120,
                "other_rule_count": 4,
            },
            "memory": {
                "tracemalloc_current_bytes": 10,
                "tracemalloc_peak_bytes": 20,
                "resource_ru_maxrss": None,
            },
        }
        save_stats_json(stats, json_path, total_time=5.5, runtime_profile=runtime_profile)

        with open(json_path) as f:
            data = json.load(f)

        assert data["schema_version"] == 4
        assert data["version"] == "1.5.0"
        assert data["timestamp"].endswith("Z")
        assert data["execution_time_seconds"] == 5.5
        assert data["statistics"]["files_processed"] == 10
        assert data["statistics"]["lines_output"] == 500
        assert (
            data["statistics"]["lines_output"]
            == data["statistics"]["abp_kept"] + data["statistics"]["other_kept"]
        )
        assert data["statistics"]["url_path_removed"] == 0
        assert data["statistics"]["invalid_removed"] == 0
        assert data["statistics"]["duplicate_pruned"] == 50
        assert data["statistics"]["abp_kept"] == 400
        assert data["statistics"]["other_kept"] == 100
        assert data["statistics"]["formats_compressed"] == 100
        assert data["statistics"]["malformed_discarded"] == 7
        assert data["statistics"]["rule_effect_block"] == 11
        assert data["statistics"]["rule_effect_uncertain"] == 17
        assert data["statistics"]["compression_policy_broadened"] == 18
        assert data["statistics"]["regex_preserved_no_pruning"] == 19
        assert data["semantics"] == {
            "rule_effect_counts": {
                "block": 11,
                "exception": 12,
                "rewrite": 13,
                "disable": 14,
                "ignored": 15,
                "unsupported": 16,
                "uncertain": 17,
            },
            "compression_policy": {
                "hosts_plain_promoted_to_abp": 18,
                "regex_preserved_no_pruning": 19,
            },
        }
        assert set(data["stage_summaries"]) == {"cleaner", "compiler"}
        assert set(data["stage_summaries"]["cleaner"]) == {
            "normalize",
            "prefilter",
            "compatibility",
            "syntax",
            "emit",
        }
        assert set(data["stage_summaries"]["compiler"]) == {
            "parse",
            "normalize",
            "classify",
            "compress",
            "index",
            "prune",
            "write",
        }
        assert data["stage_summaries"]["cleaner"]["normalize"]["reasons"] == {"trimmed": 10}
        assert data["stage_summaries"]["cleaner"]["emit"]["reasons"] == {"kept": 800}
        assert data["stage_summaries"]["compiler"]["compress"]["reasons"] == {
            "hosts_plain_promoted_to_abp": 18,
        }
        serialized_stages = json.dumps(data["stage_summaries"], sort_keys=True)
        for forbidden in ("sample", "samples", "sample_buckets", "fingerprint", "records"):
            assert forbidden not in serialized_stages
        assert data["runtime_profile"] == runtime_profile
        assert not os.path.exists(os.path.join(tmp_dir, "stats.tmp"))


class TestPipelineCli:
    """Test command-line pipeline report options."""

    def test_cli_explicit_coverage_proof_writes_report_independent_of_json_stats(
        self,
        make_input_dir,
        monkeypatch,
        tmp_path: Path,
    ) -> None:
        """The CLI should generate proof reports only for an explicit path."""
        input_dir, output_file = make_input_dir({
            "list1.txt": "||example.com^\n||ads.example.com^\n",
        })
        proof_report = tmp_path / "reports" / "coverage-proof.json"
        stats_report = tmp_path / "reports" / "pipeline-stats.json"
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "scripts.pipeline",
                input_dir,
                output_file,
                "--coverage-proof",
                str(proof_report),
                "--json-stats",
                str(stats_report),
            ],
        )

        assert pipeline_module.main() == 0

        proof_data = json.loads(proof_report.read_text(encoding="utf-8"))
        stats_data = json.loads(stats_report.read_text(encoding="utf-8"))
        proof_sample = proof_data["sample_buckets"][0]["records"][0]
        assert proof_data["report_type"] == "capped"
        assert proof_data["summary"]["total_records"] >= 1
        assert proof_sample["fingerprint"]
        assert stats_data["schema_version"] == 4
        assert "stage_summaries" in stats_data
        assert "coverage_proof" not in stats_data
        assert "coverage-proof" not in json.dumps(stats_data)

    def test_cli_without_coverage_proof_writes_no_default_report(
        self,
        make_input_dir,
        monkeypatch,
        tmp_path: Path,
    ) -> None:
        """Omitting --coverage-proof should leave proof report paths absent."""
        input_dir, output_file = make_input_dir({
            "list1.txt": "||example.com^\n||ads.example.com^\n",
        })
        proof_report = tmp_path / "reports" / "coverage-proof.json"
        stats_report = tmp_path / "reports" / "pipeline-stats.json"
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "scripts.pipeline",
                input_dir,
                output_file,
                "--json-stats",
                str(stats_report),
            ],
        )

        assert pipeline_module.main() == 0

        assert stats_report.exists()
        assert not proof_report.exists()


@pytest.mark.parametrize(
    "path",
    [
        Path("scripts/release_validator.py"),
        Path(".github/workflows/update.yml"),
    ],
)
def test_release_boundaries_do_not_reference_coverage_proof_gates(path: Path) -> None:
    """Phase 8 proof reports must not become scheduled release gates."""
    text = path.read_text(encoding="utf-8")

    assert "coverage-proof" not in text
    assert "coverage_proof" not in text
    assert "ProofLedger" not in text


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
