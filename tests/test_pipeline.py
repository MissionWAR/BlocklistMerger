#!/usr/bin/env python3
"""
test_pipeline.py

Tests for the pipeline module's end-to-end processing.
Tests process_files() with real temp directories to verify the full
clean -> compile pipeline produces correct output.
"""
import json
import os
import tempfile

import pytest

from scripts.pipeline import print_summary, process_files, save_stats_json


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
            "abp_kept": 1,
            "other_kept": 0,
        }

        print_summary(stats)

        output = capsys.readouterr().out
        assert "URL paths:" in output
        assert "Invalid rules:" in output


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
        }
        save_stats_json(stats, json_path, total_time=5.5)

        with open(json_path) as f:
            data = json.load(f)

        assert data["statistics"]["files_processed"] == 10
        assert data["statistics"]["lines_output"] == 500
        assert data["statistics"]["url_path_removed"] == 0
        assert data["statistics"]["invalid_removed"] == 0
        assert data["execution_time_seconds"] == 5.5
        assert data["version"] == "1.5.0"
        assert "timestamp" in data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
