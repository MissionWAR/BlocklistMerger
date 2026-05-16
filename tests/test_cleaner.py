#!/usr/bin/env python3
"""
test_cleaner.py

Edge case tests for the cleaner module.
"""
import pytest

from scripts.cleaner import (
    DISCARD_REASON_INVALID,
    DISCARD_REASON_UNSUPPORTED_MODIFIER,
    DISCARD_REASON_URL_PATH,
    clean_line,
    extract_modifiers,
    has_unsupported_modifiers,
    is_cosmetic_rule,
    is_url_path_rule,
)


class TestComments:
    """Test comment detection and removal."""

    def test_exclamation_comment(self):
        result, _ = clean_line("! This is a comment")
        assert result.discarded
        assert result.reason == "comment"

    def test_hash_comment(self):
        result, _ = clean_line("# Another comment")
        assert result.discarded
        assert result.reason == "comment"

    def test_comment_with_leading_space(self):
        result, _ = clean_line("  ! Indented comment")
        assert result.discarded
        assert result.reason == "comment"

    def test_not_a_comment(self):
        result, _ = clean_line("||example.com^")
        assert not result.discarded
        assert result.line == "||example.com^"


class TestCosmeticRules:
    """Test cosmetic/element-hiding rule detection."""

    def test_element_hiding(self):
        assert is_cosmetic_rule("example.com##.ad-banner")

    def test_exception_element_hiding(self):
        assert is_cosmetic_rule("example.com#@#.ad-banner")

    def test_extended_css(self):
        assert is_cosmetic_rule("example.com#?#div:has(.ad)")

    def test_scriptlet(self):
        assert is_cosmetic_rule("example.com#%#//scriptlet('abort-on-property-read')")

    def test_snippet(self):
        assert is_cosmetic_rule("example.com$#abort-on-property-read test")

    def test_adblock_header(self):
        assert is_cosmetic_rule("[Adblock Plus 2.0]")

    def test_not_cosmetic_abp(self):
        assert not is_cosmetic_rule("||example.com^")

    def test_not_cosmetic_hosts(self):
        assert not is_cosmetic_rule("0.0.0.0 example.com")


class TestModifiers:
    """Test modifier extraction and validation."""

    def test_extract_single_modifier(self):
        mods = extract_modifiers("||example.com^$important")
        assert mods == {"important"}

    def test_extract_multiple_modifiers(self):
        mods = extract_modifiers("||example.com^$important,badfilter")
        assert mods == {"important", "badfilter"}

    def test_extract_modifier_with_value(self):
        mods = extract_modifiers("||example.com^$dnsrewrite=1.2.3.4")
        assert "dnsrewrite" in mods

    def test_extract_modifier_with_slash_value(self):
        mods = extract_modifiers("||example.org^$client=192.168.0.0/24")
        assert mods == {"client"}

    def test_extract_negated_modifier(self):
        mods = extract_modifiers("||example.com^$~third-party")
        assert "third-party" in mods

    def test_no_modifiers(self):
        mods = extract_modifiers("||example.com^")
        assert mods == set()

    def test_unsupported_script(self):
        assert has_unsupported_modifiers({"script"})

    def test_unsupported_third_party(self):
        assert has_unsupported_modifiers({"third-party"})

    def test_unsupported_3p(self):
        assert has_unsupported_modifiers({"3p"})

    def test_supported_important(self):
        assert not has_unsupported_modifiers({"important"})

    def test_supported_dnsrewrite(self):
        assert not has_unsupported_modifiers({"dnsrewrite"})


class TestCleanLine:
    """Test complete line cleaning."""

    def test_empty_line(self):
        result, _ = clean_line("")
        assert result.discarded
        assert result.reason == "empty"

    def test_whitespace_only(self):
        result, _ = clean_line("   \t\n")
        assert result.discarded
        assert result.reason == "empty"

    def test_valid_abp_rule(self):
        result, _ = clean_line("||example.com^")
        assert not result.discarded
        assert result.line == "||example.com^"

    def test_abp_with_supported_modifier(self):
        result, _ = clean_line("||example.com^$important")
        assert not result.discarded
        assert result.line == "||example.com^$important"

    def test_abp_with_unsupported_modifier_discarded(self):
        """Rules with unsupported modifiers should be completely discarded."""
        result, _ = clean_line("||example.com^$script,third-party")
        assert result.discarded
        assert result.reason == DISCARD_REASON_UNSUPPORTED_MODIFIER

    def test_abp_with_supported_slash_modifier_kept(self):
        result, _ = clean_line("||example.org^$client=192.168.0.0/24")
        assert not result.discarded
        assert result.line == "||example.org^$client=192.168.0.0/24"

    def test_abp_with_unsupported_slash_modifier_discarded(self):
        result, _ = clean_line("||example.org^$domain=foo/bar.com")
        assert result.discarded
        assert result.reason == DISCARD_REASON_UNSUPPORTED_MODIFIER

    def test_hosts_rule_kept(self):
        result, _ = clean_line("0.0.0.0 example.com")
        assert not result.discarded
        assert result.line == "0.0.0.0 example.com"

    def test_cosmetic_rule_discarded(self):
        result, _ = clean_line("example.com##.ad-banner")
        assert result.discarded
        assert result.reason == "cosmetic"

    def test_trailing_comment_stripped(self):
        result, was_trimmed = clean_line("||example.com^ # block ads")
        assert not result.discarded
        assert result.line == "||example.com^"
        assert was_trimmed

    def test_whitespace_trimmed(self):
        result, was_trimmed = clean_line("  ||example.com^  ")
        assert not result.discarded
        assert result.line == "||example.com^"
        assert was_trimmed


class TestUrlPathRules:
    """Test URL path rule detection logic."""

    def test_standard_path(self):
        assert is_url_path_rule("||example.com/ads/")

    def test_domain_path(self):
        assert is_url_path_rule("domain.com/path")

    def test_path_with_modifier(self):
        assert is_url_path_rule("||example.com/ads/$important")

    def test_whitelist_path(self):
        assert is_url_path_rule("@@||example.com/ads/")

    def test_regex_rule_basic(self):
        assert not is_url_path_rule("/regex/")

    def test_regex_rule_with_quantifiers_anchors(self):
        assert not is_url_path_rule("/^https?:\\/\\/(www\\.)?example\\.com\\/ads\\//")

    def test_regex_rule_with_end_anchor(self):
        assert not is_url_path_rule("/^example\\.com$/")

    def test_regex_with_modifiers(self):
        assert not is_url_path_rule("/regex/$important")

    def test_abp_rule_modifier_with_slash(self):
        """A valid rule where the slash is IN the modifier shouldn't be matched as a path rule."""
        assert not is_url_path_rule("||example.com^$domain=foo/bar.com")

    def test_abp_rule_supported_modifier_with_slash(self):
        assert not is_url_path_rule("||example.org^$client=192.168.0.0/24")


class TestEdgeCases:
    """Edge cases that could cause issues."""

    def test_rule_with_hash_in_domain(self):
        """Hash in domain shouldn't be treated as comment, but dropped as URL path."""
        result, _ = clean_line("||example.com/path#anchor^")
        assert result.discarded
        assert result.reason == DISCARD_REASON_URL_PATH

    def test_url_path_rule_discarded(self):
        result, _ = clean_line("domain.com/path")
        assert result.discarded
        assert result.reason == DISCARD_REASON_URL_PATH

    def test_regex_rule_kept(self):
        result, _ = clean_line("/regex/$important")
        assert not result.discarded
        assert result.line == "/regex/$important"

    def test_modifier_only_rule_invalid(self):
        result, _ = clean_line("$important")
        assert result.discarded
        assert result.reason == DISCARD_REASON_INVALID

    def test_empty_abp_rule_invalid(self):
        result, _ = clean_line("||^")
        assert result.discarded
        assert result.reason == DISCARD_REASON_INVALID

    def test_exception_rule_kept(self):
        result, _ = clean_line("@@||example.com^")
        assert not result.discarded
        assert result.line == "@@||example.com^"

    def test_exception_with_modifier(self):
        result, _ = clean_line("@@||example.com^$important")
        assert not result.discarded

    def test_ip_rule_kept(self):
        """IP-based ABP rules should be kept."""
        result, _ = clean_line("||100.48.203.212^")
        assert not result.discarded
        assert result.line == "||100.48.203.212^"

    def test_wildcard_rule_kept(self):
        result, _ = clean_line("||*.example.com^")
        assert not result.discarded

    def test_tld_wildcard_rule_kept(self):
        result, _ = clean_line("||*.autos^")
        assert not result.discarded


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
