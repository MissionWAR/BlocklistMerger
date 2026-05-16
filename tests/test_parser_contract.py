from pathlib import Path

import pytest

from scripts.cleaner import (
    DISCARD_REASON_INVALID,
    DISCARD_REASON_UNSUPPORTED_MODIFIER,
    DISCARD_REASON_URL_PATH,
    clean_line,
)
from scripts.compiler import clear_caches, compile_rules


@pytest.mark.parametrize(
    (
        "raw_rule",
        "expected_reason",
        "expected_cleaned",
        "expected_compiled",
    ),
    [
        ("||example.com/ads/", DISCARD_REASON_URL_PATH, None, None),
        ("domain.com/path", DISCARD_REASON_URL_PATH, None, None),
        ("@@||example.com/ads/", DISCARD_REASON_URL_PATH, None, None),
        ("/example.*/", None, "/example.*/", "/example.*/"),
        ("/^example\\.com$/", None, "/^example\\.com$/", "/^example\\.com$/"),
        ("/regex/$important", None, "/regex/$important", "/regex/$important"),
        (
            "||example.org^$client=192.168.0.0/24",
            None,
            "||example.org^$client=192.168.0.0/24",
            "||example.org^$client=192.168.0.0/24",
        ),
        (
            "||example.org^$domain=foo/bar.com",
            DISCARD_REASON_UNSUPPORTED_MODIFIER,
            None,
            None,
        ),
        (
            "||example.com^$script,third-party",
            DISCARD_REASON_UNSUPPORTED_MODIFIER,
            None,
            None,
        ),
        ("$important", DISCARD_REASON_INVALID, None, None),
        ("||^", DISCARD_REASON_INVALID, None, None),
    ],
    ids=[
        "abp-url-path",
        "plain-domain-url-path",
        "exception-url-path",
        "regex-basic",
        "regex-anchor",
        "regex-with-modifier",
        "supported-client-cidr",
        "unsupported-domain-slash",
        "unsupported-browser-modifiers",
        "modifier-only-invalid",
        "empty-abp-invalid",
    ],
)
def test_cleaner_compiler_parser_contract(
    raw_rule: str,
    expected_reason: str | None,
    expected_cleaned: str | None,
    expected_compiled: str | None,
    tmp_path: Path,
) -> None:
    """Cleaner reason, cleaned output, and compiled output agree for syntax cases."""
    result, _was_trimmed = clean_line(raw_rule)

    if expected_reason is not None:
        assert result.discarded
        assert result.reason == expected_reason
        assert result.line is None
        return

    assert not result.discarded
    assert result.reason is None
    assert result.line == expected_cleaned

    clear_caches()
    output_file = tmp_path / "merged.txt"
    stats = compile_rules([result.line], str(output_file))
    output_lines = output_file.read_text(encoding="utf-8").splitlines()

    assert expected_compiled in output_lines
    assert stats.total_output == 1
