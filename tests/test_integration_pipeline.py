from __future__ import annotations

from pathlib import Path

import pytest

from scripts.cleaner import clean_lines
from scripts.compiler import clear_caches, compile_rules

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _run_case(case_name: str, tmp_path: Path) -> None:
    """Helper to run a full cleaner+compiler roundtrip for a fixture case."""
    input_path = FIXTURES_DIR / f"{case_name}_input.txt"
    expected_path = FIXTURES_DIR / f"{case_name}_expected.txt"

    raw_lines = input_path.read_text(encoding="utf-8").splitlines()

    # Use the same cleaning stage as the real pipeline.
    cleaned_lines, _stats = clean_lines(raw_lines)

    # Compile into a temporary output file.
    clear_caches()
    output_file = tmp_path / f"{case_name}_output.txt"
    compile_rules(cleaned_lines, str(output_file))

    output_lines = output_file.read_text(encoding="utf-8").splitlines()
    expected_lines = expected_path.read_text(encoding="utf-8").splitlines()

    assert output_lines == expected_lines


@pytest.mark.parametrize(
    "case_name",
    [
        "whitelist_basic",
        "whitelist_wildcard",
        "modifiers_priority",
        "semantic_whitelist_scope",
        "agh_semantics_effects",
    ],
)
def test_pipeline_fixtures(case_name: str, tmp_path: Path) -> None:
    """End-to-end tests using small, focused fixtures and golden outputs."""
    _run_case(case_name, tmp_path)

