from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.cleaner import clean_lines
from scripts.compiler import clear_caches, compile_rules
from scripts.pruning_proof import ProofLedger, render_full_report, write_report_json

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


def _run_proof_case(case_name: str, tmp_path: Path) -> None:
    """Run a fixture through the compiler and assert full proof sidecar output."""
    input_path = FIXTURES_DIR / f"{case_name}_input.txt"
    expected_path = FIXTURES_DIR / f"{case_name}_expected.txt"
    expected_proof_path = FIXTURES_DIR / f"{case_name}_expected.json"

    assert input_path.parent == FIXTURES_DIR
    assert input_path.stat().st_size < 10_000
    assert expected_path.stat().st_size < 10_000
    assert expected_proof_path.stat().st_size < 50_000

    raw_lines = input_path.read_text(encoding="utf-8").splitlines()
    cleaned_lines, _stats = clean_lines(raw_lines)

    clear_caches()
    ledger = ProofLedger()
    output_file = tmp_path / f"{case_name}_output.txt"
    proof_file = tmp_path / f"{case_name}_proof.json"
    compile_rules(cleaned_lines, str(output_file), proof_ledger=ledger)
    write_report_json(proof_file, render_full_report(ledger))

    output_lines = output_file.read_text(encoding="utf-8").splitlines()
    expected_lines = expected_path.read_text(encoding="utf-8").splitlines()
    actual_proof = json.loads(proof_file.read_text(encoding="utf-8"))
    expected_proof = json.loads(expected_proof_path.read_text(encoding="utf-8"))

    assert output_lines == expected_lines
    assert actual_proof == expected_proof


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


def test_coverage_proof_pruning_fixture(tmp_path: Path) -> None:
    """Full sidecar fixture proves pruning categories without generated data."""
    _run_proof_case("coverage_proof_pruning", tmp_path)

