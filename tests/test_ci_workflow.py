"""
Static checks for the GitHub Actions release workflow.

These tests guard the quality gate ordering that keeps scheduled releases from
fetching, compiling, validating, or publishing when lint or pytest fail.
"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "update.yml"


def _workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def _position(text: str, needle: str) -> int:
    position = text.find(needle)
    assert position != -1, f"Missing workflow text: {needle!r}"
    return position


def test_quality_gate_commands_run_before_release_work() -> None:
    """Dev install, Ruff, and pytest must run before release-producing steps."""
    text = _workflow_text()

    install = _position(text, 'pip install -q ".[dev]"')
    ruff = _position(text, "python -m ruff check .")
    pytest = _position(text, "python -m pytest")

    assert install < ruff < pytest

    protected_steps = [
        "- name: Get Cache Key",
        "- name: Restore Cache",
        "- name: Fetch Sources",
        "- name: Compile Sources",
        "- name: Calculate Stats",
        "- name: Validate Output",
        "- name: Publish Release",
        "- name: Save Cache",
        "- name: Cleanup Old Caches",
        "- name: Summary",
    ]
    for step in protected_steps:
        assert pytest < _position(text, step)


def test_quality_gate_steps_stay_immediately_after_install() -> None:
    """The quality gate should be the next two steps after dependency install."""
    text = _workflow_text()

    install_name = _position(text, "- name: Install Dependencies")
    install_run = _position(text, 'pip install -q ".[dev]"')
    ruff_name = _position(text, "- name: Ruff")
    ruff_run = _position(text, "python -m ruff check .")
    test_name = _position(text, "- name: Test")
    test_run = _position(text, "python -m pytest")
    next_release_work = _position(text, "- name: Get Cache Key")

    assert install_name < install_run < ruff_name < ruff_run < test_name < test_run
    assert test_run < next_release_work


def test_workflow_permissions_remain_single_top_level_block() -> None:
    """Phase 1 must not add job-level permissions or broaden existing grants."""
    text = _workflow_text()

    assert text.count("\npermissions:\n") == 1
    assert text.count("  contents: write\n") == 1
    assert text.count("  actions: write\n") == 1
    assert "\n    permissions:" not in text
    assert "\n      permissions:" not in text
