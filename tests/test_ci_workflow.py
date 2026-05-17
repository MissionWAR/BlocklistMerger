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


def _job_section(text: str, job_name: str) -> str:
    marker = f"  {job_name}:\n"
    start = _position(text, marker)
    next_job = text.find("\n  ", start + len(marker))
    while next_job != -1 and text[next_job + 3 : next_job + 4] == " ":
        next_job = text.find("\n  ", next_job + 1)
    if next_job == -1:
        return text[start:]
    return text[start:next_job]


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
        "- name: Prepare Report Directories",
        "- name: Fetch Sources",
        "- name: Compile Sources",
        "- name: Calculate Stats",
        "- name: Download Previous Release Output",
        "- name: Validate Release Candidate",
        "- name: Append Validation Summary",
        "- name: Upload Release Diagnostics",
        "- name: Download Release Candidate",
        "- name: Publish Release",
        "- name: Save Cache",
        "- name: Cleanup Old Caches",
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


def test_workflow_uses_job_level_least_privilege_permissions() -> None:
    """Only publishing and cache cleanup jobs should receive write permissions."""
    text = _workflow_text()

    assert "\npermissions: {}\n" in text
    assert "permissions:\n  contents: write\n" not in text
    assert "permissions:\n  actions: write\n" not in text

    build_validate = _job_section(text, "build_validate")
    publish = _job_section(text, "publish")
    cache_cleanup = _job_section(text, "cache_cleanup")

    assert "\n    permissions:\n      contents: read\n" in build_validate
    assert "contents: write" not in build_validate
    assert "actions: write" not in build_validate

    assert "\n    permissions:\n      contents: write\n" in publish
    assert "actions: write" not in publish

    assert "\n    permissions:\n      actions: write\n" in cache_cleanup
    assert "contents: write" not in cache_cleanup


def test_release_validation_reports_and_artifacts_are_wired() -> None:
    """Workflow should generate diagnostics, validate, summarize, and hand off artifacts."""
    text = _workflow_text()

    assert "--health-report reports/source-health.json" in text
    assert "--json-stats reports/pipeline-stats.json" in text
    assert "python -m scripts.release_validator" in text
    assert "reports/validation-summary.json" in text
    assert "reports/validation-summary.md" in text
    assert "$GITHUB_STEP_SUMMARY" in text
    assert "releases/latest/download/merged.txt" in text
    assert "actions/upload-artifact@" in text
    assert "actions/download-artifact@" in text

    validate = _position(text, "- name: Validate Release Candidate")
    append_summary = _position(text, "- name: Append Validation Summary")
    upload_artifact = _position(text, "- name: Upload Release Diagnostics")
    download_artifact = _position(text, "- name: Download Release Candidate")
    publish = _position(text, "- name: Publish Release")

    assert validate < append_summary < upload_artifact < download_artifact < publish


def test_failure_diagnostics_are_always_uploaded_and_summarized() -> None:
    """Validator failures must still leave maintainer triage output."""
    text = _workflow_text()

    append_summary = _position(text, "- name: Append Validation Summary")
    upload_artifact = _position(text, "- name: Upload Release Diagnostics")

    assert _position(text[append_summary:upload_artifact], "if: always()") != -1
    assert _position(text[upload_artifact:], "if: always()") != -1
