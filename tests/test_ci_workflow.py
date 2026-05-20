"""
Static checks for the GitHub Actions release workflow.

These tests guard the quality gate ordering that keeps scheduled releases from
fetching, compiling, validating, or publishing when lint or pytest fail.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "update.yml"
PYPROJECT = ROOT / "pyproject.toml"
RELEASE_CONSTRAINTS = ROOT / "constraints" / "release-py314.txt"
RELEASE_INSTALL = 'python -m pip install -q -c constraints/release-py314.txt ".[dev]"'
AUDIT_INSTALL = (
    'python -m pip install -e ".[dev]" --ignore-requires-python '
    "-c constraints/release-py314.txt"
)


def _workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def _pyproject_text() -> str:
    return PYPROJECT.read_text(encoding="utf-8")


def _constraints_text() -> str:
    return RELEASE_CONSTRAINTS.read_text(encoding="utf-8")


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


def _step_section(text: str, step_name: str) -> str:
    marker = f"      - name: {step_name}\n"
    start = _position(text, marker)
    next_step = text.find("\n      - name:", start + len(marker))
    if next_step == -1:
        return text[start:]
    return text[start:next_step]


def test_quality_gate_commands_run_before_release_work() -> None:
    """Dev install, Ruff, and pytest must run before release-producing steps."""
    text = _workflow_text()

    install = _position(text, RELEASE_INSTALL)
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
    install_run = _position(text, RELEASE_INSTALL)
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


def test_build_validate_timeout_allows_live_compile_headroom() -> None:
    """Release builds need enough time for live fetch, compile, and validation."""
    text = _workflow_text()
    build_validate = _job_section(text, "build_validate")
    audit = _job_section(text, "python_compatibility_audit")
    publish = _job_section(text, "publish")
    cache_cleanup = _job_section(text, "cache_cleanup")

    assert "\n    timeout-minutes: 30\n" in build_validate
    assert "\n    timeout-minutes: 15\n" not in build_validate
    assert "\n    timeout-minutes: 15\n" in audit
    assert "\n    timeout-minutes: 10\n" in publish
    assert "\n    timeout-minutes: 5\n" in cache_cleanup


def test_release_constraints_file_pins_py314_resolution() -> None:
    """The scheduled-release dependency set should be reviewable as exact pip pins."""
    text = _constraints_text()
    lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.startswith("#")
    ]
    pinned_names = {line.split("==", maxsplit=1)[0].lower() for line in lines}

    assert RELEASE_CONSTRAINTS.exists()
    assert lines
    assert all("==" in line for line in lines)
    assert {"aiofiles", "aiohttp", "pytest", "ruff", "tldextract"} <= pinned_names
    assert "blocklist-merger" not in pinned_names
    assert "pip" not in pinned_names


def test_release_install_uses_constraints_and_cache_dependency_path() -> None:
    """Release dependency resolution should be pinned and cache-invalidated by constraints."""
    text = _workflow_text()
    build_validate = _job_section(text, "build_validate")

    assert RELEASE_INSTALL in build_validate
    assert "cache: pip" in build_validate
    assert "cache-dependency-path: |" in build_validate
    assert "pyproject.toml" in build_validate
    assert "constraints/release-py314.txt" in build_validate
    assert 'pip install -q ".[dev]"' not in build_validate


def test_python_compatibility_audit_matrix_is_read_only_and_separate() -> None:
    """The Python support audit should not publish or weaken release-job permissions."""
    text = _workflow_text()
    audit = _job_section(text, "python_compatibility_audit")
    publish = _job_section(text, "publish")

    assert "\n    permissions:\n      contents: read\n" in audit
    assert "contents: write" not in audit
    assert "actions: write" not in audit
    assert 'python-version: ["3.13", "3.14"]' in audit
    assert AUDIT_INSTALL in audit
    assert "python -m ruff check ." in audit
    assert "python -m pytest" in audit
    assert AUDIT_INSTALL not in publish
    assert "python_compatibility_audit" not in publish


def test_audit_install_runs_before_audit_quality_gates() -> None:
    """The audit job should install with constraints before linting and tests."""
    audit = _job_section(_workflow_text(), "python_compatibility_audit")

    install = _position(audit, AUDIT_INSTALL)
    ruff = _position(audit, "python -m ruff check .")
    pytest = _position(audit, "python -m pytest")

    assert install < ruff < pytest


def test_python_requirement_and_ruff_target_remain_py314() -> None:
    """Compatibility evidence should not lower declared support in this phase."""
    text = _pyproject_text()

    assert 'requires-python = ">=3.14"' in text
    assert 'target-version = "py314"' in text


def test_package_discovery_stays_limited_to_scripts_package() -> None:
    """Top-level constraints and runtime data directories must not enter package builds."""
    text = _pyproject_text()

    assert "[tool.setuptools]" in text
    assert 'packages = ["scripts"]' in text


def test_runtime_profile_summary_mirrors_only_compact_fields() -> None:
    """Step summary should show a small runtime excerpt, not full diagnostic detail."""
    text = _workflow_text()
    build_validate = _job_section(text, "build_validate")
    runtime_summary = _step_section(build_validate, "Append Runtime Profile Summary")

    compile_sources = _position(build_validate, "- name: Compile Sources")
    append_runtime = _position(build_validate, "- name: Append Runtime Profile Summary")
    validate = _position(build_validate, "- name: Validate Release Candidate")

    assert compile_sources < append_runtime < validate
    assert "reports/pipeline-stats.json" in runtime_summary
    assert "$GITHUB_STEP_SUMMARY" in runtime_summary
    assert "runtime_profile" in runtime_summary
    assert "worker_count" in runtime_summary
    assert "raw_input_bytes" in runtime_summary
    assert "output_bytes" in runtime_summary
    assert "resource_ru_maxrss" in runtime_summary
    assert "stage_durations_seconds" not in runtime_summary
    assert "compiler_cardinalities" not in runtime_summary


def test_no_non_pip_dependency_manager_is_introduced() -> None:
    """Phase 04 keeps pip constraints instead of adding another dependency workflow."""
    combined = "\n".join([_workflow_text(), _constraints_text()])
    forbidden = ("uv", "poetry", "pipenv", "pip-tools")

    assert all(token not in combined.lower() for token in forbidden)


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
