"""
Static pins for the isolated weekly perf-evidence workflow.

The perf-evidence workflow publishes benchmark evidence as non-blocking
artifacts on a Tuesday 03:17 UTC schedule plus manual dispatch. These tests
guard the structural isolation that keeps advisory evidence from ever
touching the 12h publish path: own triggers, own concurrency group, minimal
permissions, SHA-pinned actions, dated artifact shape, and zero contact with
publish lineage.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PERF_WORKFLOW = ROOT / ".github" / "workflows" / "perf-evidence.yml"
UPDATE_WORKFLOW = ROOT / ".github" / "workflows" / "update.yml"
HEAVY_EVIDENCE_WORKFLOW = ROOT / ".github" / "workflows" / "heavy-evidence.yml"

PERF_CRON = "17 3 * * 2"
RELEASE_INSTALL = 'python -m pip install -q -c constraints/release-py314.txt ".[dev]"'
CHECKOUT_PIN = "uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1"
SETUP_PYTHON_PIN = (
    "uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97  # v7.0.0"
)
UPLOAD_ARTIFACT_PIN = (
    "uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a  # v7.0.1"
)
DOWNLOAD_ARTIFACT_PIN = (
    "uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c  # v8.0.1"
)
PUBLISH_PATH_TOKENS = (
    "softprops",
    "tag_name",
    "actions/cache",
    "gh cache",
    "merged.txt",
    "publish:",
    "gh release",
    "git tag",
    "blocklists-",
    "heavy-release-evidence",
    "release-candidate",
    "cache_cleanup",
)


def _perf_text() -> str:
    assert PERF_WORKFLOW.exists(), f"Missing isolated workflow: {PERF_WORKFLOW}"
    return PERF_WORKFLOW.read_text(encoding="utf-8")


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


def _run_blocks(text: str) -> list[str]:
    blocks = []
    lines = text.splitlines(keepends=True)
    index = 0
    while index < len(lines):
        stripped = lines[index].lstrip()
        if stripped.startswith("run:"):
            indent = len(lines[index]) - len(stripped)
            rest = stripped[len("run:") :].strip()
            if rest in ("|", ">", "|-", ">-"):
                index += 1
                chunk = []
                while index < len(lines):
                    line = lines[index]
                    if line.strip():
                        line_indent = len(line) - len(line.lstrip())
                        if line_indent <= indent:
                            break
                    chunk.append(line)
                    index += 1
                blocks.append("".join(chunk))
                continue
            blocks.append(rest)
        index += 1
    return blocks


def test_perf_evidence_runs_weekly_and_on_dispatch() -> None:
    """Weekly Tuesday schedule plus manual dispatch live only in the new file."""
    text = _perf_text()

    assert f'cron: "{PERF_CRON}"' in text
    assert "\n  workflow_dispatch:\n" in text
    assert "pull_request" not in text

    for other in (UPDATE_WORKFLOW, HEAVY_EVIDENCE_WORKFLOW):
        assert PERF_CRON not in other.read_text(encoding="utf-8")


def test_perf_evidence_permissions_are_read_only() -> None:
    """Empty top-level permissions with read-only job scopes and no write token."""
    text = _perf_text()
    job = _job_section(text, "perf_evidence")

    assert "\npermissions: {}\n" in text
    assert "\n    permissions:\n      contents: read\n      actions: read\n" in job
    assert "contents: write" not in text
    assert "actions: write" not in text
    assert "write-all" not in text


def test_perf_evidence_concurrency_is_isolated() -> None:
    """Own concurrency group with no shared lineage and a 120-minute timeout."""
    text = _perf_text()
    job = _job_section(text, "perf_evidence")

    assert "group: perf-evidence-" in text
    assert "blocklists-update-" not in text
    assert "heavy-release-evidence" not in text
    assert "cancel-in-progress: false" in text
    assert "cancel-in-progress: true" not in text
    assert "\n    timeout-minutes: 120\n" in job


def test_perf_evidence_actions_are_sha_pinned() -> None:
    """All four actions are SHA-pinned with trailing version comments."""
    text = _perf_text()

    assert CHECKOUT_PIN in text
    assert SETUP_PYTHON_PIN in text
    assert UPLOAD_ARTIFACT_PIN in text
    assert DOWNLOAD_ARTIFACT_PIN in text


def test_perf_evidence_artifact_shape_and_install() -> None:
    """Dated artifact name with run id, 90-day retention, and pinned install line."""
    text = _perf_text()
    upload_step = _step_section(text, "Upload Perf Evidence")
    stamp_step = _step_section(text, "Stamp Evidence Date")

    assert "name: perf-evidence-" in upload_step
    assert "github.run_id" in upload_step
    assert "steps.stamp.outputs.date" in upload_step
    assert "retention-days: 90" in upload_step
    assert "if-no-files-found: warn" in upload_step
    assert "if: always()" in upload_step
    assert "date -u +%Y%m%d" in stamp_step
    assert RELEASE_INSTALL in text


def test_perf_evidence_has_no_publish_path_contact() -> None:
    """Zero publish lineage alongside the rolling-baseline download surface."""
    text = _perf_text()
    lower_text = text.lower()

    for token in PUBLISH_PATH_TOKENS:
        assert token not in lower_text

    assert "github_token" not in text
    assert "actions/download-artifact@" in text
    assert "github-token:" in text
    assert "run-id:" in text


def test_perf_evidence_compares_are_captured_and_always_run() -> None:
    """Compare steps never gate: always-run with captured tool failures."""
    text = _perf_text()
    for step in (
        "Compare pinned leg vs rolling baseline",
        "Compare live leg vs rolling baseline",
    ):
        section = _step_section(text, step)
        assert "if: always()" in section
        assert "continue-on-error: true" in section
        assert "|| true" in section


def test_perf_evidence_evidence_steps_always_run() -> None:
    """Receipts, summary, and baseline upload always run for partial evidence."""
    text = _perf_text()
    for step in (
        "Collect Environment Receipts",
        "Render Advisory Summary",
        "Upload baseline report",
    ):
        section = _step_section(text, step)
        assert "if: always()" in section


def test_perf_evidence_rolling_baseline_resolver_is_guarded() -> None:
    """Rolling-baseline resolver keeps its filter, selector, guard, and capture."""
    text = _perf_text()

    assert "gh run list --workflow perf-evidence.yml --status success" in text
    assert ".[0].databaseId // empty" in text
    assert "steps.baseline.outputs.run-id != ''" in text
    download = _step_section(text, "Download prior report")
    assert "continue-on-error: true" in download


def test_perf_snapshot_env_is_coherent() -> None:
    """Snapshot digest is 64-hex and the artifact name carries its 12-char prefix."""
    text = _perf_text()

    match = re.search(r"PERF_SNAPSHOT_DIGEST: ([0-9a-f]+)", text)
    assert match is not None, "Missing PERF_SNAPSHOT_DIGEST env value"
    digest = match.group(1)
    assert re.fullmatch(r"[0-9a-f]{64}", digest) is not None
    assert f"PERF_SNAPSHOT_ARTIFACT: perf-snapshot-{digest[:12]}" in text


def test_perf_evidence_run_blocks_avoid_untrusted_context() -> None:
    """Run blocks must not interpolate untrusted event context."""
    text = _perf_text()

    blocks = _run_blocks(text)
    assert blocks
    for block in blocks:
        assert "github.event." not in block
