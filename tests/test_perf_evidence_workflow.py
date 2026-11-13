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
SETUP_PYTHON_PIN = "uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97  # v7.0.0"
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


_JOB_HEADER_RE = re.compile(r"^  [A-Za-z0-9_-]+:\s*(?:#.*)?$")
_RUN_KEY_RE = re.compile(r"^(?:-\s+)?run:\s*(?P<rest>.*)$")
_BLOCK_SCALAR_RE = re.compile(r"^[|>][0-9+-]*(?:\s+#.*)?$")


def _job_section(text: str, job_name: str) -> str:
    marker = f"  {job_name}:\n"
    start = _position(text, marker)
    lines = text[start:].splitlines(keepends=True)
    collected = [lines[0]]
    for line in lines[1:]:
        stripped = line.lstrip()
        if (
            stripped
            and not stripped.startswith("#")
            and (_JOB_HEADER_RE.match(line.rstrip("\r\n")) or not line.startswith(" "))
        ):
            break
        collected.append(line)
    return "".join(collected)


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
        if stripped.startswith("#"):
            index += 1
            continue
        match = _RUN_KEY_RE.match(stripped.rstrip("\r\n"))
        if match is not None:
            indent = len(lines[index]) - len(stripped)
            rest = match.group("rest").strip()
            if _BLOCK_SCALAR_RE.match(rest):
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
            if rest and not rest.startswith("#"):
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


def test_perf_alert_job_is_isolated_with_minimal_issues_write() -> None:
    """Alerting runs in a separate advisory job holding sole minimal issues: write."""
    text = _perf_text()

    assert "\npermissions: {}\n" in text

    perf_evidence = _job_section(text, "perf_evidence")
    assert "\n    permissions:\n      contents: read\n      actions: read\n" in perf_evidence
    assert "issues: write" not in perf_evidence

    assert _position(text, "  perf_evidence:\n") < _position(text, "  perf_alert:\n")
    perf_alert = _job_section(text, "perf_alert")

    assert "\n    needs: perf_evidence\n" in perf_alert
    assert "!cancelled()" in perf_alert
    assert "needs.perf_evidence.result == 'success'" in perf_alert
    assert "needs.perf_evidence.result == 'failure'" in perf_alert
    assert "\n    timeout-minutes: 10\n" in perf_alert
    assert "\n    permissions:\n      contents: read\n      issues: write\n" in perf_alert
    assert "actions: read" not in perf_alert
    assert "actions: write" not in perf_alert
    assert "contents: write" not in perf_alert
    assert "write-all" not in perf_alert

    download_handoff = _step_section(perf_alert, "Download Alert Handoff")
    assert "continue-on-error: true" in download_handoff
    assert "name: perf-alert-handoff-${{ github.run_id }}" in download_handoff
    assert "path: alert-handoff" in download_handoff
    assert "run-id:" not in download_handoff
    assert "github-token:" not in download_handoff

    sync_step = _step_section(perf_alert, "Evaluate and Sync Perf Alert")
    assert "continue-on-error: true" in sync_step
    assert "GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}" in sync_step
    assert "GH_REPO: ${{ github.repository }}" in sync_step
    assert "python -m scripts.perf_alert sync --handoff-dir alert-handoff" in sync_step


def test_perf_evidence_non_pinned_isolation_and_receipts_baseline() -> None:
    """Baseline lookup, receipts staging, and alert handoff survive non-pinned leg failures."""
    text = _perf_text()
    perf_evidence = _job_section(text, "perf_evidence")

    resolve_step = _step_section(perf_evidence, "Resolve baseline run id")
    assert "if: always()" in resolve_step

    download_prior = _step_section(perf_evidence, "Download prior report")
    assert "if: always()" in download_prior
    assert "steps.baseline.outputs.run-id != ''" in download_prior

    stage_baseline = _step_section(perf_evidence, "Stage baseline report")
    assert "if: always()" in stage_baseline
    assert "inputs.smoke_mode" in stage_baseline
    assert "reports/benchmarks/runs/pinned-timing.json" in stage_baseline
    assert "reports/benchmarks/runs/live-timing.json" in stage_baseline
    assert "reports/perf-evidence/receipts.json" in stage_baseline
    assert "reports/perf-evidence/baseline-stage" in stage_baseline

    upload_baseline = _step_section(perf_evidence, "Upload baseline report")
    assert "if: always()" in upload_baseline
    assert "inputs.smoke_mode" in upload_baseline
    assert "reports/perf-evidence/baseline-stage/*.json" in upload_baseline
    assert _position(perf_evidence, "      - name: Stage baseline report\n") < _position(
        perf_evidence, "      - name: Upload baseline report\n"
    )

    write_ctx = _step_section(perf_evidence, "Write Alert Context")
    assert "if: always()" in write_ctx
    assert (
        "python -m scripts.perf_alert write-context "
        "--output reports/perf-evidence/alert-context.json" in write_ctx
    )
    assert "PINNED_DRIFTED: ${{ steps.pinned-verify.outputs.drifted }}" in write_ctx
    assert "BASELINE_RUN_ID: ${{ steps.baseline.outputs.run-id }}" in write_ctx
    assert "SMOKE_PINNED_DRIFTED: ${{ steps.smoke-prep.outputs.drifted }}" in write_ctx
    assert "SMOKE_BASELINE_RUN_ID: ${{ steps.smoke-prep.outputs.baseline-run-id }}" in write_ctx
    for env_key in (
        "RUN_ID:",
        "RUN_ATTEMPT:",
        "SERVER_URL:",
        "REPO:",
        "GIT_SHA:",
        "EVENT_NAME:",
        "SMOKE_MODE:",
        "PERF_SNAPSHOT_DIGEST:",
        "PERF_SNAPSHOT_RUN_ID:",
        "OUTCOME_RESTORE:",
        "OUTCOME_PINNED_TIMING:",
        "OUTCOME_PINNED_MEMORY:",
        "OUTCOME_FETCH:",
        "OUTCOME_LIVE_TIMING:",
        "OUTCOME_LIVE_MEMORY:",
        "OUTCOME_DOWNLOAD_PRIOR:",
    ):
        assert env_key in write_ctx
    for line in write_ctx.splitlines():
        if "outputs." in line:
            assert "||" not in line

    stage_handoff = _step_section(perf_evidence, "Stage Alert Handoff")
    assert "if: always()" in stage_handoff
    assert "reports/perf-evidence/alert-context.json" in stage_handoff
    assert "reports/perf-evidence/alert-handoff" in stage_handoff

    upload_handoff = _step_section(perf_evidence, "Upload Alert Handoff")
    assert "if: always()" in upload_handoff
    assert "name: perf-alert-handoff-${{ github.run_id }}" in upload_handoff
    assert "path: reports/perf-evidence/alert-handoff/**" in upload_handoff
    assert "retention-days: 7" in upload_handoff
    assert "if-no-files-found: warn" in upload_handoff

    assert _position(perf_evidence, "      - name: Write Alert Context\n") < _position(
        perf_evidence, "      - name: Stage Alert Handoff\n"
    )
    assert _position(perf_evidence, "      - name: Stage Alert Handoff\n") < _position(
        perf_evidence, "      - name: Upload Alert Handoff\n"
    )


def test_perf_evidence_smoke_mode_is_isolated() -> None:
    """Manual smoke_mode runs stay tagged, excluded from baselines, and never upload prod data."""
    text = _perf_text()
    perf_evidence = _job_section(text, "perf_evidence")

    assert "\n  workflow_dispatch:\n    inputs:\n      smoke_mode:\n" in text
    dispatch_start = _position(text, "\n  workflow_dispatch:\n")
    schedule_start = _position(text, "\n  schedule:\n")
    dispatch_block = text[dispatch_start:schedule_start]
    assert "type: choice" in dispatch_block
    assert "default: none" in dispatch_block
    for choice in ("none", "regression", "partial_recovery", "recovery", "degraded"):
        assert f"- {choice}\n" in dispatch_block

    assert "\nrun-name:" in text
    assert "Perf Evidence [SMOKE" in text
    assert "inputs.smoke_mode != '' && inputs.smoke_mode != 'none'" in text

    resolve_step = _step_section(perf_evidence, "Resolve baseline run id")
    assert "Perf Evidence [SMOKE" in resolve_step
    assert "displayTitle" in resolve_step

    prep_smoke = _step_section(perf_evidence, "Prepare Smoke Evidence")
    assert "id: smoke-prep" in prep_smoke
    assert "inputs.smoke_mode" in prep_smoke
    assert "SMOKE_MODE: ${{ inputs.smoke_mode }}" in prep_smoke
    assert (
        'python -m scripts.perf_alert prepare-smoke --smoke-mode "$SMOKE_MODE" '
        "--output-dir reports/perf-evidence/smoke" in prep_smoke
    )

    upload_smoke = _step_section(perf_evidence, "Upload Smoke Evidence")
    assert "name: perf-evidence-smoke-${{ steps.stamp.outputs.date }}-${{ github.run_id }}" in (
        upload_smoke
    )
    assert "path: reports/perf-evidence/smoke/**" in upload_smoke
    assert "retention-days: 7" in upload_smoke
    assert "inputs.smoke_mode" in upload_smoke

    non_smoke_guard = (
        "(github.event_name != 'workflow_dispatch' || (inputs.smoke_mode || 'none') == 'none')"
    )
    for prod_step in (
        "Stage baseline report",
        "Upload baseline report",
        "Upload self-seeded snapshot",
        "Upload Perf Evidence",
    ):
        assert non_smoke_guard in _step_section(perf_evidence, prod_step)


def test_perf_evidence_all_uses_sha_pinned_and_run_blocks_expression_free() -> None:
    """Every uses: across both jobs is SHA-pinned and no run: block interpolates expressions."""
    text = _perf_text()

    allowed_pins = {
        CHECKOUT_PIN,
        SETUP_PYTHON_PIN,
        UPLOAD_ARTIFACT_PIN,
        DOWNLOAD_ARTIFACT_PIN,
    }
    uses_lines = [
        line.strip().removeprefix("- ").strip()
        for line in text.splitlines()
        if line.strip().startswith(("uses:", "- uses:"))
    ]
    assert uses_lines
    for uses_line in uses_lines:
        assert uses_line in allowed_pins, f"Unpinned or unexpected uses line: {uses_line!r}"

    perf_evidence = _job_section(text, "perf_evidence")
    perf_alert = _job_section(text, "perf_alert")
    perf_alert_uses = [
        line.strip().removeprefix("- ").strip()
        for line in perf_alert.splitlines()
        if line.strip().startswith(("uses:", "- uses:"))
    ]
    assert len(perf_alert_uses) >= 3
    assert CHECKOUT_PIN in perf_alert_uses
    assert SETUP_PYTHON_PIN in perf_alert_uses
    assert DOWNLOAD_ARTIFACT_PIN in perf_alert_uses
    assert UPLOAD_ARTIFACT_PIN in _step_section(perf_evidence, "Upload Alert Handoff")
    assert UPLOAD_ARTIFACT_PIN in _step_section(perf_evidence, "Upload Smoke Evidence")

    blocks = _run_blocks(text)
    assert blocks
    for block in blocks:
        assert "github.event." not in block
        assert "${{" not in block

    for step_name in (
        "Stage baseline report",
        "Prepare Smoke Evidence",
        "Write Alert Context",
        "Stage Alert Handoff",
        "Evaluate and Sync Perf Alert",
    ):
        assert f"      - name: {step_name}\n" in text


def test_perf_alert_setup_and_advisory_upload_steps_never_fail_workflow() -> None:
    """Advisory uploads, context staging, and perf_alert setup stay non-gating (WR-01/05, IN-04)."""
    text = _perf_text()
    perf_evidence = _job_section(text, "perf_evidence")
    perf_alert = _job_section(text, "perf_alert")

    for step_name in (
        "Resolve baseline run id",
        "Upload baseline report",
        "Upload Perf Evidence",
        "Write Alert Context",
        "Stage Alert Handoff",
        "Upload Alert Handoff",
    ):
        assert "continue-on-error: true" in _step_section(perf_evidence, step_name), step_name

    resolve_step = _step_section(perf_evidence, "Resolve baseline run id")
    assert "--limit 100" in resolve_step
    assert "--limit 20" not in resolve_step

    prep_smoke = _step_section(perf_evidence, "Prepare Smoke Evidence")
    assert "RUN_ID:" not in prep_smoke
    assert "GIT_SHA:" not in prep_smoke

    checkout_step = _step_section(perf_alert, "Checkout")
    assert "id: checkout" in checkout_step
    assert "continue-on-error: true" in checkout_step

    setup_python_step = _step_section(perf_alert, "Setup Python")
    assert "id: setup-python" in setup_python_step
    assert "if: steps.checkout.outcome == 'success'" in setup_python_step
    assert "continue-on-error: true" in setup_python_step

    setup_gate = (
        "if: steps.checkout.outcome == 'success' && steps.setup-python.outcome == 'success'"
    )
    download_step = _step_section(perf_alert, "Download Alert Handoff")
    assert setup_gate in download_step
    assert "continue-on-error: true" in download_step

    sync_step = _step_section(perf_alert, "Evaluate and Sync Perf Alert")
    assert setup_gate in sync_step
    assert "continue-on-error: true" in sync_step


def test_workflow_section_helpers_and_baseline_handoff_filters() -> None:
    """Section/run helpers handle comments/block scalars; baseline filter and staging guard work."""
    synthetic_yaml = (
        "jobs:\n"
        "  perf_evidence:\n"
        "    steps:\n"
        "      - name: First\n"
        "        run: |+\n"
        "          echo one\n"
        "          echo two\n"
        "  # 2-space comment between steps must not truncate job slice\n"
        "      # commented run: should be ignored\n"
        "      - name: Second\n"
        "        run: |2\n"
        "          echo three\n"
        "      - name: Third\n"
        "        run: >+\n"
        "          echo four\n"
        "  perf_alert:\n"
        "    permissions:\n"
        "      issues: write\n"
    )
    ev_slice = _job_section(synthetic_yaml, "perf_evidence")
    assert "echo two" in ev_slice
    assert "issues: write" not in ev_slice
    assert "echo four" in ev_slice

    blocks = _run_blocks(synthetic_yaml)
    assert len(blocks) == 3
    assert "echo one" in blocks[0]
    assert "echo two" in blocks[0]
    assert "echo three" in blocks[1]
    assert "echo four" in blocks[2]
    assert all("should be ignored" not in b for b in blocks)

    text = _perf_text()
    perf_evidence = _job_section(text, "perf_evidence")
    resolve_step = _step_section(perf_evidence, "Resolve baseline run id")
    assert (
        '[.[] | select((.displayTitle // "") | startswith("Perf Evidence [SMOKE") | not)] '
        "| .[0].databaseId // empty" in resolve_step
    )

    stage_handoff = _step_section(perf_evidence, "Stage Alert Handoff")
    assert '[ -f "$f" ]' in stage_handoff
    assert '[ -f "$SMOKE_DIR/$f" ]' in stage_handoff
    assert '[ -f "reports/perf-evidence/$f" ]' in stage_handoff
    assert "if [ -f reports/perf-evidence/alert-context.json ]; then" in stage_handoff
