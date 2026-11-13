"""Wave 0 RED-first unit and tracer tests for scripts/perf_alert.py."""

from __future__ import annotations

import ast
import copy
import json
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from scripts.benchmark import extract_perf_fields

REPO_ROOT = Path(__file__).resolve().parent.parent
PERF_ALERT_PATH = REPO_ROOT / "scripts" / "perf_alert.py"
CORPUS_BASELINE_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "benchmarks" / "corpus-baseline.json"

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64


def _full_timing_report(
    median: object,
    digest: object,
    *,
    report_type: object = "corpus_benchmark",
    mode: object = "timing",
    created_at: str = "2026-09-13T03:35:00Z",
    python_version: str = "3.14.7",
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "report_type": report_type,
        "mode": mode,
        "created_at": created_at,
        "identity": {
            "python_version": python_version,
            "platform": "Linux-6.8.0-x86_64",
            "package_version": "1.5.0",
            "git_revision": "abc1234",
        },
        "summary": {
            "min_seconds": median,
            "median_seconds": median,
            "max_seconds": median,
        },
        "corpus": {
            "dir": "reports/perf-evidence/pinned-corpus",
            "file_count": 2,
            "total_bytes": 1024,
            "manifest_sha256": digest,
        },
    }


def _slim_timing_report(
    median: object,
    digest: object,
    *,
    report_type: object = "corpus_benchmark",
    mode: object = "timing",
    created_at: str = "2026-09-06T03:30:00Z",
) -> dict[str, object]:
    return {
        "report_type": report_type,
        "mode": mode,
        "created_at": created_at,
        "identity": {
            "python_version": "3.14.7",
            "platform": "Linux-6.8.0-x86_64",
            "package_version": "1.5.0",
            "git_revision": "def5678",
        },
        "median_seconds": median,
        "manifest_sha256": digest,
    }


def _memory_report(peak_bytes: int, digest: str) -> dict[str, object]:
    return {
        "schema_version": 1,
        "report_type": "corpus_benchmark",
        "mode": "memory",
        "created_at": "2026-09-13T03:36:00Z",
        "corpus": {"manifest_sha256": digest},
        "tracemalloc_current_bytes": 1000,
        "tracemalloc_peak_bytes": peak_bytes,
    }


def _receipts_payload(
    *,
    cpu_model: str = "AMD EPYC 7763 64-Core Processor",
    runner_image: str = "ubuntu-24.04",
    runner_image_version: str = "20260901.1",
    python_version: str = "Python 3.14.7",
    pinned_manifest_sha256: str = DIGEST_A,
    live_manifest_sha256: str = DIGEST_B,
    git_revision: str = "abc1234",
    run_id: str = "34099999999",
) -> dict[str, object]:
    return {
        "cpu_model": cpu_model,
        "runner_image": runner_image,
        "runner_image_version": runner_image_version,
        "python_version": python_version,
        "pinned_manifest_sha256": pinned_manifest_sha256,
        "live_manifest_sha256": live_manifest_sha256,
        "git_revision": git_revision,
        "run_id": run_id,
    }


def _source_health_payload(source_count: int = 2) -> dict[str, object]:
    return {
        "schema_version": 1,
        "version": "1.5.0",
        "generated_at": "2026-09-13T03:20:00Z",
        "source_count": source_count,
        "totals_by_status": {"fetched": source_count, "failed": 0},
        "sources": [],
    }


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _stage_handoff_dir(
    handoff_dir: Path,
    *,
    run_id: str = "34099999999",
    baseline_run_id: str = "34040028893",
    pinned_drifted: str = "false",
    create_drifted_file: bool = False,
    snapshot_digest: str = DIGEST_A,
    current_pinned: dict[str, object] | None = None,
    previous_pinned: dict[str, object] | None = None,
    current_receipts: dict[str, object] | None = None,
    previous_receipts: dict[str, object] | None = None,
    live_timing: dict[str, object] | None = None,
    pinned_memory: dict[str, object] | None = None,
    live_memory: dict[str, object] | None = None,
    source_health: dict[str, object] | None = None,
    event_name: str = "schedule",
    smoke_mode: str = "none",
    step_outcomes: dict[str, str] | None = None,
) -> Path:
    handoff_dir.mkdir(parents=True, exist_ok=True)
    context = {
        "run_id": run_id,
        "run_attempt": "1",
        "run_url": f"https://github.com/MissionWAR/BlocklistMerger/actions/runs/{run_id}",
        "git_sha": "abc1234",
        "event_name": event_name,
        "smoke_mode": smoke_mode,
        "pinned_snapshot_digest": snapshot_digest,
        "pinned_snapshot_run_id": "34037935171",
        "pinned_drifted": pinned_drifted,
        "baseline_run_id": baseline_run_id,
        "step_outcomes": step_outcomes
        or {
            "restore": "success",
            "pinned_timing": "success",
            "pinned_memory": "success",
            "fetch": "success",
            "live_timing": "success",
            "live_memory": "success",
            "download_prior": "success",
        },
    }
    _write_json(handoff_dir / "alert-context.json", context)

    if current_pinned is not None:
        _write_json(handoff_dir / "runs" / "pinned-timing.json", current_pinned)
    if previous_pinned is not None:
        _write_json(handoff_dir / "previous" / "pinned-timing.json", previous_pinned)
    if current_receipts is not None:
        _write_json(handoff_dir / "receipts.json", current_receipts)
    if previous_receipts is not None:
        _write_json(handoff_dir / "previous" / "receipts.json", previous_receipts)
    if live_timing is not None:
        _write_json(handoff_dir / "runs" / "live-timing.json", live_timing)
    if pinned_memory is not None:
        _write_json(handoff_dir / "runs" / "pinned-memory.json", pinned_memory)
    if live_memory is not None:
        _write_json(handoff_dir / "runs" / "live-memory.json", live_memory)
    if source_health is not None:
        _write_json(handoff_dir / "source-health.json", source_health)
    if create_drifted_file:
        (handoff_dir / "pinned-drifted").write_text("", encoding="utf-8")

    return handoff_dir


class FakeGitHubIssueClient:
    """In-memory fake GitHubIssueClient recording all REST API mutations."""

    def __init__(self, initial_issues: Sequence[dict[str, object]] = ()) -> None:
        self.issues: list[dict[str, object]] = [dict(item) for item in initial_issues]
        self.comments: dict[int, list[dict[str, object]]] = {}
        self.ensured_labels: list[dict[str, str]] = []
        self.created_issues: list[dict[str, object]] = []
        self.updated_issues: list[dict[str, object]] = []
        self.created_comments: list[dict[str, object]] = []
        self._next_number = max((int(item["number"]) for item in self.issues), default=0) + 1

    def ensure_label(self, label: str, *, color: str, description: str) -> None:
        self.ensured_labels.append({"label": label, "color": color, "description": description})

    def list_issues(self, label: str) -> list[dict[str, object]]:
        matched: list[dict[str, object]] = []
        for item in self.issues:
            raw_labels = item.get("labels", [])
            label_names = {lbl["name"] if isinstance(lbl, dict) else str(lbl) for lbl in raw_labels}
            if label in label_names:
                matched.append(dict(item))
        return matched

    def create_issue(self, *, title: str, body: str, labels: Sequence[str]) -> dict[str, object]:
        number = self._next_number
        self._next_number += 1
        issue = {
            "number": number,
            "title": title,
            "body": body,
            "state": "open",
            "state_reason": None,
            "labels": [{"name": lbl} for lbl in labels],
            "html_url": f"https://github.com/MissionWAR/BlocklistMerger/issues/{number}",
            "created_at": "2026-09-13T03:40:00Z",
        }
        self.issues.append(issue)
        self.created_issues.append(dict(issue))
        return dict(issue)

    def update_issue(
        self,
        issue_number: int,
        *,
        body: str,
        state: str | None = None,
        state_reason: str | None = None,
    ) -> dict[str, object]:
        for item in self.issues:
            if item["number"] == issue_number:
                item["body"] = body
                if state is not None:
                    item["state"] = state
                if state_reason is not None:
                    item["state_reason"] = state_reason
                record = {
                    "number": issue_number,
                    "body": body,
                    "state": state,
                    "state_reason": state_reason,
                }
                self.updated_issues.append(record)
                return dict(item)
        raise KeyError(f"unknown issue #{issue_number}")

    def list_comments(self, issue_number: int) -> list[dict[str, object]]:
        return [dict(comment) for comment in self.comments.get(issue_number, [])]

    def create_comment(self, issue_number: int, *, body: str) -> dict[str, object]:
        comment = {"id": len(self.created_comments) + 1, "body": body}
        self.comments.setdefault(issue_number, []).append(comment)
        self.created_comments.append({"number": issue_number, "body": body})
        return dict(comment)


def test_perf_alert_uses_stdlib_only_imports() -> None:
    """scripts/perf_alert.py must import strictly Python 3.14 stdlib modules (T-24-05)."""
    source = PERF_ALERT_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(PERF_ALERT_PATH))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top_level = alias.name.split(".", maxsplit=1)[0]
                assert top_level in sys.stdlib_module_names, f"Non-stdlib import: {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "Relative imports are prohibited in scripts/perf_alert.py"
            assert node.module is not None
            top_level = node.module.split(".", maxsplit=1)[0]
            assert top_level in sys.stdlib_module_names, f"Non-stdlib import: {node.module}"
            assert not node.module.startswith("scripts"), "Must not import scripts.* at runtime"


class TestReportValidationAndSchemaParity:
    """Prove exact extract_perf_fields precedence parity plus strict ALERT-02 gates."""

    def test_parity_on_full_and_slim_reports(self) -> None:
        from scripts.perf_alert import parse_timing_report

        full = _full_timing_report(182.456789, DIGEST_A)
        slim = _slim_timing_report(150.25, DIGEST_B)

        parsed_full = parse_timing_report(full)
        parsed_slim = parse_timing_report(slim)

        assert parsed_full is not None
        assert parsed_slim is not None
        assert (parsed_full.median_seconds, parsed_full.manifest_sha256) == extract_perf_fields(
            full
        )
        assert (parsed_slim.median_seconds, parsed_slim.manifest_sha256) == extract_perf_fields(
            slim
        )

    def test_parity_on_summary_precedence_and_corpus_baseline_fixture(self) -> None:
        from scripts.perf_alert import parse_timing_report

        both_present: dict[str, object] = {
            "report_type": "corpus_benchmark",
            "mode": "timing",
            "summary": {"median_seconds": 210.5},
            "median_seconds": 999.0,
            "corpus": {"manifest_sha256": DIGEST_A},
            "manifest_sha256": DIGEST_B,
        }
        parsed_both = parse_timing_report(both_present)
        assert parsed_both is not None
        assert (parsed_both.median_seconds, parsed_both.manifest_sha256) == extract_perf_fields(
            both_present
        )
        assert parsed_both.median_seconds == 210.5
        assert parsed_both.manifest_sha256 == DIGEST_A

        fixture_doc = json.loads(CORPUS_BASELINE_FIXTURE.read_text(encoding="utf-8"))
        parsed_fixture = parse_timing_report(fixture_doc)
        assert parsed_fixture is not None
        assert (
            parsed_fixture.median_seconds,
            parsed_fixture.manifest_sha256,
        ) == extract_perf_fields(fixture_doc)

    @pytest.mark.parametrize(
        "payload",
        [
            pytest.param(["not", "a", "dict"], id="list-root"),
            pytest.param("not-a-dict", id="str-root"),
            pytest.param(42, id="int-root"),
            pytest.param(None, id="none-root"),
            pytest.param(_full_timing_report(100.0, DIGEST_A, report_type="other"), id="bad-type"),
            pytest.param(_full_timing_report(100.0, DIGEST_A, mode="memory"), id="memory-mode"),
            pytest.param(_full_timing_report(True, DIGEST_A), id="bool-true-median"),
            pytest.param(_full_timing_report(False, DIGEST_A), id="bool-false-median"),
            pytest.param(_slim_timing_report(True, DIGEST_A), id="slim-bool-true"),
            pytest.param(_full_timing_report(float("nan"), DIGEST_A), id="nan-median"),
            pytest.param(_full_timing_report(float("inf"), DIGEST_A), id="pos-inf-median"),
            pytest.param(_full_timing_report(float("-inf"), DIGEST_A), id="neg-inf-median"),
            pytest.param(_full_timing_report(0.0, DIGEST_A), id="zero-median"),
            pytest.param(_full_timing_report(-5.0, DIGEST_A), id="negative-median"),
            pytest.param(_full_timing_report(100.0, "a" * 63), id="short-digest"),
            pytest.param(_full_timing_report(100.0, "a" * 65), id="long-digest"),
            pytest.param(_full_timing_report(100.0, "g" * 64), id="non-hex-digest"),
            pytest.param(_full_timing_report(100.0, "A" * 64), id="uppercase-hex-digest"),
        ],
    )
    def test_strict_alert02_rejection(self, payload: object) -> None:
        from scripts.perf_alert import parse_timing_report

        assert parse_timing_report(payload) is None

    def test_load_timing_report_handles_missing_and_corrupt_files(self, tmp_path: Path) -> None:
        from scripts.perf_alert import load_timing_report

        assert load_timing_report(tmp_path / "missing.json") is None
        bad_json = tmp_path / "bad.json"
        bad_json.write_text("{not-json", encoding="utf-8")
        assert load_timing_report(bad_json) is None

        nan_json = tmp_path / "nan.json"
        nan_json.write_text(
            '{"report_type":"corpus_benchmark","mode":"timing","median_seconds":NaN,"manifest_sha256":"'
            + DIGEST_A
            + '"}',
            encoding="utf-8",
        )
        assert load_timing_report(nan_json) is None


class TestSlowdownAndRecoveryMath:
    """Verify D-24-02 unrounded >= 15.0% threshold and D-24-06 anchor recovery math."""

    def test_unrounded_threshold_boundaries(self) -> None:
        from scripts.perf_alert import (
            REGRESSION_THRESHOLD_PERCENT,
            compute_slowdown_percent,
            is_regression_breach,
        )

        assert REGRESSION_THRESHOLD_PERCENT == 15.0

        below_eps = compute_slowdown_percent(100.0, 114.999999)
        assert below_eps < 15.0
        assert is_regression_breach(100.0, 114.999999) is False

        # 14.96% rounds to 15.0% at 1 decimal place — must NOT trigger breach!
        unrounded_1496 = compute_slowdown_percent(100.0, 114.96)
        assert unrounded_1496 == pytest.approx(14.96)
        assert is_regression_breach(100.0, 114.96) is False

        exact = compute_slowdown_percent(100.0, 115.0)
        assert exact == pytest.approx(15.0)
        assert is_regression_breach(100.0, 115.0) is True

        faster = compute_slowdown_percent(100.0, 90.0)
        assert faster == pytest.approx(-10.0)
        assert is_regression_breach(100.0, 90.0) is False

    def test_anchor_recovery_inclusive_at_or_faster(self) -> None:
        from scripts.perf_alert import is_anchor_recovered

        assert is_anchor_recovered(180.0, 180.0) is True
        assert is_anchor_recovered(180.0, 179.9) is True
        assert is_anchor_recovered(180.0, 180.001) is False


class TestStateMarkerCodec:
    """Verify HTML comment JSON state codec and T-24-03 angle-bracket escaping."""

    def test_round_trip_and_angle_bracket_escaping(self) -> None:
        from scripts.perf_alert import (
            EpisodeState,
            HistoryEntry,
            format_state_marker,
            parse_state_marker,
            serialize_state,
        )

        state = EpisodeState(
            episode_mode="production",
            status="open",
            anchor_seconds=180.0,
            anchor_manifest_sha256=DIGEST_A,
            anchor_run_id="34040028893",
            anchor_created_at="2026-09-06T03:30:00Z",
            anchor_receipts={
                "cpu_model": "AMD --> EPYC <!-- 7763",
                "runner_image": "ubuntu-24.04",
                "runner_image_version": "20260901.1",
                "python_version": "Python 3.14.7",
            },
            opened_at="2026-09-13T03:35:00Z",
            opened_run_id="34099999999",
            recorded_run_ids=["34099999999"],
            notified_corpus_digests=[],
            history=[
                HistoryEntry(
                    date="2026-09-13",
                    run_id="34099999999",
                    current_seconds=216.0,
                    anchor_delta_pct=20.0,
                    rolling_seconds=180.0,
                    rolling_delta_pct=20.0,
                    env_changed=False,
                    missing_legs=(),
                )
            ],
        )

        serialized = serialize_state(state)
        assert "<" not in serialized
        assert ">" not in serialized
        assert "\\u003c" in serialized
        assert "\\u003e" in serialized

        marker = format_state_marker(state)
        assert marker.startswith("<!-- perf-alert-state:v1 ")
        assert marker.endswith(" -->")
        assert marker.count("-->") == 1

        body = f"## Perf Regression Alert\n\nSome details.\n\n{marker}\n"
        decoded = parse_state_marker(body)
        assert decoded is not None
        assert decoded == state

    @pytest.mark.parametrize(
        "body",
        [
            pytest.param("", id="empty"),
            pytest.param("No marker here", id="missing-marker"),
            pytest.param("<!-- perf-alert-state:v1 {not-json} -->", id="malformed-json"),
            pytest.param(
                '<!-- perf-alert-state:v1 {"schema_version": 99, "episode_mode": "production"} -->',
                id="wrong-schema-version",
            ),
            pytest.param(
                (
                    '<!-- perf-alert-state:v1 {"schema_version":1,"episode_mode":"production",'
                    '"status":"open","anchor_seconds":true,"anchor_manifest_sha256":"'
                    + DIGEST_A
                    + '","anchor_run_id":"1","opened_run_id":"1"} -->'
                ),
                id="bool-anchor-seconds",
            ),
        ],
    )
    def test_parse_state_marker_rejects_invalid_markers(self, body: str) -> None:
        from scripts.perf_alert import parse_state_marker

        assert parse_state_marker(body) is None


class TestTracerSyncEndToEnd:
    """End-to-end tracer test calling main(['sync', '--handoff-dir', ...])."""

    def test_tracer_noop_below_threshold_drifted_and_live_only(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import scripts.perf_alert as perf_alert

        fake_client = FakeGitHubIssueClient()
        monkeypatch.setattr(perf_alert, "GhCliIssueClient", lambda *a, **kw: fake_client)
        monkeypatch.setenv("GH_REPO", "MissionWAR/BlocklistMerger")

        # 1. Below threshold (14.96% slowdown) -> no-op
        below_dir = _stage_handoff_dir(
            tmp_path / "below",
            current_pinned=_full_timing_report(114.96, DIGEST_A),
            previous_pinned=_slim_timing_report(100.0, DIGEST_A),
            current_receipts=_receipts_payload(),
            previous_receipts=_receipts_payload(),
            live_timing=_full_timing_report(300.0, DIGEST_B),
            pinned_memory=_memory_report(2048, DIGEST_A),
            live_memory=_memory_report(4096, DIGEST_B),
            source_health=_source_health_payload(),
        )
        assert perf_alert.main(["sync", "--handoff-dir", str(below_dir)]) == 0
        assert fake_client.created_issues == []

        # 2. Drifted pinned leg + huge live slowdown -> no-op (D-24-01 + ALERT-02)
        drifted_dir = _stage_handoff_dir(
            tmp_path / "drifted",
            pinned_drifted="true",
            create_drifted_file=True,
            current_pinned=_full_timing_report(150.0, DIGEST_A),
            previous_pinned=_slim_timing_report(100.0, DIGEST_A),
            live_timing=_full_timing_report(500.0, DIGEST_B),
        )
        assert perf_alert.main(["sync", "--handoff-dir", str(drifted_dir)]) == 0
        assert fake_client.created_issues == []

    def test_tracer_opens_on_breach_then_closes_on_recovery(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import scripts.perf_alert as perf_alert

        fake_client = FakeGitHubIssueClient()
        monkeypatch.setattr(perf_alert, "GhCliIssueClient", lambda *a, **kw: fake_client)
        monkeypatch.setenv("GH_REPO", "MissionWAR/BlocklistMerger")
        summary_file = tmp_path / "step_summary.md"
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))

        # Week 1: 180.0s -> 207.0s (+15.0% exact breach) opens one issue
        open_dir = _stage_handoff_dir(
            tmp_path / "week1-open",
            run_id="34099999999",
            baseline_run_id="34040028893",
            current_pinned=_full_timing_report(207.0, DIGEST_A, created_at="2026-09-13T03:35:00Z"),
            previous_pinned=_slim_timing_report(180.0, DIGEST_A, created_at="2026-09-06T03:30:00Z"),
            current_receipts=_receipts_payload(),
            previous_receipts=_receipts_payload(run_id="34040028893"),
            live_timing=_full_timing_report(210.0, DIGEST_B),
            pinned_memory=_memory_report(2048, DIGEST_A),
            live_memory=_memory_report(4096, DIGEST_B),
            source_health=_source_health_payload(),
        )
        assert perf_alert.main(["sync", "--handoff-dir", str(open_dir)]) == 0
        assert len(fake_client.created_issues) == 1
        created = fake_client.created_issues[0]
        assert created["labels"] == [{"name": perf_alert.PRODUCTION_ALERT_LABEL}]
        assert "+15.0%" in created["body"] or "+15.00%" in created["body"]
        assert "34040028893" in created["body"]
        assert "34099999999" in created["body"]

        state = perf_alert.parse_state_marker(created["body"])
        assert state is not None
        assert state.status == "open"
        assert state.anchor_seconds == 180.0
        assert state.anchor_manifest_sha256 == DIGEST_A
        assert state.anchor_run_id == "34040028893"

        # Week 2: returns to 180.0s (<= anchor_seconds) -> closes issue with recovery comment
        recover_dir = _stage_handoff_dir(
            tmp_path / "week2-recover",
            run_id="34150000000",
            baseline_run_id="34099999999",
            current_pinned=_full_timing_report(180.0, DIGEST_A, created_at="2026-09-20T03:35:00Z"),
            previous_pinned=_full_timing_report(207.0, DIGEST_A, created_at="2026-09-13T03:35:00Z"),
            current_receipts=_receipts_payload(run_id="34150000000"),
            previous_receipts=_receipts_payload(run_id="34099999999"),
            live_timing=_full_timing_report(185.0, DIGEST_B),
            pinned_memory=_memory_report(2048, DIGEST_A),
            live_memory=_memory_report(4096, DIGEST_B),
            source_health=_source_health_payload(),
        )
        assert perf_alert.main(["sync", "--handoff-dir", str(recover_dir)]) == 0
        assert len(fake_client.created_issues) == 1
        assert len(fake_client.created_comments) == 1
        assert len(fake_client.updated_issues) == 1
        closed_update = fake_client.updated_issues[0]
        assert closed_update["state"] == "closed"
        assert closed_update["state_reason"] == "completed"
        closed_state = perf_alert.parse_state_marker(closed_update["body"])
        assert closed_state is not None
        assert closed_state.status == "recovered"
        assert closed_state.anchor_seconds == 180.0


def _context(
    *,
    run_id: str = "34100000001",
    baseline_run_id: str = "34040028893",
    snapshot_digest: str = DIGEST_A,
    pinned_drifted: str = "false",
    event_name: str = "schedule",
    smoke_mode: str = "none",
    step_outcomes: dict[str, str] | None = None,
) -> object:
    from scripts.perf_alert import AlertContext

    return AlertContext(
        run_id=run_id,
        run_attempt="1",
        run_url=f"https://github.com/MissionWAR/BlocklistMerger/actions/runs/{run_id}",
        repo="MissionWAR/BlocklistMerger",
        git_sha="abc1234",
        event_name=event_name,
        smoke_mode=smoke_mode,
        pinned_snapshot_digest=snapshot_digest,
        pinned_snapshot_run_id="34037935171",
        pinned_drifted=pinned_drifted,
        baseline_run_id=baseline_run_id,
        step_outcomes=step_outcomes
        or {
            "restore": "success",
            "pinned_timing": "success",
            "pinned_memory": "success",
            "fetch": "success",
            "live_timing": "success",
            "live_memory": "success",
            "download_prior": "success",
        },
    )


def _open_episode_state(
    *,
    episode_mode: str = "production",
    status: str = "open",
    anchor_seconds: float = 180.0,
    anchor_manifest: str = DIGEST_A,
    anchor_run_id: str = "34040028893",
    opened_run_id: str = "34099999999",
    recorded_run_ids: list[str] | None = None,
    notified_corpus_digests: list[str] | None = None,
    anchor_receipts: dict[str, object] | None = None,
) -> object:
    from scripts.perf_alert import EpisodeState, HistoryEntry

    return EpisodeState(
        episode_mode=episode_mode,
        status=status,
        anchor_seconds=anchor_seconds,
        anchor_manifest_sha256=anchor_manifest,
        anchor_run_id=anchor_run_id,
        anchor_created_at="2026-09-06T03:30:00Z",
        anchor_receipts=anchor_receipts
        if anchor_receipts is not None
        else {
            "cpu_model": "AMD EPYC 7763 64-Core Processor",
            "runner_image": "ubuntu-24.04",
            "runner_image_version": "20260901.1",
            "python_version": "Python 3.14.7",
        },
        opened_at="2026-09-13T03:35:00Z",
        opened_run_id=opened_run_id,
        recorded_run_ids=list(recorded_run_ids or [opened_run_id]),
        notified_corpus_digests=list(notified_corpus_digests or []),
        history=[
            HistoryEntry(
                date="2026-09-13",
                run_id=opened_run_id,
                current_seconds=216.0,
                anchor_delta_pct=20.0,
                rolling_seconds=anchor_seconds,
                rolling_delta_pct=20.0,
                env_changed=False,
                missing_legs=(),
            )
        ],
    )


def _issue_record(
    *,
    number: int = 42,
    issue_state: str = "open",
    episode_state: object,
    label: str = "perf-regression",
) -> object:
    from scripts.perf_alert import IssueRecord, format_state_marker

    return IssueRecord(
        number=number,
        title="Perf regression",
        body=f"Details\n\n{format_state_marker(episode_state)}\n",
        state=issue_state,
        labels=(label,),
        episode_state=episode_state,
    )


class TestFullThirteenRowStateMachine:
    """Cover every row (1..13) of the Phase 24 episode state-transition matrix."""

    def test_row_1_to_4_no_active_episode_transitions(self) -> None:
        from scripts.perf_alert import TimingReport, evaluate_episode

        # Row 1: degraded current pinned (drifted and snapshot-digest mismatch) -> noop
        d1 = evaluate_episode(
            context=_context(pinned_drifted="true"),
            current_pinned=TimingReport(216.0, DIGEST_A, "2026-09-13T03:35:00Z"),
            rolling_baseline=TimingReport(180.0, DIGEST_A, "2026-09-06T03:30:00Z"),
            is_drifted=True,
        )
        assert d1.action == "noop"

        d1_digest_mismatch = evaluate_episode(
            context=_context(snapshot_digest=DIGEST_B),
            current_pinned=TimingReport(216.0, DIGEST_A, "2026-09-13T03:35:00Z"),
            rolling_baseline=TimingReport(180.0, DIGEST_A, "2026-09-06T03:30:00Z"),
            is_drifted=False,
        )
        assert d1_digest_mismatch.action == "noop"

        # Row 2: missing or mismatched rolling baseline -> noop
        d2_missing = evaluate_episode(
            context=_context(baseline_run_id=""),
            current_pinned=TimingReport(216.0, DIGEST_A, "2026-09-13T03:35:00Z"),
            rolling_baseline=None,
            is_drifted=False,
        )
        assert d2_missing.action == "noop"

        d2_mismatch = evaluate_episode(
            context=_context(snapshot_digest=DIGEST_B),
            current_pinned=TimingReport(216.0, DIGEST_B, "2026-09-13T03:35:00Z"),
            rolling_baseline=TimingReport(180.0, DIGEST_A, "2026-09-06T03:30:00Z"),
            is_drifted=False,
        )
        assert d2_mismatch.action == "noop"

        # Row 3: valid < 15.0% -> noop
        d3 = evaluate_episode(
            context=_context(),
            current_pinned=TimingReport(206.9, DIGEST_A, "2026-09-13T03:35:00Z"),
            rolling_baseline=TimingReport(180.0, DIGEST_A, "2026-09-06T03:30:00Z"),
            is_drifted=False,
        )
        assert d3.action == "noop"

        # Row 4: valid >= 15.0% after prior recovered episode -> opens new episode
        prior_recovered = _issue_record(
            number=11,
            issue_state="closed",
            episode_state=_open_episode_state(status="recovered", opened_run_id="34000000000"),
        )
        d4 = evaluate_episode(
            context=_context(run_id="34100000099"),
            current_pinned=TimingReport(207.0, DIGEST_A, "2026-09-13T03:35:00Z"),
            rolling_baseline=TimingReport(180.0, DIGEST_A, "2026-09-06T03:30:00Z"),
            is_drifted=False,
            active_issue=prior_recovered,
        )
        assert d4.action == "open"
        assert d4.next_state is not None
        assert d4.next_state.anchor_seconds == 180.0
        assert d4.next_state.anchor_manifest_sha256 == DIGEST_A
        assert d4.next_state.recorded_run_ids == ["34100000099"]

    def test_row_5_degraded_week_in_open_episode_is_noop(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import scripts.perf_alert as perf_alert

        open_state = _open_episode_state()
        open_issue = {
            "number": 42,
            "title": "Perf regression",
            "body": f"Body\n\n{perf_alert.format_state_marker(open_state)}\n",
            "state": "open",
            "labels": [{"name": perf_alert.PRODUCTION_ALERT_LABEL}],
        }
        fake_client = FakeGitHubIssueClient([open_issue])
        monkeypatch.setattr(perf_alert, "GhCliIssueClient", lambda *a, **kw: fake_client)
        monkeypatch.setenv("GH_REPO", "MissionWAR/BlocklistMerger")

        degraded_dir = _stage_handoff_dir(
            tmp_path / "row5-degraded",
            run_id="34110000001",
            pinned_drifted="true",
            create_drifted_file=True,
            current_pinned=None,
            previous_pinned=_full_timing_report(216.0, DIGEST_A),
        )
        assert perf_alert.main(["sync", "--handoff-dir", str(degraded_dir)]) == 0
        assert fake_client.updated_issues == []
        assert fake_client.created_comments == []
        assert fake_client.created_issues == []
        assert fake_client.issues[0]["state"] == "open"

    def test_row_6_same_corpus_missing_or_expired_rolling_baseline_holds_open(self) -> None:
        from scripts.perf_alert import TimingReport, evaluate_episode

        open_issue = _issue_record(
            number=42, issue_state="open", episode_state=_open_episode_state()
        )
        decision = evaluate_episode(
            context=_context(run_id="34200000001", baseline_run_id="", snapshot_digest=DIGEST_A),
            current_pinned=TimingReport(170.0, DIGEST_A, "2026-12-20T03:35:00Z"),
            rolling_baseline=None,
            is_drifted=False,
            active_issue=open_issue,
        )
        assert decision.action == "noop"

    def test_row_7_repin_week_n_precedes_row_6_and_week_n_plus_1_is_idempotent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Week N of D1 -> D2 re-pin must hit Row 7 before Row 6, even when prior holds D1."""
        import scripts.perf_alert as perf_alert

        open_state = _open_episode_state(anchor_manifest=DIGEST_A)
        open_issue = {
            "number": 42,
            "title": "Perf regression",
            "body": perf_alert.render_issue_body(
                open_state,
                _context(run_id="34099999999", snapshot_digest=DIGEST_A),
            ),
            "state": "open",
            "labels": [{"name": perf_alert.PRODUCTION_ALERT_LABEL}],
        }
        fake_client = FakeGitHubIssueClient([open_issue])
        monkeypatch.setattr(perf_alert, "GhCliIssueClient", lambda *a, **kw: fake_client)
        monkeypatch.setenv("GH_REPO", "MissionWAR/BlocklistMerger")

        # Week N: current_pinned is valid on D2 (DIGEST_B), previous/pinned-timing still holds D1!
        week_n_dir = _stage_handoff_dir(
            tmp_path / "week-n-repin",
            run_id="34110000001",
            baseline_run_id="34099999999",
            snapshot_digest=DIGEST_B,
            current_pinned=_full_timing_report(120.0, DIGEST_B, created_at="2026-09-20T03:35:00Z"),
            previous_pinned=_full_timing_report(216.0, DIGEST_A, created_at="2026-09-13T03:35:00Z"),
            current_receipts=_receipts_payload(
                pinned_manifest_sha256=DIGEST_B, run_id="34110000001"
            ),
            previous_receipts=_receipts_payload(
                pinned_manifest_sha256=DIGEST_A, run_id="34099999999"
            ),
            live_timing=_full_timing_report(190.0, DIGEST_C),
            pinned_memory=_memory_report(2048, DIGEST_B),
            live_memory=_memory_report(4096, DIGEST_C),
            source_health=_source_health_payload(),
        )
        assert perf_alert.main(["sync", "--handoff-dir", str(week_n_dir)]) == 0
        assert fake_client.issues[0]["state"] == "open"
        assert len(fake_client.created_comments) == 1
        notice_marker = f"<!-- perf-alert-comment:corpus-changed-{DIGEST_B[:12]} -->"
        assert notice_marker in fake_client.created_comments[0]["body"]
        assert len(fake_client.updated_issues) == 1
        assert fake_client.updated_issues[0]["state"] is None
        updated_state = perf_alert.parse_state_marker(fake_client.updated_issues[0]["body"])
        assert updated_state is not None
        assert updated_state.status == "open"
        assert updated_state.anchor_seconds == 180.0
        assert updated_state.anchor_manifest_sha256 == DIGEST_A
        assert DIGEST_B in updated_state.notified_corpus_digests
        assert "34110000001" in updated_state.recorded_run_ids
        assert len(updated_state.history) == 1

        # Week N+1: both current and previous are on D2 -> idempotent no-op, no duplicate comment
        week_n_plus_1_dir = _stage_handoff_dir(
            tmp_path / "week-n-plus-1-repin",
            run_id="34120000002",
            baseline_run_id="34110000001",
            snapshot_digest=DIGEST_B,
            current_pinned=_full_timing_report(120.0, DIGEST_B, created_at="2026-09-27T03:35:00Z"),
            previous_pinned=_full_timing_report(120.0, DIGEST_B, created_at="2026-09-20T03:35:00Z"),
            current_receipts=_receipts_payload(
                pinned_manifest_sha256=DIGEST_B, run_id="34120000002"
            ),
            previous_receipts=_receipts_payload(
                pinned_manifest_sha256=DIGEST_B, run_id="34110000001"
            ),
            live_timing=_full_timing_report(190.0, DIGEST_C),
            pinned_memory=_memory_report(2048, DIGEST_B),
            live_memory=_memory_report(4096, DIGEST_C),
            source_health=_source_health_payload(),
        )
        assert perf_alert.main(["sync", "--handoff-dir", str(week_n_plus_1_dir)]) == 0
        assert len(fake_client.created_comments) == 1
        assert len(fake_client.updated_issues) == 1
        assert fake_client.issues[0]["state"] == "open"

    @pytest.mark.parametrize(
        ("current_sec", "expected_anchor_delta", "expected_rolling_delta"),
        [
            pytest.param(225.0, 25.0, 225.0 / 216.0 * 100.0 - 100.0, id="worse"),
            pytest.param(216.0, 20.0, 0.0, id="flat"),
            pytest.param(198.0, 10.0, (198.0 - 216.0) / 216.0 * 100.0, id="partial-recovery"),
        ],
    )
    def test_row_8_continuation_and_partial_recovery_stay_open(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        current_sec: float,
        expected_anchor_delta: float,
        expected_rolling_delta: float,
    ) -> None:
        import scripts.perf_alert as perf_alert

        open_state = _open_episode_state(anchor_seconds=180.0)
        open_issue = {
            "number": 42,
            "title": "Perf regression",
            "body": perf_alert.render_issue_body(open_state, _context(run_id="34099999999")),
            "state": "open",
            "labels": [{"name": perf_alert.PRODUCTION_ALERT_LABEL}],
        }
        fake_client = FakeGitHubIssueClient([open_issue])
        monkeypatch.setattr(perf_alert, "GhCliIssueClient", lambda *a, **kw: fake_client)
        monkeypatch.setenv("GH_REPO", "MissionWAR/BlocklistMerger")

        cont_dir = _stage_handoff_dir(
            tmp_path / "row8-cont",
            run_id="34110000001",
            baseline_run_id="34099999999",
            current_pinned=_full_timing_report(
                current_sec, DIGEST_A, created_at="2026-09-20T03:35:00Z"
            ),
            previous_pinned=_full_timing_report(216.0, DIGEST_A, created_at="2026-09-13T03:35:00Z"),
            current_receipts=_receipts_payload(run_id="34110000001"),
            previous_receipts=_receipts_payload(run_id="34099999999"),
            live_timing=_full_timing_report(190.0, DIGEST_B),
            pinned_memory=_memory_report(2048, DIGEST_A),
            live_memory=_memory_report(4096, DIGEST_B),
            source_health=_source_health_payload(),
        )
        assert perf_alert.main(["sync", "--handoff-dir", str(cont_dir)]) == 0
        assert fake_client.issues[0]["state"] == "open"
        assert len(fake_client.created_comments) == 1
        assert (
            "<!-- perf-alert-comment:run-34110000001 -->" in fake_client.created_comments[0]["body"]
        )
        assert len(fake_client.updated_issues) == 1
        assert fake_client.updated_issues[0]["state"] is None

        updated_state = perf_alert.parse_state_marker(fake_client.updated_issues[0]["body"])
        assert updated_state is not None
        assert updated_state.status == "open"
        assert updated_state.anchor_seconds == 180.0
        assert len(updated_state.history) == 2
        latest_row = updated_state.history[-1]
        assert latest_row.anchor_delta_pct == pytest.approx(expected_anchor_delta)
        assert latest_row.rolling_delta_pct == pytest.approx(expected_rolling_delta)
        # Body history table retains both Week 1 (+20.00%) and Week 2 deltas (D-24-10)
        assert "+20.00%" in fake_client.updated_issues[0]["body"]
        assert f"{expected_anchor_delta:+.2f}%" in fake_client.updated_issues[0]["body"]

    def test_rows_10_to_12_manual_closure_respected_then_silently_retired(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import scripts.perf_alert as perf_alert

        # Issue #42 was manually closed by maintainer while marker status == "open"
        open_state = _open_episode_state(anchor_seconds=180.0)
        manually_closed_issue = {
            "number": 42,
            "title": "Perf regression",
            "body": perf_alert.render_issue_body(open_state, _context(run_id="34099999999")),
            "state": "closed",
            "state_reason": "completed",
            "labels": [{"name": perf_alert.PRODUCTION_ALERT_LABEL}],
        }
        fake_client = FakeGitHubIssueClient([manually_closed_issue])
        monkeypatch.setattr(perf_alert, "GhCliIssueClient", lambda *a, **kw: fake_client)
        monkeypatch.setenv("GH_REPO", "MissionWAR/BlocklistMerger")

        # Row 10: degraded week and mid-episode corpus re-pin while manually closed -> noop
        r10_dir = _stage_handoff_dir(
            tmp_path / "row10",
            run_id="34110000001",
            pinned_drifted="true",
            create_drifted_file=True,
        )
        assert perf_alert.main(["sync", "--handoff-dir", str(r10_dir)]) == 0
        r10_repin_dir = _stage_handoff_dir(
            tmp_path / "row10-repin",
            run_id="34110000099",
            baseline_run_id="34099999999",
            snapshot_digest=DIGEST_B,
            current_pinned=_full_timing_report(120.0, DIGEST_B),
            previous_pinned=_full_timing_report(216.0, DIGEST_A),
        )
        assert perf_alert.main(["sync", "--handoff-dir", str(r10_repin_dir)]) == 0
        assert fake_client.created_issues == []
        assert fake_client.updated_issues == []
        assert fake_client.created_comments == []

        # Row 11: unrecovered AND >= 15% slower than rolling -> MUST NOT reopen or duplicate
        r11_dir = _stage_handoff_dir(
            tmp_path / "row11",
            run_id="34120000002",
            baseline_run_id="34110000001",
            current_pinned=_full_timing_report(240.0, DIGEST_A),
            previous_pinned=_full_timing_report(200.0, DIGEST_A),
            current_receipts=_receipts_payload(run_id="34120000002"),
            previous_receipts=_receipts_payload(run_id="34110000001"),
            live_timing=_full_timing_report(190.0, DIGEST_B),
            pinned_memory=_memory_report(2048, DIGEST_A),
            live_memory=_memory_report(4096, DIGEST_B),
            source_health=_source_health_payload(),
        )
        assert perf_alert.main(["sync", "--handoff-dir", str(r11_dir)]) == 0
        assert fake_client.created_issues == []
        assert fake_client.updated_issues == []
        assert fake_client.created_comments == []
        assert fake_client.issues[0]["state"] == "closed"

        # Row 12: returns <= anchor -> silent body marker retirement, NO comment, stays closed
        r12_dir = _stage_handoff_dir(
            tmp_path / "row12",
            run_id="34130000003",
            baseline_run_id="34120000002",
            current_pinned=_full_timing_report(175.0, DIGEST_A),
            previous_pinned=_full_timing_report(240.0, DIGEST_A),
            current_receipts=_receipts_payload(run_id="34130000003"),
            previous_receipts=_receipts_payload(run_id="34120000002"),
            live_timing=_full_timing_report(190.0, DIGEST_B),
            pinned_memory=_memory_report(2048, DIGEST_A),
            live_memory=_memory_report(4096, DIGEST_B),
            source_health=_source_health_payload(),
        )
        assert perf_alert.main(["sync", "--handoff-dir", str(r12_dir)]) == 0
        assert fake_client.created_comments == []
        assert len(fake_client.updated_issues) == 1
        assert fake_client.updated_issues[0]["state"] is None
        assert fake_client.issues[0]["state"] == "closed"
        retired_state = perf_alert.parse_state_marker(fake_client.issues[0]["body"])
        assert retired_state is not None
        assert retired_state.status == "recovered"

        # Subsequent brand-new >= 15% breach (175s -> 210s, +20%) now opens fresh issue #43
        new_breach_dir = _stage_handoff_dir(
            tmp_path / "new-episode",
            run_id="34140000004",
            baseline_run_id="34130000003",
            current_pinned=_full_timing_report(210.0, DIGEST_A),
            previous_pinned=_full_timing_report(175.0, DIGEST_A),
            current_receipts=_receipts_payload(run_id="34140000004"),
            previous_receipts=_receipts_payload(run_id="34130000003"),
            live_timing=_full_timing_report(190.0, DIGEST_B),
            pinned_memory=_memory_report(2048, DIGEST_A),
            live_memory=_memory_report(4096, DIGEST_B),
            source_health=_source_health_payload(),
        )
        assert perf_alert.main(["sync", "--handoff-dir", str(new_breach_dir)]) == 0
        assert len(fake_client.created_issues) == 1
        assert fake_client.created_issues[0]["number"] == 43

    def test_row_13_replay_idempotency_and_recorded_run_ids_cap(self) -> None:
        from scripts.perf_alert import MAX_RECORDED_RUN_IDS, TimingReport, evaluate_episode

        existing_ids = [f"run-{i}" for i in range(MAX_RECORDED_RUN_IDS)]
        state = _open_episode_state(opened_run_id="run-0", recorded_run_ids=existing_ids)
        open_issue = _issue_record(number=42, issue_state="open", episode_state=state)

        # Replaying an already recorded run_id -> noop regardless of metrics
        replay_decision = evaluate_episode(
            context=_context(run_id="run-0"),
            current_pinned=TimingReport(100.0, DIGEST_A, "2026-09-20T03:35:00Z"),
            rolling_baseline=TimingReport(216.0, DIGEST_A, "2026-09-13T03:35:00Z"),
            is_drifted=False,
            active_issue=open_issue,
        )
        assert replay_decision.action == "noop"
        assert replay_decision.reason == "row_13_replay"

        # Adding run 101 caps recorded_run_ids at MAX_RECORDED_RUN_IDS while retaining opened_run_id
        update_decision = evaluate_episode(
            context=_context(run_id="run-100"),
            current_pinned=TimingReport(220.0, DIGEST_A, "2026-09-20T03:35:00Z"),
            rolling_baseline=TimingReport(216.0, DIGEST_A, "2026-09-13T03:35:00Z"),
            is_drifted=False,
            active_issue=open_issue,
        )
        assert update_decision.action == "update"
        assert update_decision.next_state is not None
        assert len(update_decision.next_state.recorded_run_ids) == MAX_RECORDED_RUN_IDS
        assert update_decision.next_state.recorded_run_ids[0] == "run-0"
        assert "run-100" in update_decision.next_state.recorded_run_ids

    def test_row_7_hold_open_preserves_env_changes_and_missing_legs(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import scripts.perf_alert as perf_alert
        from scripts.perf_alert import ReceiptSnapshot, TimingReport, evaluate_episode

        open_state = _open_episode_state(anchor_manifest=DIGEST_A)
        open_issue = _issue_record(number=42, issue_state="open", episode_state=open_state)
        decision = evaluate_episode(
            context=_context(run_id="34110000001", snapshot_digest=DIGEST_B),
            current_pinned=TimingReport(120.0, DIGEST_B, "2026-09-20T03:35:00Z"),
            rolling_baseline=TimingReport(216.0, DIGEST_A, "2026-09-13T03:35:00Z"),
            is_drifted=False,
            active_issue=open_issue,
            current_receipts=ReceiptSnapshot(
                cpu_model="AMD EPYC 9R14",
                runner_image="ubuntu-24.04",
                runner_image_version="20260910.1",
                python_version="Python 3.14.8",
            ),
            missing_legs=("fetch", "live_timing"),
        )
        assert decision.action == "hold_open"
        assert decision.reason == "row_7_corpus_changed_hold"
        assert decision.missing_legs == ("fetch", "live_timing")
        assert decision.prior_receipts_unavailable is False
        assert any("AMD EPYC 9R14" in line for line in decision.env_changes)

        open_issue_dict = {
            "number": 42,
            "title": "Perf regression",
            "body": perf_alert.render_issue_body(
                open_state,
                _context(run_id="34099999999", snapshot_digest=DIGEST_A),
            ),
            "state": "open",
            "labels": [{"name": perf_alert.PRODUCTION_ALERT_LABEL}],
        }
        fake_client = FakeGitHubIssueClient([open_issue_dict])
        monkeypatch.setattr(perf_alert, "GhCliIssueClient", lambda *a, **kw: fake_client)
        monkeypatch.setenv("GH_REPO", "MissionWAR/BlocklistMerger")

        repin_dir = _stage_handoff_dir(
            tmp_path / "row7-callouts",
            run_id="34110000001",
            baseline_run_id="34099999999",
            snapshot_digest=DIGEST_B,
            current_pinned=_full_timing_report(120.0, DIGEST_B, created_at="2026-09-20T03:35:00Z"),
            previous_pinned=_full_timing_report(216.0, DIGEST_A, created_at="2026-09-13T03:35:00Z"),
            current_receipts=_receipts_payload(
                cpu_model="AMD EPYC 9R14",
                pinned_manifest_sha256=DIGEST_B,
                run_id="34110000001",
            ),
            previous_receipts=_receipts_payload(
                pinned_manifest_sha256=DIGEST_A, run_id="34099999999"
            ),
            live_timing=None,
            pinned_memory=_memory_report(2048, DIGEST_B),
            live_memory=_memory_report(4096, DIGEST_C),
            source_health=_source_health_payload(),
            step_outcomes={
                "restore": "success",
                "pinned_timing": "success",
                "pinned_memory": "success",
                "fetch": "success",
                "live_timing": "failure",
                "live_memory": "success",
                "download_prior": "success",
            },
        )
        assert perf_alert.main(["sync", "--handoff-dir", str(repin_dir)]) == 0
        assert len(fake_client.updated_issues) == 1
        updated_body = str(fake_client.updated_issues[0]["body"])
        assert "Environment Changes Observed" in updated_body
        assert "AMD EPYC 9R14" in updated_body
        assert "Missing Supporting Evidence" in updated_body
        assert "live_timing" in updated_body

    def test_evaluate_episode_rejects_episode_mode_mismatch(self) -> None:
        from scripts.perf_alert import PerfAlertError, evaluate_episode

        prod_ctx = _context(event_name="schedule")
        smoke_state = _open_episode_state(episode_mode="smoke")
        with pytest.raises(PerfAlertError, match="Episode mode mismatch"):
            evaluate_episode(
                context=prod_ctx,
                current_pinned=None,
                rolling_baseline=None,
                is_drifted=True,
                active_state=smoke_state,
            )

        smoke_ctx = _context(event_name="workflow_dispatch", smoke_mode="regression")
        prod_issue = _issue_record(
            number=7,
            issue_state="open",
            episode_state=_open_episode_state(episode_mode="production"),
            label="perf-regression-test",
        )
        with pytest.raises(PerfAlertError, match="Episode mode mismatch"):
            evaluate_episode(
                context=smoke_ctx,
                current_pinned=None,
                rolling_baseline=None,
                is_drifted=True,
                active_issue=prod_issue,
            )


class TestEnvironmentReceiptDiffs:
    """Verify D-24-04 receipt diffing, Python prefix normalization, and Phase 22 fallback."""

    def test_python_version_prefix_normalization(self) -> None:
        from scripts.perf_alert import ReceiptSnapshot, diff_receipts, normalize_python_version

        assert normalize_python_version("Python 3.14.7") == "3.14.7"
        assert normalize_python_version("3.14.7") == "3.14.7"

        baseline = ReceiptSnapshot(
            cpu_model="AMD EPYC 7763 64-Core Processor",
            runner_image="ubuntu-24.04",
            runner_image_version="20260901.1",
            python_version="3.14.7",
        )
        current = ReceiptSnapshot(
            cpu_model="AMD EPYC 7763 64-Core Processor",
            runner_image="ubuntu-24.04",
            runner_image_version="20260901.1",
            python_version="Python 3.14.7",
        )
        diff = diff_receipts(baseline, current)
        assert diff.env_changed is False
        assert diff.changes == ()

    def test_phase_22_missing_previous_receipts_uses_identity_fallback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import scripts.perf_alert as perf_alert

        fake_client = FakeGitHubIssueClient()
        monkeypatch.setattr(perf_alert, "GhCliIssueClient", lambda *a, **kw: fake_client)
        monkeypatch.setenv("GH_REPO", "MissionWAR/BlocklistMerger")

        # No previous/receipts.json: use previous/pinned-timing.json identity fallback
        handoff_dir = _stage_handoff_dir(
            tmp_path / "phase22-fallback",
            run_id="34099999999",
            baseline_run_id="34040028893",
            current_pinned=_full_timing_report(216.0, DIGEST_A),
            previous_pinned=_slim_timing_report(180.0, DIGEST_A),
            current_receipts=_receipts_payload(python_version="Python 3.14.7"),
            previous_receipts=None,
            live_timing=_full_timing_report(185.0, DIGEST_B),
            pinned_memory=_memory_report(2048, DIGEST_A),
            live_memory=_memory_report(4096, DIGEST_B),
            source_health=_source_health_payload(),
        )

        bundle = perf_alert.load_handoff_bundle(handoff_dir)
        assert bundle.prior_receipts is not None
        assert bundle.prior_receipts.prior_receipts_unavailable is True
        diff = perf_alert.diff_receipts(bundle.prior_receipts, bundle.current_receipts)
        assert diff.prior_receipts_unavailable is True
        assert diff.env_changed is False
        assert diff.changes == ()

        # Only Python patch version change on fallback reports python_version, never false CPU/image
        from dataclasses import replace

        patch_diff = perf_alert.diff_receipts(
            bundle.prior_receipts,
            replace(bundle.current_receipts, python_version="Python 3.14.8"),
        )
        assert patch_diff.prior_receipts_unavailable is True
        assert patch_diff.env_changed is True
        assert patch_diff.changes == (("python_version", "3.14.7", "Python 3.14.8"),)

        assert perf_alert.main(["sync", "--handoff-dir", str(handoff_dir)]) == 0
        assert len(fake_client.created_issues) == 1
        assert "prior receipts unavailable" in fake_client.created_issues[0]["body"].lower()

    def test_changed_cpu_and_runner_image_do_not_suppress_alert_and_render_prominently(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import scripts.perf_alert as perf_alert

        fake_client = FakeGitHubIssueClient()
        monkeypatch.setattr(perf_alert, "GhCliIssueClient", lambda *a, **kw: fake_client)
        monkeypatch.setenv("GH_REPO", "MissionWAR/BlocklistMerger")

        changed_dir = _stage_handoff_dir(
            tmp_path / "env-changed",
            run_id="34099999999",
            baseline_run_id="34040028893",
            current_pinned=_full_timing_report(216.0, DIGEST_A),
            previous_pinned=_full_timing_report(180.0, DIGEST_A),
            current_receipts=_receipts_payload(
                cpu_model="AMD EPYC 9R14",
                runner_image="ubuntu-24.04",
                runner_image_version="20260910.1",
                python_version="Python 3.14.8",
            ),
            previous_receipts=_receipts_payload(
                cpu_model="AMD EPYC 7763 64-Core Processor",
                runner_image="ubuntu-24.04",
                runner_image_version="20260901.1",
                python_version="Python 3.14.7",
                run_id="34040028893",
            ),
            live_timing=_full_timing_report(185.0, DIGEST_B),
            pinned_memory=_memory_report(2048, DIGEST_A),
            live_memory=_memory_report(4096, DIGEST_B),
            source_health=_source_health_payload(),
        )
        assert perf_alert.main(["sync", "--handoff-dir", str(changed_dir)]) == 0
        assert len(fake_client.created_issues) == 1
        body = fake_client.created_issues[0]["body"]
        assert "Environment Changes Observed" in body
        assert "AMD EPYC 7763" in body
        assert "AMD EPYC 9R14" in body
        assert "not proven to be a code regression" in body

    def test_diff_receipts_skips_unknown_placeholders_and_falls_back_to_current_pinned(
        self, tmp_path: Path
    ) -> None:
        from scripts.perf_alert import ReceiptSnapshot, diff_receipts, load_handoff_bundle

        unknown_baseline = ReceiptSnapshot(
            cpu_model="unknown",
            runner_image="unknown (see the runner log)",
            runner_image_version="Unknown (see the runner log)",
            python_version="3.14.7",
        )
        known_current = ReceiptSnapshot(
            cpu_model="AMD EPYC 7763 64-Core Processor",
            runner_image="ubuntu-24.04",
            runner_image_version="20260901.1",
            python_version="Python 3.14.7",
        )
        diff_forward = diff_receipts(unknown_baseline, known_current)
        assert diff_forward.env_changed is False
        assert diff_forward.changes == ()

        diff_reverse = diff_receipts(known_current, unknown_baseline)
        assert diff_reverse.env_changed is False
        assert diff_reverse.changes == ()

        # Missing receipts.json falls back to current_pinned.identity without false CPU diffs
        handoff_dir = _stage_handoff_dir(
            tmp_path / "missing-current-receipts",
            run_id="34099999999",
            baseline_run_id="34040028893",
            current_pinned=_full_timing_report(216.0, DIGEST_A, python_version="3.14.8"),
            previous_pinned=_full_timing_report(180.0, DIGEST_A, python_version="3.14.7"),
            current_receipts=None,
            previous_receipts=_receipts_payload(python_version="Python 3.14.7"),
        )
        bundle = load_handoff_bundle(handoff_dir)
        assert bundle.current_receipts is not None
        assert bundle.current_receipts.prior_receipts_unavailable is True
        assert bundle.current_receipts.python_version == "3.14.8"
        bundle_diff = diff_receipts(bundle.prior_receipts, bundle.current_receipts)
        assert bundle_diff.env_changed is True
        assert bundle_diff.changes == (("python_version", "Python 3.14.7", "3.14.8"),)


class TestNonPinnedLegIsolationAndIssueSelection:
    """Verify D-24-05 supporting leg isolation, T-24-02 PR/mode filtering, and body cap."""

    def test_skipped_smoke_steps_with_valid_synthetic_files_have_no_missing_legs(
        self, tmp_path: Path
    ) -> None:
        from scripts.perf_alert import detect_missing_legs, load_handoff_bundle

        smoke_dir = _stage_handoff_dir(
            tmp_path / "clean-smoke",
            event_name="workflow_dispatch",
            smoke_mode="regression",
            snapshot_digest=DIGEST_A,
            current_pinned=_full_timing_report(216.0, DIGEST_A),
            previous_pinned=_full_timing_report(180.0, DIGEST_A),
            current_receipts=_receipts_payload(),
            previous_receipts=_receipts_payload(),
            live_timing=_full_timing_report(185.0, DIGEST_B),
            pinned_memory=_memory_report(2048, DIGEST_A),
            live_memory=_memory_report(4096, DIGEST_B),
            source_health=_source_health_payload(),
            step_outcomes={
                "restore": "skipped",
                "pinned_timing": "skipped",
                "pinned_memory": "skipped",
                "fetch": "skipped",
                "live_timing": "skipped",
                "live_memory": "skipped",
                "download_prior": "skipped",
            },
        )
        bundle = load_handoff_bundle(smoke_dir)
        assert detect_missing_legs(smoke_dir, bundle.context) == ()
        assert bundle.missing_legs == ()

    def test_failed_and_corrupt_supporting_legs_do_not_suppress_pinned_breach(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import scripts.perf_alert as perf_alert

        fake_client = FakeGitHubIssueClient()
        monkeypatch.setattr(perf_alert, "GhCliIssueClient", lambda *a, **kw: fake_client)
        monkeypatch.setenv("GH_REPO", "MissionWAR/BlocklistMerger")

        handoff_dir = _stage_handoff_dir(
            tmp_path / "failed-supporting",
            run_id="34099999999",
            baseline_run_id="34040028893",
            current_pinned=_full_timing_report(216.0, DIGEST_A),
            previous_pinned=_full_timing_report(180.0, DIGEST_A),
            current_receipts=_receipts_payload(),
            previous_receipts=_receipts_payload(run_id="34040028893"),
            pinned_memory={"report_type": "corpus_benchmark", "mode": "timing"},  # invalid mode
            live_timing=None,  # missing
            live_memory=None,  # missing
            source_health=_source_health_payload(),
            step_outcomes={
                "restore": "success",
                "pinned_timing": "success",
                "pinned_memory": "success",
                "fetch": "failure",
                "live_timing": "failure",
                "live_memory": "skipped",
                "download_prior": "success",
            },
        )
        (handoff_dir / "source-health.json").write_text("{corrupt", encoding="utf-8")

        bundle = perf_alert.load_handoff_bundle(handoff_dir)
        assert set(bundle.missing_legs) == {
            "pinned_memory",
            "fetch",
            "live_timing",
            "live_memory",
        }

        assert perf_alert.main(["sync", "--handoff-dir", str(handoff_dir)]) == 0
        assert len(fake_client.created_issues) == 1
        body = fake_client.created_issues[0]["body"]
        assert "Missing Supporting Evidence" in body
        assert "fetch" in body
        assert "live_timing" in body

    def test_select_active_episode_issue_filters_prs_isolates_modes_and_sorts_numerically(
        self,
    ) -> None:
        from scripts.perf_alert import (
            PRODUCTION_ALERT_LABEL,
            SMOKE_ALERT_LABEL,
            format_state_marker,
            select_active_episode_issue,
        )

        prod_state_9 = _open_episode_state(episode_mode="production", opened_run_id="run-9")
        prod_state_10 = _open_episode_state(episode_mode="production", opened_run_id="run-10")
        smoke_state = _open_episode_state(episode_mode="smoke", opened_run_id="run-smoke")

        items: list[dict[str, object]] = [
            {
                "number": 999,
                "state": "open",
                "pull_request": {"url": "https://example.invalid/pulls/999"},
                "labels": [{"name": PRODUCTION_ALERT_LABEL}],
                "body": format_state_marker(prod_state_9),
            },
            {
                "number": 888,
                "state": "open",
                "labels": [{"name": PRODUCTION_ALERT_LABEL}],
                "body": format_state_marker(smoke_state),
            },
            {
                "number": 9,
                "state": "open",
                "labels": [{"name": PRODUCTION_ALERT_LABEL}],
                "body": format_state_marker(prod_state_9),
            },
            {
                "number": 10,
                "state": "open",
                "labels": [{"name": PRODUCTION_ALERT_LABEL}],
                "body": format_state_marker(prod_state_10),
            },
            {
                "number": 50,
                "state": "open",
                "labels": [{"name": SMOKE_ALERT_LABEL}],
                "body": format_state_marker(smoke_state),
            },
        ]

        selected_prod = select_active_episode_issue(
            items, episode_mode="production", required_label=PRODUCTION_ALERT_LABEL
        )
        assert selected_prod is not None
        assert selected_prod.number == 10

        selected_smoke = select_active_episode_issue(
            items, episode_mode="smoke", required_label=SMOKE_ALERT_LABEL
        )
        assert selected_smoke is not None
        assert selected_smoke.number == 50

    def test_render_issue_body_compacts_under_max_issue_body_chars(self) -> None:
        from scripts.perf_alert import (
            MAX_ISSUE_BODY_CHARS,
            EpisodeState,
            HistoryEntry,
            parse_state_marker,
            render_issue_body,
        )

        def _make_history(count: int) -> list[HistoryEntry]:
            return [
                HistoryEntry(
                    date=f"2026-09-{(i % 28) + 1:02d}",
                    run_id=f"3409999{i:04d}",
                    current_seconds=216.0 + i * 0.01,
                    anchor_delta_pct=20.0,
                    rolling_seconds=180.0,
                    rolling_delta_pct=20.0,
                    env_changed=True,
                    missing_legs=("fetch", "live_timing", "pinned_memory", "live_memory"),
                )
                for i in range(count)
            ]

        # Stage 1: ~210 rows pushes total body over 60k -> compacts Markdown table, keeps full JSON
        medium_history = _make_history(210)
        medium_state = EpisodeState(
            episode_mode="production",
            status="open",
            anchor_seconds=180.0,
            anchor_manifest_sha256=DIGEST_A,
            anchor_run_id="34040028893",
            anchor_created_at="2026-09-06T03:30:00Z",
            opened_at="2026-09-13T03:35:00Z",
            opened_run_id="34099990000",
            recorded_run_ids=["34099990000"],
            history=medium_history,
        )
        rendered_medium = render_issue_body(medium_state, _context(run_id="34099990209"))
        assert len(rendered_medium) <= MAX_ISSUE_BODY_CHARS
        assert "compacted" in rendered_medium
        assert parse_state_marker(rendered_medium) == medium_state

        # Stage 2: extreme 600-row history compacts JSON middle rows too, preserving opener & latest
        huge_history = _make_history(600)
        huge_state = EpisodeState(
            episode_mode="production",
            status="open",
            anchor_seconds=180.0,
            anchor_manifest_sha256=DIGEST_A,
            anchor_run_id="34040028893",
            anchor_created_at="2026-09-06T03:30:00Z",
            opened_at="2026-09-13T03:35:00Z",
            opened_run_id="34099990000",
            recorded_run_ids=["34099990000"],
            history=huge_history,
        )
        rendered_huge = render_issue_body(huge_state, _context(run_id="34099990599"))
        assert len(rendered_huge) <= MAX_ISSUE_BODY_CHARS
        parsed_huge = parse_state_marker(rendered_huge)
        assert parsed_huge is not None
        assert parsed_huge.history[0] == huge_history[0]
        assert parsed_huge.history[-1] == huge_history[-1]

    def test_partial_failure_comment_marker_deduplicates_on_retry_and_smoke_trigger_guard(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import scripts.perf_alert as perf_alert

        # Non-dispatch event must ignore smoke_mode (D-24-14)
        scheduled_smoke = _context(event_name="schedule", smoke_mode="regression")
        assert scheduled_smoke.effective_smoke_mode == "none"
        assert scheduled_smoke.episode_mode == "production"
        assert scheduled_smoke.alert_label == perf_alert.PRODUCTION_ALERT_LABEL

        # Partial-retry test: comment for run-34110000001 exists, marker not yet updated
        open_state = _open_episode_state(anchor_seconds=180.0)
        open_issue = {
            "number": 42,
            "title": "Perf regression",
            "body": perf_alert.render_issue_body(open_state, _context(run_id="34099999999")),
            "state": "open",
            "labels": [{"name": perf_alert.PRODUCTION_ALERT_LABEL}],
        }
        fake_client = FakeGitHubIssueClient([open_issue])
        fake_client.comments[42] = [
            {"id": 99, "body": "<!-- perf-alert-comment:run-34110000001 -->\nPrior partial comment"}
        ]
        monkeypatch.setattr(perf_alert, "GhCliIssueClient", lambda *a, **kw: fake_client)
        monkeypatch.setenv("GH_REPO", "MissionWAR/BlocklistMerger")

        retry_dir = _stage_handoff_dir(
            tmp_path / "partial-retry",
            run_id="34110000001",
            baseline_run_id="34099999999",
            current_pinned=_full_timing_report(225.0, DIGEST_A, created_at="2026-09-20T03:35:00Z"),
            previous_pinned=_full_timing_report(216.0, DIGEST_A, created_at="2026-09-13T03:35:00Z"),
            current_receipts=_receipts_payload(run_id="34110000001"),
            previous_receipts=_receipts_payload(run_id="34099999999"),
            live_timing=_full_timing_report(190.0, DIGEST_B),
            pinned_memory=_memory_report(2048, DIGEST_A),
            live_memory=_memory_report(4096, DIGEST_B),
            source_health=_source_health_payload(),
        )
        assert perf_alert.main(["sync", "--handoff-dir", str(retry_dir)]) == 0
        assert fake_client.created_comments == []
        assert len(fake_client.updated_issues) == 1
        updated = perf_alert.parse_state_marker(fake_client.updated_issues[0]["body"])
        assert updated is not None
        assert "34110000001" in updated.recorded_run_ids


class TestMarkdownRenderingAndCompaction:
    """Task 1: Sanitized rendering, D-24-03..D-24-12 copy, comments, and 500-week compaction."""

    def test_sanitize_markdown_text_neutralizes_comments_controls_and_pipes(self) -> None:
        from scripts.perf_alert import (
            HistoryEntry,
            parse_state_marker,
            render_continuation_comment,
            render_issue_body,
            render_recovery_comment,
            sanitize_markdown_text,
        )

        hostile = "AMD <!<!---- EPYC --<!--> 7763 | evil\\|cell\n\r\t\x00\x1f\x7f"
        cleaned = sanitize_markdown_text(hostile)
        assert "<!--" not in cleaned
        assert "-->" not in cleaned
        assert "--!>" not in cleaned
        assert all(ord(ch) >= 0x20 and ord(ch) != 0x7F for ch in cleaned)
        assert "\\|" in cleaned
        assert "|" not in cleaned.replace("\\|", "")

        state = _open_episode_state(
            anchor_receipts={
                "cpu_model": hostile,
                "runner_image": "ubuntu-24.04 | <!-- evil -->",
                "runner_image_version": "20260901.1\n-->",
                "python_version": "Python 3.14.7",
            }
        )
        state.history.append(
            HistoryEntry(
                date="2026-09-20",
                run_id="34110000001",
                current_seconds=210.0,
                anchor_delta_pct=16.67,
                rolling_seconds=216.0,
                rolling_delta_pct=-2.78,
                env_changed=True,
                missing_legs=("fetch | bad<!--x-->",),
            )
        )
        ctx = _context(run_id="34110000001")
        env_changes = (f"cpu_model: {hostile} -> Safe CPU",)
        body = render_issue_body(
            state,
            ctx,
            env_changes=env_changes,
            missing_legs=("fetch | bad<!--x-->",),
        )
        assert body.count("<!--") == 1
        assert body.count("-->") == 1
        assert parse_state_marker(body) == state

        cont = render_continuation_comment(
            state,
            ctx,
            env_changes=env_changes,
            missing_legs=("fetch | bad<!--x-->",),
        )
        assert cont.count("<!--") == 1
        assert cont.count("-->") == 1

        rec = render_recovery_comment(
            state,
            ctx,
            env_changes=env_changes,
            missing_legs=("fetch | bad<!--x-->",),
        )
        assert rec.count("<!--") == 1
        assert rec.count("-->") == 1

    def test_titles_baseline_links_smoke_labeling_and_multiweek_table(self) -> None:
        from scripts.perf_alert import (
            HistoryEntry,
            render_issue_body,
            render_issue_title,
        )

        state = _open_episode_state(anchor_seconds=180.0, anchor_run_id="34040028893")
        state.history.append(
            HistoryEntry(
                date="2026-09-20",
                run_id="34110000001",
                current_seconds=198.0,
                anchor_delta_pct=10.0,
                rolling_seconds=216.0,
                rolling_delta_pct=-8.33,
                env_changed=False,
                missing_legs=(),
            )
        )
        prod_ctx = _context(run_id="34110000001", baseline_run_id="34099999999")
        prod_title = render_issue_title(state, prod_ctx)
        assert "[SMOKE TEST]" not in prod_title
        assert "+10.00%" in prod_title

        prod_body = render_issue_body(state, prod_ctx)
        assert "advisory" in prod_body.lower()
        assert "noise" in prod_body.lower() or "vary" in prod_body.lower()
        assert "never block" in prod_body.lower()
        # Anchor baseline link points to anchor_run_id (not rolling baseline_run_id)
        assert "https://github.com/MissionWAR/BlocklistMerger/actions/runs/34040028893" in prod_body
        assert "https://github.com/MissionWAR/BlocklistMerger/actions/runs/34110000001" in prod_body
        # Multi-week history table preserves opening +20.00% and continuation +10.00% & -8.33%
        assert "+20.00%" in prod_body
        assert "+10.00%" in prod_body
        assert "-8.33%" in prod_body
        assert "34099999999" in prod_body
        assert "34110000001" in prod_body

        # Smoke mode: [SMOKE TEST] prefix, synthetic baseline clearly labeled without fake run URL
        smoke_state = _open_episode_state(
            episode_mode="smoke",
            anchor_seconds=180.0,
            anchor_run_id="smoke-baseline-regression",
        )
        smoke_ctx = _context(
            run_id="35000000001",
            baseline_run_id="smoke-baseline-regression",
            event_name="workflow_dispatch",
            smoke_mode="regression",
        )
        smoke_title = render_issue_title(smoke_state, smoke_ctx)
        assert smoke_title.startswith("[SMOKE TEST]")
        smoke_body = render_issue_body(smoke_state, smoke_ctx)
        assert "synthetic smoke baseline" in smoke_body.lower()
        assert "/actions/runs/smoke-baseline-regression" not in smoke_body
        assert (
            "https://github.com/MissionWAR/BlocklistMerger/actions/runs/35000000001" in smoke_body
        )

    def test_comments_include_required_markers_d24_04_d24_05_d24_08_and_d24_11_fields(
        self,
    ) -> None:
        from scripts.perf_alert import (
            HistoryEntry,
            render_continuation_comment,
            render_corpus_changed_comment,
            render_recovery_comment,
        )

        state = _open_episode_state(
            anchor_seconds=180.0,
            anchor_run_id="34040028893",
            opened_run_id="34099999999",
        )
        state.history.append(
            HistoryEntry(
                date="2026-09-20",
                run_id="34110000001",
                current_seconds=198.0,
                anchor_delta_pct=10.0,
                rolling_seconds=216.0,
                rolling_delta_pct=-8.33,
                env_changed=True,
                missing_legs=("fetch", "live_memory"),
            )
        )
        cont_ctx = _context(run_id="34110000001", baseline_run_id="34099999999")
        cont = render_continuation_comment(
            state,
            cont_ctx,
            env_changes=("cpu_model: AMD EPYC 7763 -> AMD EPYC 9R14",),
            missing_legs=("fetch", "live_memory"),
        )
        assert "<!-- perf-alert-comment:run-34110000001 -->" in cont
        assert "2026-09-20" in cont
        assert "198.000s" in cont
        assert "+10.00%" in cont
        assert "-8.33%" in cont
        assert "observed across changed environments" in cont.lower()
        assert "not proven to be a code regression" in cont.lower()
        assert "fetch" in cont
        assert "live_memory" in cont

        # Recovery comment (D-24-11): open date, immutable anchor, close value/delta, run link
        state.status = "recovered"
        state.history.append(
            HistoryEntry(
                date="2026-09-27",
                run_id="34120000002",
                current_seconds=175.5,
                anchor_delta_pct=-2.5,
                rolling_seconds=198.0,
                rolling_delta_pct=-11.36,
                env_changed=False,
                missing_legs=(),
            )
        )
        rec_ctx = _context(run_id="34120000002", baseline_run_id="34110000001")
        rec = render_recovery_comment(state, rec_ctx)
        assert "<!-- perf-alert-comment:recovery-34120000002 -->" in rec
        assert "2026-09-13" in rec
        assert "180.000s" in rec
        assert "34040028893" in rec
        assert "175.500s" in rec
        assert "-2.50%" in rec
        assert "https://github.com/MissionWAR/BlocklistMerger/actions/runs/34120000002" in rec

        # Corpus-changed comment (D-24-08)
        corpus_msg = render_corpus_changed_comment(state, rec_ctx, DIGEST_B)
        assert f"<!-- perf-alert-comment:corpus-changed-{DIGEST_B[:12]} -->" in corpus_msg
        assert DIGEST_A[:12] in corpus_msg
        assert DIGEST_B[:12] in corpus_msg
        assert "stays open" in corpus_msg.lower()

    def test_500_week_history_compaction_under_60k_preserves_opener_and_latest_rows(
        self,
    ) -> None:
        from scripts.perf_alert import (
            MAX_ISSUE_BODY_CHARS,
            MAX_RECORDED_RUN_IDS,
            EpisodeState,
            HistoryEntry,
            parse_state_marker,
            render_issue_body,
        )

        history = [
            HistoryEntry(
                date=f"2026-{(i // 28) % 12 + 1:02d}-{(i % 28) + 1:02d}",
                run_id=f"350000{i:04d}",
                current_seconds=210.0 + (i % 20),
                anchor_delta_pct=16.67 + (i % 10),
                rolling_seconds=180.0,
                rolling_delta_pct=16.67,
                env_changed=(i % 5 == 0),
                missing_legs=("fetch", "live_timing") if i % 3 == 0 else (),
            )
            for i in range(500)
        ]
        recorded = ["3500000000", *[f"350000{i:04d}" for i in range(401, 500)]]
        assert len(recorded) == MAX_RECORDED_RUN_IDS
        state = EpisodeState(
            episode_mode="production",
            status="open",
            anchor_seconds=180.0,
            anchor_manifest_sha256=DIGEST_A,
            anchor_run_id="34040028893",
            anchor_created_at="2026-09-06T03:30:00Z",
            opened_at="2026-09-13T03:35:00Z",
            opened_run_id="3500000000",
            recorded_run_ids=recorded,
            history=history,
        )
        rendered = render_issue_body(state, _context(run_id="3500000499"))
        assert len(rendered) <= MAX_ISSUE_BODY_CHARS
        assert "compacted" in rendered.lower()
        # Visible Markdown table must keep opening breach row AND latest row(s)
        assert "3500000000" in rendered
        assert "3500000499" in rendered

        parsed = parse_state_marker(rendered)
        assert parsed is not None
        assert parsed.history[0] == history[0]
        assert parsed.history[-1] == history[-1]
        assert len(parsed.history) >= 2

    def test_render_issue_body_worst_case_env_changes_and_empty_opened_run_id(self) -> None:
        from scripts.perf_alert import (
            MAX_ISSUE_BODY_CHARS,
            EpisodeState,
            HistoryEntry,
            parse_state_marker,
            render_issue_body,
        )

        history = [
            HistoryEntry(
                date=f"2026-09-{i + 10:02d}",
                run_id=f"3409999{i:04d}",
                current_seconds=216.0 + i,
                anchor_delta_pct=20.0 + i,
                rolling_seconds=180.0,
                rolling_delta_pct=20.0,
                env_changed=True,
                missing_legs=(),
            )
            for i in range(10)
        ]
        oversized_changes = [f"cpu_model: old_{i}_" + "a" * 2000 + " -> new" for i in range(45)]
        state = EpisodeState(
            episode_mode="production",
            status="open",
            anchor_seconds=180.0,
            anchor_manifest_sha256=DIGEST_A,
            anchor_run_id="34040028893",
            anchor_created_at="2026-09-06T03:30:00Z",
            opened_at="2026-09-10T03:35:00Z",
            opened_run_id="34099990000",
            recorded_run_ids=[entry.run_id for entry in history],
            notified_corpus_digests=[DIGEST_B, DIGEST_C],
            history=history,
        )
        body = render_issue_body(
            state,
            _context(run_id="34099990009"),
            env_changes=oversized_changes,
            missing_legs=("fetch", "live_timing"),
        )
        assert len(body) <= MAX_ISSUE_BODY_CHARS
        parsed = parse_state_marker(body)
        assert parsed is not None
        assert parsed.history[0] == history[0]
        assert parsed.history[-1] == history[-1]
        assert parsed.recorded_run_ids == state.recorded_run_ids

        # Extreme non-history overflow (70k anchor_receipts, 40 oversized missing_legs, 30 digests)
        extreme_state = EpisodeState(
            episode_mode="production",
            status="open",
            anchor_seconds=180.0,
            anchor_manifest_sha256=DIGEST_A,
            anchor_run_id="34040028893",
            anchor_created_at="2026-09-06T03:30:00Z",
            anchor_receipts={"cpu_model": "X" * 70_000},
            opened_at="2026-09-10T03:35:00Z",
            opened_run_id="34099990000",
            recorded_run_ids=[f"3409999{i:04d}" for i in range(100)],
            notified_corpus_digests=[DIGEST_B if i % 2 == 0 else DIGEST_C for i in range(30)],
            history=history,
        )
        extreme_body = render_issue_body(
            extreme_state,
            _context(run_id="34099990099"),
            env_changes=oversized_changes,
            missing_legs=tuple(f"leg_{i}_" + "z" * 2000 for i in range(40)),
        )
        assert len(extreme_body) <= MAX_ISSUE_BODY_CHARS
        parsed_extreme = parse_state_marker(extreme_body)
        assert parsed_extreme is not None
        assert parsed_extreme.history[0] == history[0]
        assert parsed_extreme.history[-1] == history[-1]

        # Library caller with opened_run_id == "" must still emit a parseable non-empty marker
        empty_open_state = EpisodeState(
            episode_mode="production",
            status="open",
            anchor_seconds=180.0,
            anchor_manifest_sha256=DIGEST_A,
            anchor_run_id="34040028893",
            anchor_created_at="2026-09-06T03:30:00Z",
            opened_at="2026-09-10T03:35:00Z",
            opened_run_id="",
            recorded_run_ids=["", "34099990001"],
            history=history,
        )
        empty_open_body = render_issue_body(
            empty_open_state,
            _context(run_id="34099990009"),
            env_changes=oversized_changes,
        )
        assert len(empty_open_body) <= MAX_ISSUE_BODY_CHARS
        parsed_empty_open = parse_state_marker(empty_open_body)
        assert parsed_empty_open is not None
        assert parsed_empty_open.opened_run_id != ""
        assert "" not in parsed_empty_open.recorded_run_ids


class TestGhCliIssueClientAndResilience:
    """Task 2: Hardened GhCliIssueClient subprocess adapter & API/handoff error resilience."""

    def test_gh_client_validates_repo_slug_and_issue_numbers(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from scripts.perf_alert import GhCliIssueClient, PerfAlertError

        monkeypatch.setattr(
            "subprocess.run",
            lambda *a, **kw: pytest.fail("subprocess.run must not be called on invalid inputs"),
        )

        for bad_repo in (
            "",
            "noslash",
            "owner/repo/../../evil",
            "owner/..",
            "../repo",
            "owner/repo;rm -rf /",
            "owner/repo name",
        ):
            bad_client = GhCliIssueClient(repo=bad_repo)
            with pytest.raises(PerfAlertError):
                bad_client.list_issues("perf-regression")

        client = GhCliIssueClient(repo="MissionWAR/BlocklistMerger")
        for bad_issue in (0, -1, True, False, "42", "42;id", None):
            with pytest.raises(PerfAlertError):
                client.list_comments(bad_issue)  # type: ignore[arg-type]
            with pytest.raises(PerfAlertError):
                client.update_issue(bad_issue, body="x")  # type: ignore[arg-type]
            with pytest.raises(PerfAlertError):
                client.create_comment(bad_issue, body="x")  # type: ignore[arg-type]

    def test_gh_client_pagination_pr_filter_stdin_and_call_ordering(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import subprocess

        import scripts.perf_alert as perf_alert

        calls: list[dict[str, object]] = []
        open_state = _open_episode_state(anchor_seconds=180.0, opened_run_id="34099999999")
        existing_issue_body = perf_alert.render_issue_body(
            open_state, _context(run_id="34099999999")
        )

        def fake_run(
            args: list[str],
            *,
            input: str | None = None,
            capture_output: bool = False,
            text: bool = False,
            encoding: str | None = None,
            check: bool = False,
            shell: bool = True,
            timeout: float | None = None,
        ) -> subprocess.CompletedProcess[str]:
            assert shell is False
            assert capture_output is True
            assert text is True
            assert encoding == "utf-8"
            assert check is True
            assert timeout == 60
            payload = json.loads(input) if input is not None else None
            calls.append({"args": list(args), "input": input, "payload": payload})

            if args[:3] == ["gh", "label", "create"]:
                return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
            if args[:4] == ["gh", "api", "-X", "GET"]:
                endpoint = args[4]
                assert "--paginate" in args
                assert "--slurp" in args
                if "/issues?" in endpoint:
                    # Simulate paginated slurp response including a PR and an issue
                    pages = [
                        [
                            {
                                "number": 999,
                                "state": "open",
                                "pull_request": {"url": "https://example.invalid/pulls/999"},
                                "labels": [{"name": "perf-regression"}],
                                "body": existing_issue_body,
                            }
                        ],
                        [
                            {
                                "number": 42,
                                "state": "open",
                                "labels": [{"name": "perf-regression"}],
                                "body": existing_issue_body,
                            }
                        ],
                    ]
                    return subprocess.CompletedProcess(args, 0, stdout=json.dumps(pages), stderr="")
                if "/issues/42/comments" in endpoint:
                    return subprocess.CompletedProcess(args, 0, stdout=json.dumps([[]]), stderr="")
            if args[:4] == ["gh", "api", "-X", "POST"]:
                assert "--input" in args and "-" in args
                assert input is not None
                return subprocess.CompletedProcess(
                    args,
                    0,
                    stdout=json.dumps({"number": 43, "id": 500}),
                    stderr="",
                )
            if args[:4] == ["gh", "api", "-X", "PATCH"]:
                assert "--input" in args and "-" in args
                assert input is not None
                return subprocess.CompletedProcess(
                    args, 0, stdout=json.dumps({"number": 42}), stderr=""
                )
            raise AssertionError(f"Unexpected gh call: {args}")

        monkeypatch.setattr("subprocess.run", fake_run)
        monkeypatch.setenv("GH_REPO", "MissionWAR/BlocklistMerger")

        # 1. Direct list_issues must flatten paginated slurp AND exclude pull_request items
        client = perf_alert.GhCliIssueClient()
        listed = client.list_issues("perf-regression")
        assert [item["number"] for item in listed] == [42]

        # 2. Recovery via sync_handoff: comment POST MUST precede PATCH /issues/42
        calls.clear()
        rec_dir = _stage_handoff_dir(
            tmp_path / "recover",
            run_id="34120000001",
            baseline_run_id="34099999999",
            current_pinned=_full_timing_report(175.0, DIGEST_A, created_at="2026-09-20T03:35:00Z"),
            previous_pinned=_full_timing_report(216.0, DIGEST_A, created_at="2026-09-13T03:35:00Z"),
            current_receipts=_receipts_payload(run_id="34120000001"),
            previous_receipts=_receipts_payload(run_id="34099999999"),
            live_timing=_full_timing_report(180.0, DIGEST_B),
            pinned_memory=_memory_report(2048, DIGEST_A),
            live_memory=_memory_report(4096, DIGEST_B),
            source_health=_source_health_payload(),
        )
        assert perf_alert.main(["sync", "--handoff-dir", str(rec_dir)]) == 0
        endpoints = [(c["args"][3], c["args"][4]) for c in calls if c["args"][:2] == ["gh", "api"]]
        assert endpoints == [
            (
                "GET",
                "repos/MissionWAR/BlocklistMerger/issues?labels=perf-regression"
                "&state=all&sort=created&direction=desc&per_page=100",
            ),
            ("GET", "repos/MissionWAR/BlocklistMerger/issues/42/comments?per_page=100"),
            ("POST", "repos/MissionWAR/BlocklistMerger/issues/42/comments"),
            ("PATCH", "repos/MissionWAR/BlocklistMerger/issues/42"),
        ]
        patch_payload = calls[-1]["payload"]
        assert isinstance(patch_payload, dict)
        assert patch_payload["state"] == "closed"
        assert patch_payload["state_reason"] == "completed"

        # 3. Manual-closure retirement omits 'state' and 'state_reason' on PATCH
        calls.clear()
        client.update_issue(42, body="retired marker")
        assert calls[-1]["payload"] == {"body": "retired marker"}
        assert "state" not in calls[-1]["payload"]

        # 4. Opening an issue ensures label with --force before POST /issues
        calls.clear()
        client.ensure_label("perf-regression", color="d93f0b", description="Alert label")
        client.create_issue(title="T", body="B", labels=["perf-regression"])
        assert calls[0]["args"][:6] == [
            "gh",
            "label",
            "create",
            "perf-regression",
            "--repo",
            "MissionWAR/BlocklistMerger",
        ]
        assert "--force" in calls[0]["args"]
        assert calls[1]["args"][:5] == [
            "gh",
            "api",
            "-X",
            "POST",
            "repos/MissionWAR/BlocklistMerger/issues",
        ]

    def test_missing_handoff_degrades_to_silent_noop_and_summary_note(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import scripts.perf_alert as perf_alert

        summary_file = tmp_path / "step_summary.md"
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))
        monkeypatch.setattr(
            "subprocess.run",
            lambda *a, **kw: pytest.fail("gh must not be called when handoff is missing"),
        )

        # Completely missing handoff directory -> exit 0 + summary note
        missing_dir = tmp_path / "does-not-exist"
        assert perf_alert.main(["sync", "--handoff-dir", str(missing_dir)]) == 0
        summary_text = summary_file.read_text(encoding="utf-8")
        assert "no-op" in summary_text.lower() or "noop" in summary_text.lower()

        # Empty handoff directory missing alert-context.json -> exit 0 + summary note
        empty_dir = tmp_path / "empty-handoff"
        empty_dir.mkdir()
        assert perf_alert.main(["sync", "--handoff-dir", str(empty_dir)]) == 0

    def test_gh_failure_logs_redacted_warning_to_summary_and_exits_cleanly(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        import subprocess

        import scripts.perf_alert as perf_alert

        secret = "ghs_SUPER_SECRET_TOKEN_987654321"
        summary_file = tmp_path / "step_summary.md"
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))
        monkeypatch.setenv("GH_TOKEN", secret)
        monkeypatch.setenv("GH_REPO", "MissionWAR/BlocklistMerger")

        handoff_dir = _stage_handoff_dir(
            tmp_path / "api-fail",
            current_pinned=_full_timing_report(216.0, DIGEST_A),
            previous_pinned=_full_timing_report(180.0, DIGEST_A),
            current_receipts=_receipts_payload(),
            previous_receipts=_receipts_payload(),
            live_timing=_full_timing_report(185.0, DIGEST_B),
            pinned_memory=_memory_report(2048, DIGEST_A),
            live_memory=_memory_report(4096, DIGEST_B),
            source_health=_source_health_payload(),
        )

        def fail_run(*args, **kwargs):
            raise subprocess.CalledProcessError(
                1, ["gh", "api"], stderr=f"HTTP 502 Bad Gateway token={secret}"
            )

        monkeypatch.setattr("subprocess.run", fail_run)
        code = perf_alert.main(["sync", "--handoff-dir", str(handoff_dir)])
        assert code == 1
        captured = capsys.readouterr()
        assert secret not in captured.out
        assert secret not in captured.err
        assert "gh command failed" in captured.err
        summary_text = summary_file.read_text(encoding="utf-8")
        assert "warning" in summary_text.lower()
        assert secret not in summary_text

    def test_gh_client_api_json_errors_on_oserror_timeout_and_malformed_json(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import subprocess

        import scripts.perf_alert as perf_alert

        client = perf_alert.GhCliIssueClient(repo="MissionWAR/BlocklistMerger")

        def raise_oserror(*args, **kwargs):
            raise OSError("gh binary missing")

        monkeypatch.setattr("subprocess.run", raise_oserror)
        with pytest.raises(perf_alert.PerfAlertError, match="Failed to invoke gh CLI"):
            client.list_issues("perf-regression")

        def raise_timeout(*args, **kwargs):
            assert kwargs.get("timeout") == 60
            raise subprocess.TimeoutExpired(["gh", "api"], timeout=60)

        monkeypatch.setattr("subprocess.run", raise_timeout)
        with pytest.raises(perf_alert.PerfAlertError, match="timed out"):
            client.list_issues("perf-regression")

        def return_bad_json(*args, **kwargs):
            return subprocess.CompletedProcess(args[0], 0, stdout="{not valid json", stderr="")

        monkeypatch.setattr("subprocess.run", return_bad_json)
        with pytest.raises(perf_alert.PerfAlertError, match="Invalid JSON"):
            client.list_issues("perf-regression")

        summary_file = tmp_path / "summary_bad_json.md"
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))
        monkeypatch.setenv("GH_REPO", "MissionWAR/BlocklistMerger")
        handoff_dir = _stage_handoff_dir(
            tmp_path / "bad-json-handoff",
            current_pinned=_full_timing_report(216.0, DIGEST_A),
            previous_pinned=_full_timing_report(180.0, DIGEST_A),
            current_receipts=_receipts_payload(),
            previous_receipts=_receipts_payload(),
        )
        assert perf_alert.main(["sync", "--handoff-dir", str(handoff_dir)]) == 1
        assert "warning" in summary_file.read_text(encoding="utf-8").lower()


class TestWriteContextSubcommand:
    """Task 2: write-context --output PATH normalization, D-24-14 guard, and branching."""

    def test_write_context_schedule_normalizes_empty_smoke_and_blocks_smoke_injection(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        import scripts.perf_alert as perf_alert

        out_path = tmp_path / "reports" / "perf-evidence" / "alert-context.json"
        monkeypatch.setenv("RUN_ID", "34500000001")
        monkeypatch.setenv("RUN_ATTEMPT", "2")
        monkeypatch.setenv("SERVER_URL", "https://github.com")
        monkeypatch.setenv("REPO", "MissionWAR/BlocklistMerger")
        monkeypatch.setenv("GIT_SHA", "deadbeef1234")
        monkeypatch.setenv("EVENT_NAME", "schedule")
        monkeypatch.setenv("SMOKE_MODE", "")  # schedule leaves inputs.smoke_mode empty
        monkeypatch.setenv("PERF_SNAPSHOT_DIGEST", DIGEST_B)
        monkeypatch.setenv("PERF_SNAPSHOT_RUN_ID", "34037935171")
        monkeypatch.setenv("PINNED_DRIFTED", "false")
        monkeypatch.setenv("BASELINE_RUN_ID", "34400000000")
        monkeypatch.setenv("SMOKE_PINNED_DRIFTED", "true")
        monkeypatch.setenv("SMOKE_BASELINE_RUN_ID", "smoke-baseline-regression")
        monkeypatch.setenv("OUTCOME_RESTORE", "success")
        monkeypatch.setenv("OUTCOME_PINNED_TIMING", "success")
        monkeypatch.setenv("OUTCOME_PINNED_MEMORY", "success")
        monkeypatch.setenv("OUTCOME_FETCH", "failure")
        monkeypatch.setenv("OUTCOME_LIVE_TIMING", "failure")
        monkeypatch.setenv("OUTCOME_LIVE_MEMORY", "skipped")
        monkeypatch.setenv("OUTCOME_DOWNLOAD_PRIOR", "success")

        assert perf_alert.main(["write-context", "--output", str(out_path)]) == 0
        assert not out_path.with_suffix(".tmp").exists()
        doc = json.loads(out_path.read_text(encoding="utf-8"))
        assert doc["smoke_mode"] == "none"
        assert doc["pinned_drifted"] == "false"
        assert doc["baseline_run_id"] == "34400000000"
        assert doc["pinned_snapshot_digest"] == DIGEST_B
        assert doc["pinned_snapshot_run_id"] == "34037935171"
        assert (
            doc["run_url"]
            == "https://github.com/MissionWAR/BlocklistMerger/actions/runs/34500000001"
        )
        assert doc["step_outcomes"]["fetch"] == "failure"

        # Non-workflow_dispatch with non-empty SMOKE_MODE forces "none" + stderr warning
        monkeypatch.setenv("EVENT_NAME", "schedule")
        monkeypatch.setenv("SMOKE_MODE", "regression")
        assert perf_alert.main(["write-context", "--output", str(out_path)]) == 0
        captured = capsys.readouterr()
        assert "workflow_dispatch" in captured.err
        doc2 = json.loads(out_path.read_text(encoding="utf-8"))
        assert doc2["smoke_mode"] == "none"
        assert doc2["pinned_snapshot_digest"] == DIGEST_B

    def test_write_context_workflow_dispatch_smoke_branching_without_truthiness_ambiguity(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import scripts.perf_alert as perf_alert

        out_path = tmp_path / "alert-context.json"
        monkeypatch.setenv("RUN_ID", "34500000002")
        monkeypatch.setenv("RUN_ATTEMPT", "1")
        monkeypatch.setenv("SERVER_URL", "https://github.com")
        monkeypatch.setenv("REPO", "MissionWAR/BlocklistMerger")
        monkeypatch.setenv("GIT_SHA", "cafebabe")
        monkeypatch.setenv("EVENT_NAME", "workflow_dispatch")
        monkeypatch.setenv("SMOKE_MODE", "regression")
        monkeypatch.setenv("PERF_SNAPSHOT_DIGEST", DIGEST_B)
        monkeypatch.setenv("PERF_SNAPSHOT_RUN_ID", "34037935171")
        # Production outputs empty / false while smoke outputs are explicit
        monkeypatch.setenv("PINNED_DRIFTED", "")
        monkeypatch.setenv("BASELINE_RUN_ID", "")
        monkeypatch.setenv("SMOKE_PINNED_DRIFTED", "false")
        monkeypatch.setenv("SMOKE_BASELINE_RUN_ID", "smoke-baseline-regression")
        for key in (
            "OUTCOME_RESTORE",
            "OUTCOME_PINNED_TIMING",
            "OUTCOME_PINNED_MEMORY",
            "OUTCOME_FETCH",
            "OUTCOME_LIVE_TIMING",
            "OUTCOME_LIVE_MEMORY",
            "OUTCOME_DOWNLOAD_PRIOR",
        ):
            monkeypatch.setenv(key, "skipped")

        assert perf_alert.main(["write-context", "--output", str(out_path)]) == 0
        doc = json.loads(out_path.read_text(encoding="utf-8"))
        assert doc["smoke_mode"] == "regression"
        assert doc["pinned_drifted"] == "false"
        assert doc["baseline_run_id"] == "smoke-baseline-regression"
        assert doc["pinned_snapshot_digest"] == perf_alert.SMOKE_SYNTHETIC_DIGEST
        assert doc["pinned_snapshot_run_id"] == "smoke-synthetic"

    def test_write_context_and_derive_url_validate_urls_and_repo(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import scripts.perf_alert as perf_alert

        out_path = tmp_path / "alert-context.json"
        monkeypatch.setenv("RUN_ID", "34500000003")
        monkeypatch.setenv("EVENT_NAME", "schedule")
        monkeypatch.setenv("SMOKE_MODE", "")
        monkeypatch.setenv("REPO", "MissionWAR/BlocklistMerger")

        for bad_server in (
            "javascript:alert(1)",
            "ftp://github.com",
            "https://github.com/a b",
            "https://github.com/a(1)",
            "https://github.com/[1]",
            "https://github.com/<x>",
            "https://github.com\n",
        ):
            monkeypatch.setenv("SERVER_URL", bad_server)
            with pytest.raises(perf_alert.PerfAlertError):
                perf_alert.write_alert_context(out_path)

        monkeypatch.setenv("SERVER_URL", "https://github.com")
        for bad_repo in ("noslash", "owner/../evil", "owner/repo;id"):
            monkeypatch.setenv("REPO", bad_repo)
            with pytest.raises(perf_alert.PerfAlertError):
                perf_alert.write_alert_context(out_path)

        # Empty REPO is permitted and produces empty run_url
        monkeypatch.setenv("REPO", "")
        payload = perf_alert.write_alert_context(out_path)
        assert payload["run_url"] == ""

        for hostile_url in (
            "javascript:alert(1)/actions/runs/34500000003",
            "ftp://evil.com/org/repo/actions/runs/34500000003",
            "https://github.com/org/repo(evil)/actions/runs/34500000003",
            "https://github.com/org/repo[evil]/actions/runs/34500000003",
            "https://github.com/org/repo <x>/actions/runs/34500000003",
            "https://github.com/org/repo\x07/actions/runs/34500000003",
        ):
            ctx = perf_alert.AlertContext(
                run_id="34500000003",
                run_url=hostile_url,
                repo="MissionWAR/BlocklistMerger",
            )
            assert perf_alert._derive_workflow_run_url(ctx, "34500000003") == ""
            assert perf_alert._derive_workflow_run_url(ctx, "34040028893") == ""


class TestPrepareSmokeSubcommand:
    """Task 2: prepare-smoke synthetic layout, stale cleanup, and D-24-05 parity."""

    @pytest.mark.parametrize(
        ("mode", "expected_current", "expected_prev", "expected_drifted", "expected_base_id"),
        [
            pytest.param("regression", 216.0, 180.0, "false", "smoke-baseline-regression"),
            pytest.param(
                "partial_recovery", 198.0, 216.0, "false", "smoke-baseline-partial_recovery"
            ),
            pytest.param("recovery", 178.0, 198.0, "false", "smoke-baseline-recovery"),
            pytest.param("degraded", None, None, "true", ""),
        ],
    )
    def test_prepare_smoke_all_four_modes_and_stale_cleanup(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        mode: str,
        expected_current: float | None,
        expected_prev: float | None,
        expected_drifted: str,
        expected_base_id: str,
    ) -> None:
        import scripts.perf_alert as perf_alert

        out_dir = tmp_path / "smoke-out"
        gh_out = tmp_path / "github_output.txt"
        monkeypatch.setenv("PERF_SNAPSHOT_DIGEST", DIGEST_B)

        # Seed stale artifacts before running prepare-smoke to prove cleanup
        (out_dir / "runs").mkdir(parents=True, exist_ok=True)
        (out_dir / "previous").mkdir(parents=True, exist_ok=True)
        (out_dir / "pinned-drifted").write_text("stale", encoding="utf-8")
        (out_dir / "runs" / "pinned-timing.json").write_text('{"stale":true}', encoding="utf-8")
        (out_dir / "previous" / "pinned-timing.json").write_text('{"stale":true}', encoding="utf-8")

        rc = perf_alert.main(
            [
                "prepare-smoke",
                "--smoke-mode",
                mode,
                "--output-dir",
                str(out_dir),
                "--github-output",
                str(gh_out),
            ]
        )
        assert rc == 0

        gh_lines = dict(
            line.split("=", 1) for line in gh_out.read_text(encoding="utf-8").splitlines() if line
        )
        assert gh_lines == {"drifted": expected_drifted, "baseline-run-id": expected_base_id}

        receipts = perf_alert.load_receipts(out_dir / "receipts.json")
        assert receipts is not None

        if mode == "degraded":
            assert (out_dir / "pinned-drifted").exists()
            assert not (out_dir / "runs" / "pinned-timing.json").exists()
            assert not (out_dir / "previous" / "pinned-timing.json").exists()
        else:
            assert not (out_dir / "pinned-drifted").exists()
            cur = perf_alert.load_timing_report(out_dir / "runs" / "pinned-timing.json")
            prev = perf_alert.load_timing_report(out_dir / "previous" / "pinned-timing.json")
            assert cur is not None and prev is not None
            assert cur.median_seconds == expected_current
            assert prev.median_seconds == expected_prev
            assert cur.manifest_sha256 == perf_alert.SMOKE_SYNTHETIC_DIGEST
            assert prev.manifest_sha256 == perf_alert.SMOKE_SYNTHETIC_DIGEST
            assert cur.manifest_sha256 != DIGEST_B
            assert (out_dir / "previous" / "receipts.json").exists()
            assert (out_dir / "runs" / "pinned-memory.json").exists()
            assert (out_dir / "runs" / "live-timing.json").exists()
            assert (out_dir / "runs" / "live-memory.json").exists()
            assert (out_dir / "source-health.json").exists()
            assert (out_dir / "previous" / "live-timing.json").exists()

    def test_clean_smoke_has_zero_missing_legs_while_corrupt_supporting_leg_triggers_callout(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import scripts.perf_alert as perf_alert

        out_dir = tmp_path / "handoff"
        gh_out = tmp_path / "gh_out.txt"
        assert (
            perf_alert.main(
                [
                    "prepare-smoke",
                    "--smoke-mode",
                    "regression",
                    "--output-dir",
                    str(out_dir),
                    "--github-output",
                    str(gh_out),
                ]
            )
            == 0
        )
        gh_lines = dict(
            line.split("=", 1) for line in gh_out.read_text(encoding="utf-8").splitlines() if line
        )
        monkeypatch.setenv("RUN_ID", "36000000001")
        monkeypatch.setenv("RUN_ATTEMPT", "1")
        monkeypatch.setenv("SERVER_URL", "https://github.com")
        monkeypatch.setenv("REPO", "MissionWAR/BlocklistMerger")
        monkeypatch.setenv("GIT_SHA", "1234567")
        monkeypatch.setenv("EVENT_NAME", "workflow_dispatch")
        monkeypatch.setenv("SMOKE_MODE", "regression")
        monkeypatch.setenv("SMOKE_PINNED_DRIFTED", gh_lines["drifted"])
        monkeypatch.setenv("SMOKE_BASELINE_RUN_ID", gh_lines["baseline-run-id"])
        for key in (
            "OUTCOME_RESTORE",
            "OUTCOME_PINNED_TIMING",
            "OUTCOME_PINNED_MEMORY",
            "OUTCOME_FETCH",
            "OUTCOME_LIVE_TIMING",
            "OUTCOME_LIVE_MEMORY",
            "OUTCOME_DOWNLOAD_PRIOR",
        ):
            monkeypatch.setenv(key, "skipped")

        assert (
            perf_alert.main(["write-context", "--output", str(out_dir / "alert-context.json")]) == 0
        )

        fake_client = FakeGitHubIssueClient()
        monkeypatch.setattr(perf_alert, "GhCliIssueClient", lambda *a, **kw: fake_client)
        assert perf_alert.main(["sync", "--handoff-dir", str(out_dir)]) == 0
        assert len(fake_client.created_issues) == 1
        clean_body = fake_client.created_issues[0]["body"]
        assert "Missing Supporting Evidence" not in clean_body

        # Now delete one supporting leg file and sync again with a new run_id -> D-24-05 banner!
        (out_dir / "runs" / "live-memory.json").unlink()
        monkeypatch.setenv("RUN_ID", "36000000002")
        assert (
            perf_alert.main(["write-context", "--output", str(out_dir / "alert-context.json")]) == 0
        )
        assert perf_alert.main(["sync", "--handoff-dir", str(out_dir)]) == 0
        assert len(fake_client.updated_issues) == 1
        corrupt_body = fake_client.updated_issues[0]["body"]
        assert "Missing Supporting Evidence" in corrupt_body
        assert "live_memory" in corrupt_body


class _StatefulGhSubprocessServer:
    """Stateful in-memory GitHub REST handler for subprocess.run end-to-end replay."""

    def __init__(self, repo: str = "MissionWAR/BlocklistMerger") -> None:
        self.repo = repo
        self.labels: dict[str, dict[str, str]] = {}
        self.issues: dict[int, dict[str, object]] = {}
        self.comments: dict[int, list[dict[str, object]]] = {}
        self.extra_api_items: list[dict[str, object]] = []
        self.calls: list[dict[str, object]] = []
        self.next_issue_number = 1
        self.next_comment_id = 100
        self.fail_next_patch_error: subprocess.CalledProcessError | None = None
        self.fail_next_api_error: subprocess.CalledProcessError | None = None

    def clone(self) -> _StatefulGhSubprocessServer:
        return copy.deepcopy(self)

    def __call__(
        self,
        args: list[str],
        *,
        input: str | None = None,
        capture_output: bool = False,
        text: bool = False,
        encoding: str | None = None,
        check: bool = False,
        shell: bool = True,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        assert shell is False
        assert capture_output is True
        assert text is True
        assert encoding == "utf-8"
        assert check is True
        assert timeout == 60
        payload = json.loads(input) if input is not None else None
        self.calls.append({"args": list(args), "payload": payload})

        if args[:3] == ["gh", "label", "create"]:
            label_name = args[3]
            repo_idx = args.index("--repo")
            assert args[repo_idx + 1] == self.repo
            assert "--force" in args
            color_idx = args.index("--color")
            desc_idx = args.index("--description")
            self.labels[label_name] = {
                "color": args[color_idx + 1],
                "description": args[desc_idx + 1],
            }
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

        if args[:2] == ["gh", "api"]:
            assert args[2] == "-X"
            method = args[3]
            endpoint = args[4]
            if self.fail_next_api_error is not None:
                err = self.fail_next_api_error
                self.fail_next_api_error = None
                raise err
            prefix = f"repos/{self.repo}/"
            assert endpoint.startswith(prefix), f"Unexpected endpoint repo: {endpoint}"

            if method == "GET":
                assert "--paginate" in args
                assert "--slurp" in args
                parsed = urlparse(endpoint)
                if parsed.path == f"repos/{self.repo}/issues":
                    qs = parse_qs(parsed.query)
                    assert qs.get("state") == ["all"]
                    req_labels = set(qs.get("labels", [""])[0].split(","))
                    matched: list[dict[str, object]] = []
                    for issue in self.issues.values():
                        issue_labels = {
                            str(lbl["name"])
                            for lbl in issue.get("labels", [])  # type: ignore[attr-defined]
                        }
                        if issue_labels & req_labels:
                            matched.append(copy.deepcopy(issue))
                    matched.extend(copy.deepcopy(item) for item in self.extra_api_items)
                    matched.sort(key=lambda item: int(item["number"]), reverse=True)  # type: ignore[arg-type]
                    pages = [matched[i : i + 2] for i in range(0, len(matched), 2)] or [[]]
                    return subprocess.CompletedProcess(args, 0, stdout=json.dumps(pages), stderr="")
                if parsed.path.endswith("/comments"):
                    issue_num = int(parsed.path.split("/")[-2])
                    items = copy.deepcopy(self.comments.get(issue_num, []))
                    return subprocess.CompletedProcess(
                        args, 0, stdout=json.dumps([items]), stderr=""
                    )

            if method == "POST":
                assert "--input" in args and "-" in args and input is not None
                assert isinstance(payload, dict)
                body = str(payload.get("body", ""))
                if len(body) > 65536:
                    raise subprocess.CalledProcessError(
                        1,
                        args,
                        stderr="HTTP 422: body is too long (maximum is 65536 characters)",
                    )
                if endpoint == f"repos/{self.repo}/issues":
                    req_labels = payload.get("labels", [])
                    assert isinstance(req_labels, list)
                    for lbl in req_labels:
                        if lbl not in self.labels:
                            raise subprocess.CalledProcessError(
                                1, args, stderr=f"HTTP 422: Label does not exist: {lbl}"
                            )
                    num = self.next_issue_number
                    self.next_issue_number += 1
                    issue: dict[str, object] = {
                        "number": num,
                        "title": payload["title"],
                        "body": body,
                        "state": "open",
                        "labels": [{"name": str(lbl)} for lbl in req_labels],
                        "created_at": f"2026-09-{10 + num:02d}T03:40:00Z",
                    }
                    self.issues[num] = issue
                    self.comments.setdefault(num, [])
                    return subprocess.CompletedProcess(args, 0, stdout=json.dumps(issue), stderr="")
                if endpoint.endswith("/comments"):
                    issue_num = int(endpoint.split("/")[-2])
                    comment = {"id": self.next_comment_id, "body": body}
                    self.next_comment_id += 1
                    self.comments.setdefault(issue_num, []).append(comment)
                    return subprocess.CompletedProcess(
                        args, 0, stdout=json.dumps(comment), stderr=""
                    )

            if method == "PATCH":
                assert "--input" in args and "-" in args and input is not None
                assert isinstance(payload, dict)
                if self.fail_next_patch_error is not None:
                    err = self.fail_next_patch_error
                    self.fail_next_patch_error = None
                    raise err
                body = str(payload.get("body", ""))
                if len(body) > 65536:
                    raise subprocess.CalledProcessError(
                        1,
                        args,
                        stderr="HTTP 422: body is too long (maximum is 65536 characters)",
                    )
                issue_num = int(endpoint.split("/")[-1])
                issue = self.issues[issue_num]
                issue["body"] = body
                if "state" in payload:
                    issue["state"] = payload["state"]
                if "state_reason" in payload:
                    issue["state_reason"] = payload["state_reason"]
                return subprocess.CompletedProcess(args, 0, stdout=json.dumps(issue), stderr="")

        raise AssertionError(f"Unexpected gh command: {args}")


def _set_prod_env(
    monkeypatch: pytest.MonkeyPatch,
    *,
    run_id: str,
    baseline_run_id: str,
    run_attempt: str = "1",
    pinned_drifted: str = "false",
    snapshot_digest: str = DIGEST_A,
    step_outcomes: dict[str, str] | None = None,
) -> None:
    monkeypatch.setenv("RUN_ID", run_id)
    monkeypatch.setenv("RUN_ATTEMPT", run_attempt)
    monkeypatch.setenv("SERVER_URL", "https://github.com")
    monkeypatch.setenv("REPO", "MissionWAR/BlocklistMerger")
    monkeypatch.setenv("GH_REPO", "MissionWAR/BlocklistMerger")
    monkeypatch.setenv("GIT_SHA", "deadbeef")
    monkeypatch.setenv("EVENT_NAME", "schedule")
    monkeypatch.setenv("SMOKE_MODE", "")
    monkeypatch.setenv("PERF_SNAPSHOT_DIGEST", snapshot_digest)
    monkeypatch.setenv("PERF_SNAPSHOT_RUN_ID", "34037935171")
    monkeypatch.setenv("PINNED_DRIFTED", pinned_drifted)
    monkeypatch.setenv("BASELINE_RUN_ID", baseline_run_id)
    outcomes = step_outcomes or {}
    for env_key, outcome_key in (
        ("OUTCOME_RESTORE", "restore"),
        ("OUTCOME_PINNED_TIMING", "pinned_timing"),
        ("OUTCOME_PINNED_MEMORY", "pinned_memory"),
        ("OUTCOME_FETCH", "fetch"),
        ("OUTCOME_LIVE_TIMING", "live_timing"),
        ("OUTCOME_LIVE_MEMORY", "live_memory"),
        ("OUTCOME_DOWNLOAD_PRIOR", "download_prior"),
    ):
        monkeypatch.setenv(env_key, outcomes.get(outcome_key, "success"))


def _stage_cli_artifacts(
    handoff_dir: Path,
    *,
    run_id: str,
    created_at: str = "2026-09-13T03:35:00Z",
    current_pinned: dict[str, object] | None = None,
    previous_pinned: dict[str, object] | None = None,
    current_receipts: dict[str, object] | None = None,
    previous_receipts: dict[str, object] | None = None,
    live_timing: dict[str, object] | None = None,
    pinned_memory: dict[str, object] | None = None,
    live_memory: dict[str, object] | None = None,
    source_health: dict[str, object] | None = None,
    create_drifted_file: bool = False,
) -> Path:
    import scripts.perf_alert as perf_alert

    handoff_dir.mkdir(parents=True, exist_ok=True)
    if current_pinned is not None:
        _write_json(handoff_dir / "runs" / "pinned-timing.json", current_pinned)
    if previous_pinned is not None:
        _write_json(handoff_dir / "previous" / "pinned-timing.json", previous_pinned)
    if current_receipts is not None:
        _write_json(handoff_dir / "receipts.json", current_receipts)
    if previous_receipts is not None:
        _write_json(handoff_dir / "previous" / "receipts.json", previous_receipts)
    if live_timing is not None:
        _write_json(handoff_dir / "runs" / "live-timing.json", live_timing)
    if pinned_memory is not None:
        _write_json(handoff_dir / "runs" / "pinned-memory.json", pinned_memory)
    if live_memory is not None:
        _write_json(handoff_dir / "runs" / "live-memory.json", live_memory)
    if source_health is not None:
        _write_json(handoff_dir / "source-health.json", source_health)
    if create_drifted_file:
        (handoff_dir / "pinned-drifted").write_text("drifted\n", encoding="utf-8")

    assert (
        perf_alert.main(["write-context", "--output", str(handoff_dir / "alert-context.json")]) == 0
    )
    return handoff_dir


class TestEndToEndWorkflowScenarios:
    """Task 3: Full stateful CLI multi-week, smoke isolation, manual closure, and retry replay."""

    def test_multi_week_production_lifecycle_replay(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import scripts.perf_alert as perf_alert

        gh = _StatefulGhSubprocessServer()
        monkeypatch.setattr("subprocess.run", gh)

        # Week 0 (<15% slowdown: +8.33%) -> silent NO-OP, zero issues
        _set_prod_env(monkeypatch, run_id="34100000000", baseline_run_id="34090000000")
        w0 = _stage_cli_artifacts(
            tmp_path / "w0",
            run_id="34100000000",
            current_pinned=_full_timing_report(195.0, DIGEST_A, created_at="2026-09-06T03:35:00Z"),
            previous_pinned=_full_timing_report(180.0, DIGEST_A, created_at="2026-08-30T03:35:00Z"),
            current_receipts=_receipts_payload(run_id="34100000000"),
            previous_receipts=_receipts_payload(run_id="34090000000"),
            live_timing=_full_timing_report(182.0, DIGEST_B),
            pinned_memory=_memory_report(2048, DIGEST_A),
            live_memory=_memory_report(4096, DIGEST_B),
            source_health=_source_health_payload(),
        )
        assert perf_alert.main(["sync", "--handoff-dir", str(w0)]) == 0
        assert gh.issues == {}

        # Week 1 (+20% breach, missing live_timing leg) -> opens #1 with D-24-05 callout
        _set_prod_env(
            monkeypatch,
            run_id="34100000001",
            baseline_run_id="34100000000",
            step_outcomes={"live_timing": "failure"},
        )
        w1 = _stage_cli_artifacts(
            tmp_path / "w1",
            run_id="34100000001",
            current_pinned=_full_timing_report(216.0, DIGEST_A, created_at="2026-09-13T03:35:00Z"),
            previous_pinned=_full_timing_report(180.0, DIGEST_A, created_at="2026-09-06T03:35:00Z"),
            current_receipts=_receipts_payload(run_id="34100000001"),
            previous_receipts=_receipts_payload(run_id="34100000000"),
            pinned_memory=_memory_report(2048, DIGEST_A),
            live_memory=_memory_report(4096, DIGEST_B),
            source_health=_source_health_payload(),
        )
        assert perf_alert.main(["sync", "--handoff-dir", str(w1)]) == 0
        assert list(gh.issues) == [1]
        issue1 = gh.issues[1]
        assert issue1["state"] == "open"
        assert "[SMOKE TEST]" not in str(issue1["title"])
        assert "Missing Supporting Evidence" in str(issue1["body"])
        assert "live timing benchmark" in str(issue1["body"])
        state1 = perf_alert.parse_state_marker(str(issue1["body"]))
        assert state1 is not None and state1.anchor_seconds == 180.0

        # Week 2 (degraded) -> hold open NO-OP (0 comments, #1 still open)
        _set_prod_env(
            monkeypatch,
            run_id="34100000002",
            baseline_run_id="",
            pinned_drifted="true",
        )
        w2 = _stage_cli_artifacts(
            tmp_path / "w2",
            run_id="34100000002",
            current_receipts=_receipts_payload(run_id="34100000002"),
            create_drifted_file=True,
        )
        assert perf_alert.main(["sync", "--handoff-dir", str(w2)]) == 0
        assert gh.issues[1]["state"] == "open"
        assert gh.comments[1] == []

        # Week 3 (partial recovery +10% vs anchor 180.0, with env change) -> update #1 + D-24-04
        _set_prod_env(monkeypatch, run_id="34100000003", baseline_run_id="34100000001")
        w3 = _stage_cli_artifacts(
            tmp_path / "w3",
            run_id="34100000003",
            current_pinned=_full_timing_report(198.0, DIGEST_A, created_at="2026-09-20T03:35:00Z"),
            previous_pinned=_full_timing_report(216.0, DIGEST_A, created_at="2026-09-13T03:35:00Z"),
            current_receipts=_receipts_payload(
                cpu_model="AMD EPYC 9654 96-Core Processor",
                runner_image="ubuntu-24.04-arm",
                run_id="34100000003",
            ),
            previous_receipts=_receipts_payload(run_id="34100000001"),
            live_timing=_full_timing_report(184.0, DIGEST_B),
            pinned_memory=_memory_report(2048, DIGEST_A),
            live_memory=_memory_report(4096, DIGEST_B),
            source_health=_source_health_payload(),
        )
        assert perf_alert.main(["sync", "--handoff-dir", str(w3)]) == 0
        assert gh.issues[1]["state"] == "open"
        assert len(gh.comments[1]) == 1
        assert "not proven to be a code regression" in str(gh.comments[1][0]["body"])
        state3 = perf_alert.parse_state_marker(str(gh.issues[1]["body"]))
        assert state3 is not None and len(state3.history) == 2

        # Branch A at Week 4: corpus re-pin holds #1 open and deduplicates comment
        gh_repin = gh.clone()
        monkeypatch.setattr("subprocess.run", gh_repin)
        _set_prod_env(
            monkeypatch,
            run_id="34100000004",
            baseline_run_id="34100000003",
            snapshot_digest=DIGEST_B,
        )
        w4_repin = _stage_cli_artifacts(
            tmp_path / "w4_repin",
            run_id="34100000004",
            current_pinned=_full_timing_report(175.0, DIGEST_B, created_at="2026-09-27T03:35:00Z"),
            previous_pinned=_full_timing_report(170.0, DIGEST_B, created_at="2026-09-20T03:35:00Z"),
            current_receipts=_receipts_payload(
                pinned_manifest_sha256=DIGEST_B, run_id="34100000004"
            ),
            previous_receipts=_receipts_payload(run_id="34100000003"),
            live_timing=_full_timing_report(180.0, DIGEST_C),
            pinned_memory=_memory_report(2048, DIGEST_B),
            live_memory=_memory_report(4096, DIGEST_C),
            source_health=_source_health_payload(),
        )
        assert perf_alert.main(["sync", "--handoff-dir", str(w4_repin)]) == 0
        assert gh_repin.issues[1]["state"] == "open"
        assert len(gh_repin.comments[1]) == 2
        assert f"corpus-changed-{DIGEST_B[:12]}" in str(gh_repin.comments[1][1]["body"])
        # Re-running with same changed digest must not duplicate corpus-changed comment
        _set_prod_env(
            monkeypatch,
            run_id="34100000005",
            baseline_run_id="34100000004",
            snapshot_digest=DIGEST_B,
        )
        w4_repin_again = _stage_cli_artifacts(
            tmp_path / "w4_repin_2",
            run_id="34100000005",
            current_pinned=_full_timing_report(176.0, DIGEST_B, created_at="2026-10-04T03:35:00Z"),
            previous_pinned=_full_timing_report(175.0, DIGEST_B, created_at="2026-09-27T03:35:00Z"),
            current_receipts=_receipts_payload(
                pinned_manifest_sha256=DIGEST_B, run_id="34100000005"
            ),
            previous_receipts=_receipts_payload(
                pinned_manifest_sha256=DIGEST_B, run_id="34100000004"
            ),
            live_timing=_full_timing_report(180.0, DIGEST_C),
            pinned_memory=_memory_report(2048, DIGEST_B),
            live_memory=_memory_report(4096, DIGEST_C),
            source_health=_source_health_payload(),
        )
        assert perf_alert.main(["sync", "--handoff-dir", str(w4_repin_again)]) == 0
        assert len(gh_repin.comments[1]) == 2

        # Branch B at Week 4 -> Week 5: recovery <= anchor closes #1, then +18% breach opens #2
        monkeypatch.setattr("subprocess.run", gh)
        _set_prod_env(monkeypatch, run_id="34100000004", baseline_run_id="34100000003")
        w4_rec = _stage_cli_artifacts(
            tmp_path / "w4_rec",
            run_id="34100000004",
            current_pinned=_full_timing_report(176.0, DIGEST_A, created_at="2026-09-27T03:35:00Z"),
            previous_pinned=_full_timing_report(198.0, DIGEST_A, created_at="2026-09-20T03:35:00Z"),
            current_receipts=_receipts_payload(run_id="34100000004"),
            previous_receipts=_receipts_payload(run_id="34100000003"),
            live_timing=_full_timing_report(179.0, DIGEST_B),
            pinned_memory=_memory_report(2048, DIGEST_A),
            live_memory=_memory_report(4096, DIGEST_B),
            source_health=_source_health_payload(),
        )
        assert perf_alert.main(["sync", "--handoff-dir", str(w4_rec)]) == 0
        assert gh.issues[1]["state"] == "closed"
        assert gh.issues[1]["state_reason"] == "completed"
        assert len(gh.comments[1]) == 2
        assert f"{perf_alert.COMMENT_MARKER_PREFIX}recovery-34100000004" in str(
            gh.comments[1][1]["body"]
        )

        # Week 5 (+18% breach after close) -> opens new issue #2; #1 remains closed
        _set_prod_env(monkeypatch, run_id="34100000005", baseline_run_id="34100000004")
        w5 = _stage_cli_artifacts(
            tmp_path / "w5",
            run_id="34100000005",
            current_pinned=_full_timing_report(212.4, DIGEST_A, created_at="2026-10-04T03:35:00Z"),
            previous_pinned=_full_timing_report(180.0, DIGEST_A, created_at="2026-09-27T03:35:00Z"),
            current_receipts=_receipts_payload(run_id="34100000005"),
            previous_receipts=_receipts_payload(run_id="34100000004"),
            live_timing=_full_timing_report(182.0, DIGEST_B),
            pinned_memory=_memory_report(2048, DIGEST_A),
            live_memory=_memory_report(4096, DIGEST_B),
            source_health=_source_health_payload(),
        )
        assert perf_alert.main(["sync", "--handoff-dir", str(w5)]) == 0
        assert sorted(gh.issues) == [1, 2]
        assert gh.issues[1]["state"] == "closed"
        assert gh.issues[2]["state"] == "open"

    def test_smoke_isolation_sequence_leaves_open_production_issue_untouched(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import scripts.perf_alert as perf_alert

        gh = _StatefulGhSubprocessServer()
        monkeypatch.setattr("subprocess.run", gh)

        # Open production issue #1 first
        _set_prod_env(monkeypatch, run_id="35000000001", baseline_run_id="35000000000")
        prod_dir = _stage_cli_artifacts(
            tmp_path / "prod",
            run_id="35000000001",
            current_pinned=_full_timing_report(216.0, DIGEST_A),
            previous_pinned=_full_timing_report(180.0, DIGEST_A),
            current_receipts=_receipts_payload(run_id="35000000001"),
            previous_receipts=_receipts_payload(run_id="35000000000"),
            live_timing=_full_timing_report(182.0, DIGEST_B),
            pinned_memory=_memory_report(2048, DIGEST_A),
            live_memory=_memory_report(4096, DIGEST_B),
            source_health=_source_health_payload(),
        )
        assert perf_alert.main(["sync", "--handoff-dir", str(prod_dir)]) == 0
        prod_snapshot = copy.deepcopy(gh.issues[1])

        def _run_smoke(step_name: str, mode: str, run_id: str, *, delete_leg: bool = False) -> Path:
            sdir = tmp_path / step_name
            gh_out = tmp_path / f"{step_name}_gh_out.txt"
            assert (
                perf_alert.main(
                    [
                        "prepare-smoke",
                        "--smoke-mode",
                        mode,
                        "--output-dir",
                        str(sdir),
                        "--github-output",
                        str(gh_out),
                    ]
                )
                == 0
            )
            gh_vals = dict(
                line.split("=", 1) for line in gh_out.read_text(encoding="utf-8").splitlines()
            )
            monkeypatch.setenv("RUN_ID", run_id)
            monkeypatch.setenv("RUN_ATTEMPT", "1")
            monkeypatch.setenv("EVENT_NAME", "workflow_dispatch")
            monkeypatch.setenv("SMOKE_MODE", mode)
            monkeypatch.setenv("SMOKE_PINNED_DRIFTED", gh_vals["drifted"])
            monkeypatch.setenv("SMOKE_BASELINE_RUN_ID", gh_vals["baseline-run-id"])
            for k in (
                "OUTCOME_RESTORE",
                "OUTCOME_PINNED_TIMING",
                "OUTCOME_PINNED_MEMORY",
                "OUTCOME_FETCH",
                "OUTCOME_LIVE_TIMING",
                "OUTCOME_LIVE_MEMORY",
                "OUTCOME_DOWNLOAD_PRIOR",
            ):
                monkeypatch.setenv(k, "skipped")
            assert (
                perf_alert.main(["write-context", "--output", str(sdir / "alert-context.json")])
                == 0
            )
            if delete_leg:
                (sdir / "runs" / "live-memory.json").unlink()
            assert perf_alert.main(["sync", "--handoff-dir", str(sdir)]) == 0
            return sdir

        # Step 1: smoke regression opens #2 with zero missing-leg warnings
        _run_smoke("s1", "regression", "35100000001")
        assert sorted(gh.issues) == [1, 2]
        assert str(gh.issues[2]["title"]).startswith("[SMOKE TEST]")
        assert gh.issues[2]["labels"] == [{"name": perf_alert.SMOKE_ALERT_LABEL}]
        body2 = str(gh.issues[2]["body"])
        assert "Missing Supporting Evidence" not in body2
        assert "synthetic smoke baseline `smoke-baseline-regression`" in body2
        assert "/actions/runs/smoke-baseline-" not in body2

        # Step 2: corrupt supporting leg triggers D-24-05 on #2
        _run_smoke("s2", "regression", "35100000002", delete_leg=True)
        assert "Missing Supporting Evidence" in str(gh.issues[2]["body"])
        assert "live_memory" in str(gh.issues[2]["body"])

        # Step 3: smoke partial_recovery keeps #2 open
        _run_smoke("s3", "partial_recovery", "35100000003")
        assert gh.issues[2]["state"] == "open"
        assert "Missing Supporting Evidence" not in str(gh.issues[2]["body"])

        # Step 4: smoke recovery closes #2
        _run_smoke("s4", "recovery", "35100000004")
        assert gh.issues[2]["state"] == "closed"

        # Step 5: smoke degraded is NO-OP
        _run_smoke("s5", "degraded", "35100000005")
        assert sorted(gh.issues) == [1, 2]

        # D-24-14 invariant: production issue #1 and its comments remain 100% untouched
        assert gh.issues[1] == prod_snapshot
        assert gh.comments[1] == []

    def test_manual_closure_lifecycle_replay(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import scripts.perf_alert as perf_alert

        gh = _StatefulGhSubprocessServer()
        monkeypatch.setattr("subprocess.run", gh)

        # Open #1
        _set_prod_env(monkeypatch, run_id="36100000001", baseline_run_id="36099999999")
        d1 = _stage_cli_artifacts(
            tmp_path / "m1",
            run_id="36100000001",
            current_pinned=_full_timing_report(216.0, DIGEST_A),
            previous_pinned=_full_timing_report(180.0, DIGEST_A),
            current_receipts=_receipts_payload(run_id="36100000001"),
            previous_receipts=_receipts_payload(run_id="36099999999"),
            live_timing=_full_timing_report(182.0, DIGEST_B),
            pinned_memory=_memory_report(2048, DIGEST_A),
            live_memory=_memory_report(4096, DIGEST_B),
            source_health=_source_health_payload(),
        )
        assert perf_alert.main(["sync", "--handoff-dir", str(d1)]) == 0
        assert gh.issues[1]["state"] == "open"

        # Maintainer manually closes #1
        gh.issues[1]["state"] = "closed"

        # Week 2 still regressed (+22% vs anchor) -> NO-OP (never reopen #1 or post comment)
        _set_prod_env(monkeypatch, run_id="36100000002", baseline_run_id="36100000001")
        d2 = _stage_cli_artifacts(
            tmp_path / "m2",
            run_id="36100000002",
            current_pinned=_full_timing_report(219.6, DIGEST_A),
            previous_pinned=_full_timing_report(216.0, DIGEST_A),
            current_receipts=_receipts_payload(run_id="36100000002"),
            previous_receipts=_receipts_payload(run_id="36100000001"),
            live_timing=_full_timing_report(182.0, DIGEST_B),
            pinned_memory=_memory_report(2048, DIGEST_A),
            live_memory=_memory_report(4096, DIGEST_B),
            source_health=_source_health_payload(),
        )
        calls_before = len(gh.calls)
        assert perf_alert.main(["sync", "--handoff-dir", str(d2)]) == 0
        api_methods = [
            c["args"][3] for c in gh.calls[calls_before:] if c["args"][:2] == ["gh", "api"]
        ]
        assert api_methods == ["GET"]
        assert gh.issues[1]["state"] == "closed"
        assert gh.comments[1] == []

        # Week 3 recovers (175.0 <= 180.0) -> silent retire PATCH omitting state/state_reason
        _set_prod_env(monkeypatch, run_id="36100000003", baseline_run_id="36100000002")
        d3 = _stage_cli_artifacts(
            tmp_path / "m3",
            run_id="36100000003",
            current_pinned=_full_timing_report(175.0, DIGEST_A),
            previous_pinned=_full_timing_report(219.6, DIGEST_A),
            current_receipts=_receipts_payload(run_id="36100000003"),
            previous_receipts=_receipts_payload(run_id="36100000002"),
            live_timing=_full_timing_report(180.0, DIGEST_B),
            pinned_memory=_memory_report(2048, DIGEST_A),
            live_memory=_memory_report(4096, DIGEST_B),
            source_health=_source_health_payload(),
        )
        assert perf_alert.main(["sync", "--handoff-dir", str(d3)]) == 0
        patch_call = gh.calls[-1]
        assert patch_call["args"][:4] == ["gh", "api", "-X", "PATCH"]
        assert "state" not in patch_call["payload"]  # type: ignore[operator]
        assert gh.issues[1]["state"] == "closed"
        assert gh.comments[1] == []
        retired_state = perf_alert.parse_state_marker(str(gh.issues[1]["body"]))
        assert retired_state is not None and retired_state.status == "recovered"

        # Week 4 new +20% breach -> opens #2
        _set_prod_env(monkeypatch, run_id="36100000004", baseline_run_id="36100000003")
        d4 = _stage_cli_artifacts(
            tmp_path / "m4",
            run_id="36100000004",
            current_pinned=_full_timing_report(216.0, DIGEST_A),
            previous_pinned=_full_timing_report(180.0, DIGEST_A),
            current_receipts=_receipts_payload(run_id="36100000004"),
            previous_receipts=_receipts_payload(run_id="36100000003"),
            live_timing=_full_timing_report(182.0, DIGEST_B),
            pinned_memory=_memory_report(2048, DIGEST_A),
            live_memory=_memory_report(4096, DIGEST_B),
            source_health=_source_health_payload(),
        )
        assert perf_alert.main(["sync", "--handoff-dir", str(d4)]) == 0
        assert sorted(gh.issues) == [1, 2]
        assert gh.issues[2]["state"] == "open"

    def test_partial_failure_retry_deduplicates_comment_via_marker(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import scripts.perf_alert as perf_alert

        gh = _StatefulGhSubprocessServer()
        monkeypatch.setattr("subprocess.run", gh)

        _set_prod_env(monkeypatch, run_id="37100000001", baseline_run_id="37099999999")
        w1 = _stage_cli_artifacts(
            tmp_path / "r1",
            run_id="37100000001",
            current_pinned=_full_timing_report(216.0, DIGEST_A),
            previous_pinned=_full_timing_report(180.0, DIGEST_A),
            current_receipts=_receipts_payload(run_id="37100000001"),
            previous_receipts=_receipts_payload(run_id="37099999999"),
            live_timing=_full_timing_report(182.0, DIGEST_B),
            pinned_memory=_memory_report(2048, DIGEST_A),
            live_memory=_memory_report(4096, DIGEST_B),
            source_health=_source_health_payload(),
        )
        assert perf_alert.main(["sync", "--handoff-dir", str(w1)]) == 0

        # Attempt 1: continuation comment succeeds, then PATCH fails transiently
        _set_prod_env(
            monkeypatch, run_id="37100000002", baseline_run_id="37100000001", run_attempt="1"
        )
        w2 = _stage_cli_artifacts(
            tmp_path / "r2",
            run_id="37100000002",
            current_pinned=_full_timing_report(205.0, DIGEST_A),
            previous_pinned=_full_timing_report(216.0, DIGEST_A),
            current_receipts=_receipts_payload(run_id="37100000002"),
            previous_receipts=_receipts_payload(run_id="37100000001"),
            live_timing=_full_timing_report(182.0, DIGEST_B),
            pinned_memory=_memory_report(2048, DIGEST_A),
            live_memory=_memory_report(4096, DIGEST_B),
            source_health=_source_health_payload(),
        )
        gh.fail_next_patch_error = subprocess.CalledProcessError(
            1, ["gh", "api"], stderr="HTTP 502 Bad Gateway"
        )
        assert perf_alert.main(["sync", "--handoff-dir", str(w2)]) == 1
        assert len(gh.comments[1]) == 1
        st_after_fail = perf_alert.parse_state_marker(str(gh.issues[1]["body"]))
        assert st_after_fail is not None and len(st_after_fail.history) == 1

        # Attempt 2: comment marker prevents duplicate comment and PATCH succeeds
        _set_prod_env(
            monkeypatch, run_id="37100000002", baseline_run_id="37100000001", run_attempt="2"
        )
        assert perf_alert.main(["write-context", "--output", str(w2 / "alert-context.json")]) == 0
        assert perf_alert.main(["sync", "--handoff-dir", str(w2)]) == 0
        assert len(gh.comments[1]) == 1
        st_after_retry = perf_alert.parse_state_marker(str(gh.issues[1]["body"]))
        assert st_after_retry is not None and len(st_after_retry.history) == 2


class TestSecurityAsvsL2Suite:
    """Task 3: ASVS L2 security regression suite (T-24-06..T-24-10)."""

    def test_traversal_nondir_and_malformed_handoff_rejected_without_gh(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        import scripts.perf_alert as perf_alert

        summary_file = tmp_path / "summary.md"
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))
        monkeypatch.setattr(
            "subprocess.run",
            lambda *a, **kw: pytest.fail("gh must not be called for invalid/traversal handoff"),
        )

        # 1. Path traversal outside handoff_dir rejected
        handoff = tmp_path / "handoff"
        handoff.mkdir()
        outside = tmp_path / "outside.json"
        _write_json(outside, _full_timing_report(999.0, DIGEST_A))
        assert perf_alert._safe_handoff_path(handoff, Path("../outside.json")) is None

        # Simulate symlink escape if OS permits symlinks, plus deterministic resolve-escape check
        can_symlink = True
        escaped_link = handoff / "alert-context.json"
        try:
            escaped_link.symlink_to(outside)
        except OSError, NotImplementedError:
            can_symlink = False

        if can_symlink:
            assert perf_alert.main(["sync", "--handoff-dir", str(handoff)]) == 1
            escaped_link.unlink()

        # 2. Handoff path is a regular file (not a directory) -> fail cleanly, warning in summary
        file_handoff = tmp_path / "not_a_dir.json"
        file_handoff.write_text("{}", encoding="utf-8")
        assert perf_alert.main(["sync", "--handoff-dir", str(file_handoff)]) == 1
        assert "warning" in summary_file.read_text(encoding="utf-8").lower()

        # 3. Malformed alert-context.json -> fail cleanly, no gh call
        bad_json = handoff / "alert-context.json"
        bad_json.write_text("{not valid json", encoding="utf-8")
        assert perf_alert.main(["sync", "--handoff-dir", str(handoff)]) == 1

        # 4. Path-injection run_id inside alert-context.json -> fail cleanly
        _write_json(bad_json, {"run_id": "../evil", "event_name": "schedule"})
        assert perf_alert.main(["sync", "--handoff-dir", str(handoff)]) == 1
        captured = capsys.readouterr()
        assert "ERROR:" in captured.err

        # 5. Deterministic escape check on pinned-timing/live-memory when _safe_handoff_path rejects
        _set_prod_env(monkeypatch, run_id="38000000001", baseline_run_id="38000000000")
        valid_handoff = _stage_cli_artifacts(
            tmp_path / "escape_check",
            run_id="38000000001",
            current_pinned=_full_timing_report(216.0, DIGEST_A),
            previous_pinned=_full_timing_report(180.0, DIGEST_A),
            current_receipts=_receipts_payload(),
            previous_receipts=_receipts_payload(),
            live_timing=_full_timing_report(182.0, DIGEST_B),
            pinned_memory=_memory_report(2048, DIGEST_A),
            live_memory=_memory_report(4096, DIGEST_B),
            source_health=_source_health_payload(),
        )
        orig_safe = perf_alert._safe_handoff_path
        blocked_rels = {
            perf_alert.HANDOFF_LAYOUT["pinned_timing"],
            perf_alert.HANDOFF_LAYOUT["live_memory"],
        }
        monkeypatch.setattr(
            perf_alert,
            "_safe_handoff_path",
            lambda base, rel: None if rel in blocked_rels else orig_safe(base, rel),
        )
        bundle = perf_alert.load_handoff_bundle(valid_handoff)
        assert bundle.current_pinned is None
        assert bundle.is_drifted is True
        assert "live_memory" in bundle.missing_legs

    def test_spoofed_pr_and_unlabeled_issues_never_hijack_episode(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import scripts.perf_alert as perf_alert

        gh = _StatefulGhSubprocessServer()
        spoof_state = _open_episode_state(anchor_seconds=50.0, opened_run_id="1")
        spoof_body = perf_alert.render_issue_body(spoof_state, _context(run_id="1"))
        # Inject an open PR with matching label AND an open issue missing required label
        gh.extra_api_items.extend(
            [
                {
                    "number": 900,
                    "title": "Spoofed PR",
                    "body": spoof_body,
                    "state": "open",
                    "pull_request": {"url": "https://example.invalid/pulls/900"},
                    "labels": [{"name": perf_alert.PRODUCTION_ALERT_LABEL}],
                },
                {
                    "number": 901,
                    "title": "Spoofed Unlabeled Issue",
                    "body": spoof_body,
                    "state": "open",
                    "labels": [{"name": "unrelated"}],
                },
            ]
        )
        monkeypatch.setattr("subprocess.run", gh)
        _set_prod_env(monkeypatch, run_id="38100000001", baseline_run_id="38099999999")
        d = _stage_cli_artifacts(
            tmp_path / "spoof",
            run_id="38100000001",
            current_pinned=_full_timing_report(216.0, DIGEST_A),
            previous_pinned=_full_timing_report(180.0, DIGEST_A),
            current_receipts=_receipts_payload(run_id="38100000001"),
            previous_receipts=_receipts_payload(run_id="38099999999"),
            live_timing=_full_timing_report(182.0, DIGEST_B),
            pinned_memory=_memory_report(2048, DIGEST_A),
            live_memory=_memory_report(4096, DIGEST_B),
            source_health=_source_health_payload(),
        )
        assert perf_alert.main(["sync", "--handoff-dir", str(d)]) == 0
        # Real issue #1 opened cleanly; spoofed anchor 50.0 ignored
        assert sorted(gh.issues) == [1]
        real_state = perf_alert.parse_state_marker(str(gh.issues[1]["body"]))
        assert real_state is not None and real_state.anchor_seconds == 180.0

    def test_hostile_repo_non_int_issue_and_secret_redaction_everywhere(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        import scripts.perf_alert as perf_alert

        gh_secret = "ghs_ADVERSARIAL_SECRET_AAA111"
        pat_secret = "github_pat_ADVERSARIAL_SECRET_BBB222"
        summary_file = tmp_path / "summary.md"
        monkeypatch.setenv("GH_TOKEN", gh_secret)
        monkeypatch.setenv("GITHUB_TOKEN", pat_secret)
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))

        # 1. Hostile GH_REPO rejected before subprocess
        gh = _StatefulGhSubprocessServer()
        monkeypatch.setattr("subprocess.run", gh)
        bad_client = perf_alert.GhCliIssueClient(repo="owner/repo/../../evil")
        with pytest.raises(perf_alert.PerfAlertError):
            bad_client.list_issues("perf-regression")
        assert gh.calls == []

        # 2. Non-integer issue number rejected before subprocess
        good_client = perf_alert.GhCliIssueClient(repo="MissionWAR/BlocklistMerger")
        with pytest.raises(perf_alert.PerfAlertError):
            good_client.update_issue("42/../../evil", body="x")  # type: ignore[arg-type]
        assert gh.calls == []

        # 3. Secret leakage prevention across stdout, stderr, issue body, and $GITHUB_STEP_SUMMARY
        _set_prod_env(monkeypatch, run_id="38200000001", baseline_run_id="38199999999")
        d = _stage_cli_artifacts(
            tmp_path / "secrets",
            run_id="38200000001",
            current_pinned=_full_timing_report(216.0, DIGEST_A),
            previous_pinned=_full_timing_report(180.0, DIGEST_A),
            current_receipts=_receipts_payload(run_id="38200000001"),
            previous_receipts=_receipts_payload(run_id="38199999999"),
            live_timing=_full_timing_report(182.0, DIGEST_B),
            pinned_memory=_memory_report(2048, DIGEST_A),
            live_memory=_memory_report(4096, DIGEST_B),
            source_health=_source_health_payload(),
        )
        gh.fail_next_api_error = subprocess.CalledProcessError(
            1,
            ["gh", "api"],
            stderr=f"fatal error token={gh_secret} pat={pat_secret}",
        )
        assert perf_alert.main(["sync", "--handoff-dir", str(d)]) == 1
        captured = capsys.readouterr()
        summary_text = summary_file.read_text(encoding="utf-8")
        for sensitive in (gh_secret, pat_secret):
            assert sensitive not in captured.out
            assert sensitive not in captured.err
            assert sensitive not in summary_text
        assert gh.issues == {}
