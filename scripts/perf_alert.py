"""Advisory performance regression alert engine (Python 3.14 stdlib only).

Evaluates weekly pinned-corpus timing evidence produced by ``perf-evidence.yml``
and synchronizes one tracked GitHub issue per regression episode without gating
release publication or pulling in third-party dependencies.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import shutil
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Protocol, runtime_checkable

# =========================================================================
# CONSTANTS
# =========================================================================

REGRESSION_THRESHOLD_PERCENT: Final[float] = 15.0
PRODUCTION_ALERT_LABEL: Final[str] = "perf-regression"
SMOKE_ALERT_LABEL: Final[str] = "perf-regression-test"
STATE_SCHEMA_VERSION: Final[int] = 1
STATE_MARKER_PREFIX: Final[str] = "<!-- perf-alert-state:v1 "
STATE_MARKER_SUFFIX: Final[str] = " -->"
COMMENT_MARKER_PREFIX: Final[str] = "<!-- perf-alert-comment:"
COMMENT_MARKER_SUFFIX: Final[str] = " -->"
MAX_RECORDED_RUN_IDS: Final[int] = 100
MAX_ISSUE_BODY_CHARS: Final[int] = 60_000
SMOKE_SYNTHETIC_DIGEST: Final[str] = "a" * 64
_SMOKE_LIVE_DIGEST: Final[str] = "b" * 64
_GH_CLI_TIMEOUT_SECONDS: Final[int] = 60

SUPPORTING_LEG_ORDER: Final[tuple[str, ...]] = (
    "pinned_memory",
    "fetch",
    "live_timing",
    "live_memory",
)

_HEX64_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
_REPO_SLUG_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_LABEL_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_.-]+$")
_COLOR_HEX6_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-fA-F]{6}$")
_CONTROL_CHARS_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_PYTHON_PREFIX_RE: Final[re.Pattern[str]] = re.compile(r"^python\s+", re.IGNORECASE)
_TOKEN_PATTERN_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:gh[pousr]_[A-Za-z0-9_]{8,}|github_pat_[A-Za-z0-9_]{8,})"
)

_LEG_DESCRIPTIONS: Final[dict[str, str]] = {
    "pinned_memory": "pinned memory benchmark",
    "fetch": "live blocklist download",
    "live_timing": "live timing benchmark",
    "live_memory": "live memory benchmark",
}

_SMOKE_MODES: Final[frozenset[str]] = frozenset(
    {"none", "regression", "partial_recovery", "recovery", "degraded"}
)
_SMOKE_ACTIVE_MODES: Final[tuple[str, ...]] = (
    "regression",
    "partial_recovery",
    "recovery",
    "degraded",
)
_SMOKE_BASELINE_TIMES: Final[dict[str, tuple[float, float]]] = {
    "regression": (216.0, 180.0),
    "partial_recovery": (198.0, 216.0),
    "recovery": (178.0, 198.0),
}
_OUTCOME_ENV_MAP: Final[tuple[tuple[str, str], ...]] = (
    ("OUTCOME_RESTORE", "restore"),
    ("OUTCOME_PINNED_TIMING", "pinned_timing"),
    ("OUTCOME_PINNED_MEMORY", "pinned_memory"),
    ("OUTCOME_FETCH", "fetch"),
    ("OUTCOME_LIVE_TIMING", "live_timing"),
    ("OUTCOME_LIVE_MEMORY", "live_memory"),
    ("OUTCOME_DOWNLOAD_PRIOR", "download_prior"),
)

HANDOFF_LAYOUT: Final[dict[str, Path]] = {
    "alert_context": Path("alert-context.json"),
    "pinned_timing": Path("runs/pinned-timing.json"),
    "pinned_memory": Path("runs/pinned-memory.json"),
    "live_timing": Path("runs/live-timing.json"),
    "live_memory": Path("runs/live-memory.json"),
    "receipts": Path("receipts.json"),
    "source_health": Path("source-health.json"),
    "pinned_drifted": Path("pinned-drifted"),
    "previous_pinned_timing": Path("previous/pinned-timing.json"),
    "previous_live_timing": Path("previous/live-timing.json"),
    "previous_receipts": Path("previous/receipts.json"),
}


class PerfAlertError(Exception):
    """Operational alert evaluation or GitHub API failure."""


# =========================================================================
# DATA STRUCTURES
# =========================================================================


@dataclass(frozen=True, slots=True)
class TimingReport:
    """Validated timing-mode benchmark report."""

    median_seconds: float
    manifest_sha256: str
    created_at: str = ""
    identity: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ReceiptSnapshot:
    """Normalized runner environment receipts from receipts.json or fallback."""

    cpu_model: str = "unknown"
    runner_image: str = "unknown"
    runner_image_version: str = "unknown"
    python_version: str = "unknown"
    git_revision: str = "unknown"
    run_id: str = ""
    pinned_manifest_sha256: str = ""
    live_manifest_sha256: str = ""
    prior_receipts_unavailable: bool = False

    def to_anchor_dict(self) -> dict[str, object]:
        """Serialize environment receipt fields stored in EpisodeState."""
        payload: dict[str, object] = {
            "cpu_model": self.cpu_model,
            "runner_image": self.runner_image,
            "runner_image_version": self.runner_image_version,
            "python_version": self.python_version,
        }
        if self.prior_receipts_unavailable:
            payload["prior_receipts_unavailable"] = True
        return payload


@dataclass(frozen=True, slots=True)
class ReceiptDiff:
    """Comparison result between baseline/anchor receipts and current receipts (D-24-04)."""

    env_changed: bool
    changes: tuple[tuple[str, str, str], ...] = ()
    prior_receipts_unavailable: bool = False
    summary_lines: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AlertContext:
    """Workflow execution metadata staged by perf_evidence into alert-context.json."""

    run_id: str
    run_attempt: str = "1"
    run_url: str = ""
    repo: str = ""
    git_sha: str = ""
    event_name: str = "schedule"
    smoke_mode: str = "none"
    pinned_snapshot_digest: str = ""
    pinned_snapshot_run_id: str = ""
    pinned_drifted: str = "true"
    baseline_run_id: str = ""
    baseline_run_url: str = ""
    step_outcomes: dict[str, str] = field(default_factory=dict)

    @property
    def effective_smoke_mode(self) -> str:
        """Accept smoke_mode only on workflow_dispatch triggers (D-24-14)."""
        if self.event_name == "workflow_dispatch" and self.smoke_mode in _SMOKE_MODES:
            return self.smoke_mode
        return "none"

    @property
    def episode_mode(self) -> str:
        """Return 'smoke' for isolated smoke runs, else 'production'."""
        return "smoke" if self.effective_smoke_mode != "none" else "production"

    @property
    def alert_label(self) -> str:
        """Return the repository label governing this execution mode."""
        return SMOKE_ALERT_LABEL if self.episode_mode == "smoke" else PRODUCTION_ALERT_LABEL


@dataclass(frozen=True, slots=True)
class HistoryEntry:
    """One valid weekly observation recorded in an episode's history table."""

    date: str
    run_id: str
    current_seconds: float
    anchor_delta_pct: float
    rolling_seconds: float
    rolling_delta_pct: float
    env_changed: bool = False
    missing_legs: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Return JSON-serializable representation for state markers."""
        return {
            "date": self.date,
            "run_id": self.run_id,
            "current_seconds": self.current_seconds,
            "anchor_delta_pct": self.anchor_delta_pct,
            "rolling_seconds": self.rolling_seconds,
            "rolling_delta_pct": self.rolling_delta_pct,
            "env_changed": self.env_changed,
            "missing_legs": list(self.missing_legs),
        }


@dataclass(slots=True)
class EpisodeState:
    """Machine-readable episode state persisted inside the tracked issue body."""

    schema_version: int = STATE_SCHEMA_VERSION
    episode_mode: str = "production"
    status: str = "open"
    anchor_seconds: float = 0.0
    anchor_manifest_sha256: str = ""
    anchor_run_id: str = ""
    anchor_created_at: str = ""
    anchor_receipts: dict[str, object] = field(default_factory=dict)
    opened_at: str = ""
    opened_run_id: str = ""
    recorded_run_ids: list[str] = field(default_factory=list)
    notified_corpus_digests: list[str] = field(default_factory=list)
    history: list[HistoryEntry] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        """Return JSON-serializable state dictionary."""
        return {
            "schema_version": self.schema_version,
            "episode_mode": self.episode_mode,
            "status": self.status,
            "anchor_seconds": self.anchor_seconds,
            "anchor_manifest_sha256": self.anchor_manifest_sha256,
            "anchor_run_id": self.anchor_run_id,
            "anchor_created_at": self.anchor_created_at,
            "anchor_receipts": dict(self.anchor_receipts),
            "opened_at": self.opened_at,
            "opened_run_id": self.opened_run_id,
            "recorded_run_ids": list(self.recorded_run_ids),
            "notified_corpus_digests": list(self.notified_corpus_digests),
            "history": [entry.to_dict() for entry in self.history],
        }


@dataclass(frozen=True, slots=True)
class IssueRecord:
    """Normalized GitHub issue record used for episode matching."""

    number: int
    title: str
    body: str
    state: str
    labels: tuple[str, ...] = ()
    html_url: str = ""
    created_at: str = ""
    state_reason: str | None = None
    episode_state: EpisodeState | None = None


@dataclass(frozen=True, slots=True)
class EpisodeDecision:
    """Result of evaluating one run against active episode state."""

    action: str
    reason: str
    episode_mode: str
    label: str
    target_issue_number: int | None = None
    next_state: EpisodeState | None = None
    anchor_delta_pct: float | None = None
    rolling_delta_pct: float | None = None
    missing_legs: tuple[str, ...] = ()
    env_changes: tuple[str, ...] = ()
    prior_receipts_unavailable: bool = False


@dataclass(frozen=True, slots=True)
class HandoffBundle:
    """All validated and supporting files loaded from a staged handoff directory."""

    handoff_dir: Path
    context: AlertContext
    current_pinned: TimingReport | None
    rolling_baseline: TimingReport | None
    is_drifted: bool
    current_receipts: ReceiptSnapshot | None
    prior_receipts: ReceiptSnapshot | None
    missing_legs: tuple[str, ...] = ()


# =========================================================================
# GITHUB ISSUE CLIENT
# =========================================================================


@runtime_checkable
class GitHubIssueClient(Protocol):
    """Protocol for GitHub repository issue/comment/label mutations."""

    def ensure_label(self, label: str, *, color: str, description: str) -> None: ...

    def list_issues(self, label: str) -> list[dict[str, object]]: ...

    def create_issue(
        self, *, title: str, body: str, labels: Sequence[str]
    ) -> dict[str, object]: ...

    def update_issue(
        self,
        issue_number: int,
        *,
        body: str,
        state: str | None = None,
        state_reason: str | None = None,
    ) -> dict[str, object]: ...

    def list_comments(self, issue_number: int) -> list[dict[str, object]]: ...

    def create_comment(self, issue_number: int, *, body: str) -> dict[str, object]: ...


def _redact_secrets(text: str) -> str:
    """Redact GH_TOKEN/GITHUB_TOKEN values and GitHub token shapes from diagnostics (T-24-09)."""
    redacted = _TOKEN_PATTERN_RE.sub("[REDACTED]", text)
    for env_key in ("GH_TOKEN", "GITHUB_TOKEN"):
        token = os.environ.get(env_key, "")
        if len(token) >= 4:
            redacted = redacted.replace(token, "[REDACTED]")
    return redacted


def _is_valid_repo_slug(repo: str) -> bool:
    if not _REPO_SLUG_RE.fullmatch(repo) or ".." in repo:
        return False
    owner, name = repo.split("/", 1)
    return owner not in {".", ".."} and name not in {".", ".."}


def _atomic_write_json(path: Path, data: Mapping[str, object]) -> None:
    """Write JSON atomically through a sibling temporary file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(".tmp")
    with open(temp_path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")
    temp_path.replace(path)


def _safe_handoff_path(handoff_dir: Path, relative_path: Path) -> Path | None:
    """Resolve ``relative_path`` inside ``handoff_dir``, rejecting symlink/traversal escapes."""
    try:
        base_resolved = handoff_dir.resolve()
        candidate = (handoff_dir / relative_path).resolve()
        candidate.relative_to(base_resolved)
    except OSError, ValueError:
        return None
    return candidate


class GhCliIssueClient:
    """GitHub Issues REST adapter backed by preinstalled ``gh`` CLI (shell=False)."""

    def __init__(self, repo: str | None = None) -> None:
        self._repo = (repo if repo is not None else os.environ.get("GH_REPO", "")).strip()

    def _require_repo(self) -> str:
        if not _is_valid_repo_slug(self._repo):
            raise PerfAlertError(f"Invalid or missing GH_REPO slug: {self._repo!r}")
        return self._repo

    @staticmethod
    def _validate_issue_number(issue_number: int) -> int:
        if isinstance(issue_number, bool) or not isinstance(issue_number, int) or issue_number <= 0:
            raise PerfAlertError(f"Invalid issue number: {issue_number!r}")
        return issue_number

    @staticmethod
    def _validate_label(label: str) -> str:
        if not _LABEL_RE.fullmatch(label):
            raise PerfAlertError(f"Invalid label name: {label!r}")
        return label

    @staticmethod
    def _validate_color(color: str) -> str:
        if not _COLOR_HEX6_RE.fullmatch(color):
            raise PerfAlertError(f"Invalid label hex color: {color!r}")
        return color

    def _run_gh(self, args: list[str], *, stdin_text: str | None = None) -> str:
        try:
            proc = subprocess.run(
                args,
                input=stdin_text,
                capture_output=True,
                text=True,
                encoding="utf-8",
                check=True,
                shell=False,
                timeout=_GH_CLI_TIMEOUT_SECONDS,
            )
        except OSError as exc:
            raise PerfAlertError(_redact_secrets(f"Failed to invoke gh CLI: {exc}")) from exc
        except subprocess.TimeoutExpired as exc:
            raise PerfAlertError(
                _redact_secrets(f"gh command timed out after {exc.timeout}s")
            ) from exc
        except subprocess.CalledProcessError as exc:
            stderr = _redact_secrets((exc.stderr or "").strip())
            raise PerfAlertError(f"gh command failed ({exc.returncode}): {stderr}") from exc
        return proc.stdout

    def _api_json(
        self,
        endpoint: str,
        *,
        method: str = "GET",
        payload: dict[str, object] | None = None,
        paginate: bool = False,
    ) -> object:
        cmd = ["gh", "api", "-X", method, endpoint]
        if paginate and method == "GET":
            cmd.extend(["--paginate", "--slurp"])
        stdin_text: str | None = None
        if payload is not None:
            cmd.extend(["--input", "-"])
            stdin_text = json.dumps(payload, ensure_ascii=True)
        stdout = self._run_gh(cmd, stdin_text=stdin_text)
        if not stdout.strip():
            return None
        try:
            return json.loads(stdout)
        except ValueError as exc:
            raise PerfAlertError(
                _redact_secrets(f"Invalid JSON response from GitHub API: {exc}")
            ) from exc

    @staticmethod
    def _flatten_api_list(raw: object, *, api_name: str) -> list[dict[str, object]]:
        if not isinstance(raw, list):
            raise PerfAlertError(f"Expected list response from GitHub {api_name} API")
        if raw and all(isinstance(page, list) for page in raw):
            flattened: list[dict[str, object]] = []
            for page in raw:
                flattened.extend(item for item in page if isinstance(item, dict))
            return flattened
        return [item for item in raw if isinstance(item, dict)]

    def ensure_label(self, label: str, *, color: str, description: str) -> None:
        """Idempotently create or update repository label via ``gh label create --force``."""
        repo = self._require_repo()
        safe_label = self._validate_label(label)
        safe_color = self._validate_color(color)
        self._run_gh(
            [
                "gh",
                "label",
                "create",
                safe_label,
                "--repo",
                repo,
                "--force",
                "--color",
                safe_color,
                "--description",
                description,
            ]
        )

    def list_issues(self, label: str) -> list[dict[str, object]]:
        """List open and closed repository issues for ``label``, excluding pull requests."""
        repo = self._require_repo()
        safe_label = self._validate_label(label)
        endpoint = (
            f"repos/{repo}/issues?labels={safe_label}"
            "&state=all&sort=created&direction=desc&per_page=100"
        )
        raw = self._api_json(endpoint, method="GET", paginate=True)
        items = self._flatten_api_list(raw, api_name="issues")
        return [item for item in items if "pull_request" not in item]

    def create_issue(self, *, title: str, body: str, labels: Sequence[str]) -> dict[str, object]:
        """Create a GitHub issue via stdin JSON payload."""
        repo = self._require_repo()
        safe_labels = [self._validate_label(lbl) for lbl in labels]
        raw = self._api_json(
            f"repos/{repo}/issues",
            method="POST",
            payload={"title": title, "body": body, "labels": safe_labels},
        )
        if not isinstance(raw, dict):
            raise PerfAlertError("Expected dict response from GitHub issue creation")
        return raw

    def update_issue(
        self,
        issue_number: int,
        *,
        body: str,
        state: str | None = None,
        state_reason: str | None = None,
    ) -> dict[str, object]:
        """Patch an existing issue body and optional state fields via stdin JSON."""
        repo = self._require_repo()
        number = self._validate_issue_number(issue_number)
        payload: dict[str, object] = {"body": body}
        if state is not None:
            payload["state"] = state
        if state_reason is not None:
            payload["state_reason"] = state_reason
        raw = self._api_json(
            f"repos/{repo}/issues/{number}",
            method="PATCH",
            payload=payload,
        )
        if not isinstance(raw, dict):
            raise PerfAlertError("Expected dict response from GitHub issue update")
        return raw

    def list_comments(self, issue_number: int) -> list[dict[str, object]]:
        """List issue comments via paginated REST GET."""
        repo = self._require_repo()
        number = self._validate_issue_number(issue_number)
        raw = self._api_json(
            f"repos/{repo}/issues/{number}/comments?per_page=100",
            method="GET",
            paginate=True,
        )
        return self._flatten_api_list(raw, api_name="comments")

    def create_comment(self, issue_number: int, *, body: str) -> dict[str, object]:
        """Post an issue comment via stdin JSON payload."""
        repo = self._require_repo()
        number = self._validate_issue_number(issue_number)
        raw = self._api_json(
            f"repos/{repo}/issues/{number}/comments",
            method="POST",
            payload={"body": body},
        )
        if not isinstance(raw, dict):
            raise PerfAlertError("Expected dict response from GitHub comment creation")
        return raw


# =========================================================================
# REPORT VALIDATION & SLOWDOWN MATH
# =========================================================================


def _utc_timestamp() -> str:
    """Return the current UTC timestamp in ISO-8601 Z format."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _is_valid_positive_number(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and float(value) > 0.0
    )


def _is_valid_digest(value: object) -> bool:
    return isinstance(value, str) and bool(_HEX64_RE.fullmatch(value))


def parse_timing_report(document: object) -> TimingReport | None:
    """Validate and extract timing fields matching scripts.benchmark precedence.

    Follows exact ``extract_perf_fields`` precedence (``summary.median_seconds``
    then top-level ``median_seconds``; ``corpus.manifest_sha256`` then top-level
    ``manifest_sha256``) while enforcing strict ALERT-02 integrity checks.
    Returns ``None`` cleanly for any invalid or non-timing document.
    """
    if not isinstance(document, dict):
        return None
    if document.get("report_type") != "corpus_benchmark":
        return None
    if document.get("mode") != "timing":
        return None

    summary = document.get("summary")
    corpus = document.get("corpus")

    median_candidates: list[object] = []
    if isinstance(summary, Mapping):
        median_candidates.append(summary.get("median_seconds"))
    median_candidates.append(document.get("median_seconds"))

    digest_candidates: list[object] = []
    if isinstance(corpus, Mapping):
        digest_candidates.append(corpus.get("manifest_sha256"))
    digest_candidates.append(document.get("manifest_sha256"))

    median_value = next(
        (
            candidate
            for candidate in median_candidates
            if isinstance(candidate, (int, float)) and not isinstance(candidate, bool)
        ),
        None,
    )
    digest_value = next(
        (
            candidate
            for candidate in digest_candidates
            if isinstance(candidate, str) and bool(candidate)
        ),
        None,
    )

    if not _is_valid_positive_number(median_value) or not _is_valid_digest(digest_value):
        return None

    created_raw = document.get("created_at")
    created_at = created_raw if isinstance(created_raw, str) else ""

    identity: dict[str, str] = {}
    raw_identity = document.get("identity")
    if isinstance(raw_identity, Mapping):
        for key in ("python_version", "platform", "package_version", "git_revision"):
            val = raw_identity.get(key)
            if isinstance(val, str) and val:
                identity[key] = val

    return TimingReport(
        median_seconds=float(median_value),
        manifest_sha256=str(digest_value),
        created_at=created_at,
        identity=identity,
    )


def _read_json_object(path: Path) -> dict[str, object] | None:
    try:
        raw_text = path.read_text(encoding="utf-8")
        data = json.loads(raw_text)
    except OSError, UnicodeDecodeError, ValueError:
        return None
    return data if isinstance(data, dict) else None


def load_timing_report(path: Path) -> TimingReport | None:
    """Load and strictly validate a timing report JSON file."""
    data = _read_json_object(path)
    if data is None:
        return None
    return parse_timing_report(data)


def compute_slowdown_percent(baseline_seconds: float, current_seconds: float) -> float:
    """Return unrounded percent slowdown; positive means current is slower."""
    if not _is_valid_positive_number(baseline_seconds):
        raise ValueError(f"baseline_seconds must be finite > 0 (got {baseline_seconds!r})")
    if not _is_valid_positive_number(current_seconds):
        raise ValueError(f"current_seconds must be finite > 0 (got {current_seconds!r})")
    return (float(current_seconds) - float(baseline_seconds)) / float(baseline_seconds) * 100.0


def is_regression_breach(baseline_seconds: float, current_seconds: float) -> bool:
    """Inclusive unrounded >= 15.0% check (D-24-02)."""
    return (
        compute_slowdown_percent(baseline_seconds, current_seconds) >= REGRESSION_THRESHOLD_PERCENT
    )


def is_anchor_recovered(anchor_seconds: float, current_seconds: float) -> bool:
    """Return True when current_seconds returns at-or-faster-than anchor_seconds (D-24-06)."""
    if not _is_valid_positive_number(anchor_seconds):
        raise ValueError(f"anchor_seconds must be finite > 0 (got {anchor_seconds!r})")
    if not _is_valid_positive_number(current_seconds):
        raise ValueError(f"current_seconds must be finite > 0 (got {current_seconds!r})")
    return float(current_seconds) <= float(anchor_seconds)


# =========================================================================
# RECEIPTS & SUPPORTING LEG ISOLATION (D-24-04, D-24-05)
# =========================================================================


def normalize_python_version(version: str) -> str:
    """Strip optional 'Python ' prefix so '3.14.7' matches 'Python 3.14.7'."""
    stripped = version.strip()
    if not stripped:
        return ""
    return _PYTHON_PREFIX_RE.sub("", stripped).strip()


def load_receipts(path: Path) -> ReceiptSnapshot | None:
    """Load environment receipts from ``receipts.json`` cleanly."""
    data = _read_json_object(path)
    if data is None:
        return None
    return ReceiptSnapshot(
        cpu_model=str(data.get("cpu_model", "unknown")),
        runner_image=str(data.get("runner_image", "unknown")),
        runner_image_version=str(data.get("runner_image_version", "unknown")),
        python_version=str(data.get("python_version", "unknown")),
        git_revision=str(data.get("git_revision", "unknown")),
        run_id=str(data.get("run_id", "")),
        pinned_manifest_sha256=str(data.get("pinned_manifest_sha256", "")),
        live_manifest_sha256=str(data.get("live_manifest_sha256", "")),
        prior_receipts_unavailable=False,
    )


def extract_identity_fallback_receipts(report: TimingReport | None) -> ReceiptSnapshot:
    """Build a fallback ReceiptSnapshot from TimingReport.identity when receipts.json is absent."""
    if report is None:
        return ReceiptSnapshot(prior_receipts_unavailable=True)
    return ReceiptSnapshot(
        cpu_model="unknown",
        runner_image="unknown",
        runner_image_version="unknown",
        python_version=report.identity.get("python_version", "unknown"),
        git_revision=report.identity.get("git_revision", "unknown"),
        pinned_manifest_sha256=report.manifest_sha256,
        prior_receipts_unavailable=True,
    )


def _coerce_receipt_fields(
    baseline: ReceiptSnapshot | Mapping[str, object] | None,
) -> tuple[str, str, str, str, bool]:
    if baseline is None:
        return ("unknown", "unknown", "unknown", "unknown", True)
    if isinstance(baseline, ReceiptSnapshot):
        return (
            baseline.cpu_model,
            baseline.runner_image,
            baseline.runner_image_version,
            baseline.python_version,
            baseline.prior_receipts_unavailable,
        )
    return (
        str(baseline.get("cpu_model", "unknown")),
        str(baseline.get("runner_image", "unknown")),
        str(baseline.get("runner_image_version", "unknown")),
        str(baseline.get("python_version", "unknown")),
        bool(baseline.get("prior_receipts_unavailable", False)) or not bool(baseline),
    )


def _is_known_receipt_value(value: str) -> bool:
    lowered = value.strip().lower()
    return bool(lowered) and lowered != "unknown" and not lowered.startswith("unknown (")


def diff_receipts(
    baseline: ReceiptSnapshot | Mapping[str, object] | None,
    current: ReceiptSnapshot | None,
) -> ReceiptDiff:
    """Diff runner environment receipts without fabricating CPU/image diffs on fallback."""
    base_cpu, base_img, base_img_ver, base_py, prior_unavailable = _coerce_receipt_fields(baseline)
    if current is None:
        return ReceiptDiff(
            env_changed=False,
            changes=(),
            prior_receipts_unavailable=prior_unavailable,
            summary_lines=(),
        )

    changes: list[tuple[str, str, str]] = []
    if not prior_unavailable:
        for field_name, before, after in (
            ("cpu_model", base_cpu, current.cpu_model),
            ("runner_image", base_img, current.runner_image),
            ("runner_image_version", base_img_ver, current.runner_image_version),
        ):
            if (
                _is_known_receipt_value(before)
                and _is_known_receipt_value(after)
                and before != after
            ):
                changes.append((field_name, before, after))

    norm_before = normalize_python_version(base_py)
    norm_after = normalize_python_version(current.python_version)
    if (
        _is_known_receipt_value(norm_before)
        and _is_known_receipt_value(norm_after)
        and norm_before != norm_after
    ):
        changes.append(("python_version", base_py, current.python_version))

    summary_lines = tuple(
        f"{_sanitize_cell(field)}: {_sanitize_cell(before)} -> {_sanitize_cell(after)}"
        for field, before, after in changes
    )
    return ReceiptDiff(
        env_changed=bool(changes),
        changes=tuple(changes),
        prior_receipts_unavailable=prior_unavailable,
        summary_lines=summary_lines,
    )


def _is_valid_memory_report(path: Path) -> bool:
    doc = _read_json_object(path)
    if doc is None:
        return False
    if doc.get("report_type") != "corpus_benchmark" or doc.get("mode") != "memory":
        return False
    peak = doc.get("tracemalloc_peak_bytes")
    if (
        not isinstance(peak, (int, float))
        or isinstance(peak, bool)
        or not math.isfinite(float(peak))
        or float(peak) < 0.0
    ):
        return False
    corpus = doc.get("corpus")
    digest = corpus.get("manifest_sha256") if isinstance(corpus, Mapping) else None
    if digest is None:
        digest = doc.get("manifest_sha256")
    return not (digest is not None and not _is_valid_digest(digest))


def _is_valid_source_health(path: Path) -> bool:
    doc = _read_json_object(path)
    if doc is None:
        return False
    source_count = doc.get("source_count")
    if isinstance(source_count, bool) or not isinstance(source_count, int) or source_count < 0:
        return False
    return isinstance(doc.get("totals_by_status"), dict)


def detect_missing_legs(handoff_dir: Path, context: AlertContext) -> tuple[str, ...]:
    """Identify failed or invalid non-pinned supporting legs without suppressing pinned alerts."""
    missing: list[str] = []
    outcomes = context.step_outcomes

    pinned_mem_path = _safe_handoff_path(handoff_dir, HANDOFF_LAYOUT["pinned_memory"])
    if (
        outcomes.get("pinned_memory") == "failure"
        or pinned_mem_path is None
        or not _is_valid_memory_report(pinned_mem_path)
    ):
        missing.append("pinned_memory")

    source_health_path = _safe_handoff_path(handoff_dir, HANDOFF_LAYOUT["source_health"])
    if (
        outcomes.get("fetch") == "failure"
        or source_health_path is None
        or not _is_valid_source_health(source_health_path)
    ):
        missing.append("fetch")

    live_timing_path = _safe_handoff_path(handoff_dir, HANDOFF_LAYOUT["live_timing"])
    if (
        outcomes.get("live_timing") == "failure"
        or live_timing_path is None
        or load_timing_report(live_timing_path) is None
    ):
        missing.append("live_timing")

    live_mem_path = _safe_handoff_path(handoff_dir, HANDOFF_LAYOUT["live_memory"])
    if (
        outcomes.get("live_memory") == "failure"
        or live_mem_path is None
        or not _is_valid_memory_report(live_mem_path)
    ):
        missing.append("live_memory")

    return tuple(missing)


# =========================================================================
# STATE MARKER CODEC (T-24-03)
# =========================================================================


def serialize_state(state: EpisodeState) -> str:
    """Serialize EpisodeState to ASCII JSON with angle brackets escaped (T-24-03)."""
    raw_json = json.dumps(state.to_dict(), ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return raw_json.replace("<", "\\u003c").replace(">", "\\u003e")


def format_state_marker(state: EpisodeState) -> str:
    """Wrap serialized EpisodeState JSON inside the HTML state marker comment."""
    return f"{STATE_MARKER_PREFIX}{serialize_state(state)}{STATE_MARKER_SUFFIX}"


def _parse_history_entry(raw: object) -> HistoryEntry | None:
    if not isinstance(raw, dict):
        return None
    date_val = raw.get("date")
    run_id_val = raw.get("run_id")
    current_val = raw.get("current_seconds")
    anchor_delta_val = raw.get("anchor_delta_pct")
    rolling_val = raw.get("rolling_seconds")
    rolling_delta_val = raw.get("rolling_delta_pct")
    env_changed_val = raw.get("env_changed", False)
    missing_legs_val = raw.get("missing_legs", [])

    if not isinstance(date_val, str) or not isinstance(run_id_val, str) or not run_id_val:
        return None
    if not _is_valid_positive_number(current_val) or not _is_valid_positive_number(rolling_val):
        return None
    for delta in (anchor_delta_val, rolling_delta_val):
        if (
            not isinstance(delta, (int, float))
            or isinstance(delta, bool)
            or not math.isfinite(float(delta))
        ):
            return None
    if not isinstance(env_changed_val, bool):
        return None
    if not isinstance(missing_legs_val, list) or not all(
        isinstance(leg, str) for leg in missing_legs_val
    ):
        return None

    return HistoryEntry(
        date=date_val,
        run_id=run_id_val,
        current_seconds=float(current_val),
        anchor_delta_pct=float(anchor_delta_val),
        rolling_seconds=float(rolling_val),
        rolling_delta_pct=float(rolling_delta_val),
        env_changed=env_changed_val,
        missing_legs=tuple(missing_legs_val),
    )


def parse_state_marker(body: str | None) -> EpisodeState | None:
    """Decode and strictly validate the embedded EpisodeState marker from an issue body."""
    if not isinstance(body, str) or not body:
        return None

    start = body.rfind(STATE_MARKER_PREFIX)
    if start == -1:
        return None
    payload_start = start + len(STATE_MARKER_PREFIX)
    end = body.find(STATE_MARKER_SUFFIX, payload_start)
    if end == -1:
        return None

    try:
        raw = json.loads(body[payload_start:end])
    except ValueError:
        return None

    if not isinstance(raw, dict):
        return None

    schema_version = raw.get("schema_version")
    if isinstance(schema_version, bool) or schema_version != STATE_SCHEMA_VERSION:
        return None

    episode_mode = raw.get("episode_mode")
    status = raw.get("status")
    if episode_mode not in {"production", "smoke"} or status not in {"open", "recovered"}:
        return None

    anchor_seconds = raw.get("anchor_seconds")
    anchor_manifest = raw.get("anchor_manifest_sha256")
    anchor_run_id = raw.get("anchor_run_id")
    opened_run_id = raw.get("opened_run_id")
    if not _is_valid_positive_number(anchor_seconds):
        return None
    if not _is_valid_digest(anchor_manifest):
        return None
    if not isinstance(anchor_run_id, str) or not anchor_run_id:
        return None
    if not isinstance(opened_run_id, str) or not opened_run_id:
        return None

    anchor_created_at = raw.get("anchor_created_at", "")
    opened_at = raw.get("opened_at", "")
    anchor_receipts = raw.get("anchor_receipts", {})
    recorded_run_ids = raw.get("recorded_run_ids", [])
    notified_digests = raw.get("notified_corpus_digests", [])
    raw_history = raw.get("history", [])

    if not isinstance(anchor_created_at, str) or not isinstance(opened_at, str):
        return None
    if not isinstance(anchor_receipts, dict):
        return None
    if not isinstance(recorded_run_ids, list) or not all(
        isinstance(rid, str) and rid for rid in recorded_run_ids
    ):
        return None
    if not isinstance(notified_digests, list) or not all(
        _is_valid_digest(digest) for digest in notified_digests
    ):
        return None
    if not isinstance(raw_history, list):
        return None

    parsed_history: list[HistoryEntry] = []
    for item in raw_history:
        entry = _parse_history_entry(item)
        if entry is None:
            return None
        parsed_history.append(entry)

    return EpisodeState(
        schema_version=STATE_SCHEMA_VERSION,
        episode_mode=episode_mode,
        status=status,
        anchor_seconds=float(anchor_seconds),
        anchor_manifest_sha256=str(anchor_manifest),
        anchor_run_id=anchor_run_id,
        anchor_created_at=anchor_created_at,
        anchor_receipts=dict(anchor_receipts),
        opened_at=opened_at,
        opened_run_id=opened_run_id,
        recorded_run_ids=list(recorded_run_ids),
        notified_corpus_digests=list(notified_digests),
        history=parsed_history,
    )


# =========================================================================
# HANDOFF LOADING & EPISODE STATE MACHINE (13-ROW MATRIX)
# =========================================================================


def sanitize_markdown_text(text: str) -> str:
    """Neutralize HTML comments, control characters, and Markdown table pipes (T-24-08)."""
    cleaned = _CONTROL_CHARS_RE.sub(" ", text)
    while "<!--" in cleaned or "-->" in cleaned or "--!>" in cleaned:
        cleaned = cleaned.replace("<!--", " ").replace("-->", " ").replace("--!>", " ")
    cleaned = re.sub(r"\\+\|", "|", cleaned).replace("|", "\\|")
    return " ".join(cleaned.split())


def _sanitize_cell(text: str) -> str:
    return sanitize_markdown_text(text)


def _sanitize_http_url(url: str) -> str:
    if _CONTROL_CHARS_RE.search(url):
        return ""
    cleaned = sanitize_markdown_text(url.strip())
    if not cleaned.startswith(("https://", "http://")):
        return ""
    if any(ch.isspace() or ch in ("(", ")", "[", "]", "<", ">") for ch in cleaned):
        return ""
    scheme_len = 8 if cleaned.startswith("https://") else 7
    if len(cleaned) <= scheme_len:
        return ""
    return cleaned


def _derive_workflow_run_url(context: AlertContext, run_id: str) -> str:
    safe_id = sanitize_markdown_text(run_id)
    if not safe_id or not safe_id.isdigit():
        return ""
    if safe_id == context.run_id and context.run_url:
        return _sanitize_http_url(context.run_url)
    suffix = f"/actions/runs/{context.run_id}"
    if context.run_url and context.run_id and context.run_url.endswith(suffix):
        return _sanitize_http_url(f"{context.run_url[: -len(suffix)]}/actions/runs/{safe_id}")
    if context.repo and _is_valid_repo_slug(context.repo):
        return f"https://github.com/{context.repo}/actions/runs/{safe_id}"
    return ""


def _validate_run_id(value: object, *, error_message: str) -> str:
    if value is None or isinstance(value, bool):
        raise PerfAlertError(error_message)
    run_id = str(value).strip()
    if (
        not run_id
        or len(run_id) > 128
        or _CONTROL_CHARS_RE.search(run_id)
        or "/" in run_id
        or "\\" in run_id
        or ".." in run_id
    ):
        raise PerfAlertError(error_message)
    return run_id


def _format_run_reference(
    context: AlertContext,
    run_id: str,
    *,
    is_smoke_baseline: bool = False,
) -> str:
    safe_id = sanitize_markdown_text(run_id)
    if is_smoke_baseline:
        return f"synthetic smoke baseline `{safe_id}` (not a production workflow run)"
    url = _derive_workflow_run_url(context, safe_id)
    if url:
        return f"run `{safe_id}` ({url})"
    return f"run `{safe_id}`"


def _load_alert_context(path: Path) -> AlertContext:
    data = _read_json_object(path)
    if data is None:
        raise PerfAlertError(f"Missing or invalid alert-context.json at {path}")

    run_id = _validate_run_id(
        data.get("run_id", ""),
        error_message=f"alert-context.json missing or invalid run_id: {path}",
    )

    raw_outcomes = data.get("step_outcomes")
    step_outcomes: dict[str, str] = {}
    if isinstance(raw_outcomes, Mapping):
        for key, value in raw_outcomes.items():
            if isinstance(key, str) and isinstance(value, str):
                step_outcomes[key] = value

    return AlertContext(
        run_id=run_id,
        run_attempt=str(data.get("run_attempt", "1")),
        run_url=str(data.get("run_url", "")),
        repo=str(data.get("repo", "")),
        git_sha=str(data.get("git_sha", "")),
        event_name=str(data.get("event_name", "schedule")).strip(),
        smoke_mode=str(data.get("smoke_mode", "none")).strip() or "none",
        pinned_snapshot_digest=str(data.get("pinned_snapshot_digest", "")).strip(),
        pinned_snapshot_run_id=str(data.get("pinned_snapshot_run_id", "")).strip(),
        pinned_drifted=str(data.get("pinned_drifted", "true")).strip().lower(),
        baseline_run_id=str(data.get("baseline_run_id", "")).strip(),
        baseline_run_url=str(data.get("baseline_run_url", "")).strip(),
        step_outcomes=step_outcomes,
    )


def load_handoff_bundle(handoff_dir: Path) -> HandoffBundle:
    """Load staged alert handoff artifacts from ``handoff_dir``."""
    if not handoff_dir.is_dir():
        raise PerfAlertError(
            f"Handoff directory does not exist or is not a directory: {handoff_dir}"
        )
    context_path = _safe_handoff_path(handoff_dir, HANDOFF_LAYOUT["alert_context"])
    if context_path is None:
        raise PerfAlertError("Refusing alert-context.json outside handoff directory")
    context = _load_alert_context(context_path)

    pinned_timing_path = _safe_handoff_path(handoff_dir, HANDOFF_LAYOUT["pinned_timing"])
    current_pinned = load_timing_report(pinned_timing_path) if pinned_timing_path else None

    prev_pinned_path = _safe_handoff_path(handoff_dir, HANDOFF_LAYOUT["previous_pinned_timing"])
    rolling_baseline = load_timing_report(prev_pinned_path) if prev_pinned_path else None

    drifted_path = _safe_handoff_path(handoff_dir, HANDOFF_LAYOUT["pinned_drifted"])
    sentinel_present = drifted_path is None or drifted_path.exists()
    is_drifted = context.pinned_drifted != "false" or sentinel_present or pinned_timing_path is None

    receipts_path = _safe_handoff_path(handoff_dir, HANDOFF_LAYOUT["receipts"])
    current_receipts = load_receipts(receipts_path) if receipts_path else None
    if current_receipts is None and current_pinned is not None:
        current_receipts = extract_identity_fallback_receipts(current_pinned)

    prev_receipts_path = _safe_handoff_path(handoff_dir, HANDOFF_LAYOUT["previous_receipts"])
    prior_receipts = load_receipts(prev_receipts_path) if prev_receipts_path else None
    if prior_receipts is None:
        prior_receipts = extract_identity_fallback_receipts(rolling_baseline)
    missing_legs = detect_missing_legs(handoff_dir, context)
    return HandoffBundle(
        handoff_dir=handoff_dir,
        context=context,
        current_pinned=current_pinned,
        rolling_baseline=rolling_baseline,
        is_drifted=is_drifted,
        current_receipts=current_receipts,
        prior_receipts=prior_receipts,
        missing_legs=missing_legs,
    )


def _append_recorded_run_id(
    existing: Sequence[str],
    run_id: str,
    opened_run_id: str,
) -> list[str]:
    ordered = list(existing)
    if run_id not in ordered:
        ordered.append(run_id)
    if len(ordered) <= MAX_RECORDED_RUN_IDS:
        return ordered
    if opened_run_id:
        tail = [rid for rid in ordered if rid != opened_run_id]
        keep_tail = MAX_RECORDED_RUN_IDS - 1
        return [opened_run_id, *tail[-keep_tail:]] if keep_tail > 0 else [opened_run_id]
    return ordered[-MAX_RECORDED_RUN_IDS:]


def _date_part(timestamp: str) -> str:
    if len(timestamp) >= 10 and timestamp[4] == "-" and timestamp[7] == "-":
        return timestamp[:10]
    return time.strftime("%Y-%m-%d", time.gmtime())


def _is_valid_current_pinned(
    context: AlertContext,
    current_pinned: TimingReport | None,
    *,
    is_drifted: bool,
) -> bool:
    if is_drifted or current_pinned is None:
        return False
    if not _is_valid_digest(context.pinned_snapshot_digest):
        return False
    return current_pinned.manifest_sha256 == context.pinned_snapshot_digest


def _is_valid_rolling_baseline(
    context: AlertContext,
    current_pinned: TimingReport | None,
    rolling_baseline: TimingReport | None,
) -> bool:
    if not context.baseline_run_id or current_pinned is None or rolling_baseline is None:
        return False
    return rolling_baseline.manifest_sha256 == current_pinned.manifest_sha256


def _extract_label_names(raw_labels: object) -> tuple[str, ...]:
    if not isinstance(raw_labels, Sequence) or isinstance(raw_labels, (str, bytes)):
        return ()
    names: list[str] = []
    for lbl in raw_labels:
        if isinstance(lbl, Mapping):
            name = lbl.get("name")
            if isinstance(name, str) and name:
                names.append(name)
        elif isinstance(lbl, str) and lbl:
            names.append(lbl)
    return tuple(names)


def select_active_episode_issue(
    issues: Sequence[Mapping[str, object] | IssueRecord],
    *,
    episode_mode: str,
    required_label: str,
) -> IssueRecord | None:
    """Select the authoritative tracked issue matching ``episode_mode`` and ``required_label``.

    Filters out pull requests, requires ``required_label`` and valid embedded
    state JSON matching ``episode_mode`` (T-24-02), and ranks open episodes >
    manually-closed unretired episodes > recovered episodes sorted by numeric
    issue number descending.
    """
    ranked: list[tuple[int, int, IssueRecord]] = []
    for item in issues:
        if isinstance(item, IssueRecord):
            if item.number <= 0 or required_label not in item.labels:
                continue
            if item.state not in {"open", "closed"}:
                continue
            parsed = item.episode_state or parse_state_marker(item.body)
            if parsed is None or parsed.episode_mode != episode_mode:
                continue
            record = IssueRecord(
                number=item.number,
                title=item.title,
                body=item.body,
                state=item.state,
                labels=item.labels,
                html_url=item.html_url,
                created_at=item.created_at,
                state_reason=item.state_reason,
                episode_state=parsed,
            )
        else:
            if "pull_request" in item:
                continue
            number = item.get("number")
            if isinstance(number, bool) or not isinstance(number, int) or number <= 0:
                continue
            state_val = item.get("state")
            if state_val not in {"open", "closed"}:
                continue
            labels = _extract_label_names(item.get("labels"))
            if required_label not in labels:
                continue
            body_raw = item.get("body")
            body_text = body_raw if isinstance(body_raw, str) else ""
            parsed = parse_state_marker(body_text)
            if parsed is None or parsed.episode_mode != episode_mode:
                continue
            reason_raw = item.get("state_reason")
            record = IssueRecord(
                number=number,
                title=str(item.get("title", "")),
                body=body_text,
                state=str(state_val),
                labels=labels,
                html_url=str(item.get("html_url", "")),
                created_at=str(item.get("created_at", "")),
                state_reason=reason_raw if isinstance(reason_raw, str) else None,
                episode_state=parsed,
            )

        assert record.episode_state is not None
        if record.state == "open" and record.episode_state.status == "open":
            tier = 3
        elif record.state == "closed" and record.episode_state.status == "open":
            tier = 2
        else:
            tier = 1
        ranked.append((tier, record.number, record))

    if not ranked:
        return None
    ranked.sort(key=lambda entry: (entry[0], entry[1]), reverse=True)
    return ranked[0][2]


def _copy_state(
    state: EpisodeState,
    *,
    status: str | None = None,
    anchor_run_id: str | None = None,
    anchor_receipts: dict[str, object] | None = None,
    opened_run_id: str | None = None,
    recorded_run_ids: list[str] | None = None,
    notified_corpus_digests: list[str] | None = None,
    history: list[HistoryEntry] | None = None,
) -> EpisodeState:
    return EpisodeState(
        schema_version=STATE_SCHEMA_VERSION,
        episode_mode=state.episode_mode,
        status=status if status is not None else state.status,
        anchor_seconds=state.anchor_seconds,
        anchor_manifest_sha256=state.anchor_manifest_sha256,
        anchor_run_id=anchor_run_id if anchor_run_id is not None else state.anchor_run_id,
        anchor_created_at=state.anchor_created_at,
        anchor_receipts=(
            dict(anchor_receipts) if anchor_receipts is not None else dict(state.anchor_receipts)
        ),
        opened_at=state.opened_at,
        opened_run_id=opened_run_id if opened_run_id is not None else state.opened_run_id,
        recorded_run_ids=(
            list(recorded_run_ids) if recorded_run_ids is not None else list(state.recorded_run_ids)
        ),
        notified_corpus_digests=(
            list(notified_corpus_digests)
            if notified_corpus_digests is not None
            else list(state.notified_corpus_digests)
        ),
        history=list(history) if history is not None else list(state.history),
    )


def _evaluate_open_episode(
    *,
    context: AlertContext,
    state: EpisodeState,
    active_issue: IssueRecord,
    current_pinned: TimingReport | None,
    rolling_baseline: TimingReport | None,
    current_valid: bool,
    rolling_valid: bool,
    current_receipts: ReceiptSnapshot | None,
    legs: tuple[str, ...],
) -> EpisodeDecision:
    episode_mode = context.episode_mode
    label = context.alert_label

    # Row 5: Degraded current pinned
    if not current_valid or current_pinned is None:
        return EpisodeDecision(
            action="noop",
            reason="row_5_degraded_current",
            episode_mode=episode_mode,
            label=label,
            target_issue_number=active_issue.number,
        )

    # Row 7 (strictly precedes Row 6!): corpus re-pinned mid-episode (D1 -> D2)
    if current_pinned.manifest_sha256 != state.anchor_manifest_sha256:
        new_digest = current_pinned.manifest_sha256
        if new_digest in state.notified_corpus_digests:
            return EpisodeDecision(
                action="noop",
                reason="row_7_corpus_changed_already_notified",
                episode_mode=episode_mode,
                label=label,
                target_issue_number=active_issue.number,
            )
        receipt_diff = diff_receipts(state.anchor_receipts, current_receipts)
        next_state = _copy_state(
            state,
            recorded_run_ids=_append_recorded_run_id(
                state.recorded_run_ids, context.run_id, state.opened_run_id
            ),
            notified_corpus_digests=[*state.notified_corpus_digests, new_digest],
        )
        return EpisodeDecision(
            action="hold_open",
            reason="row_7_corpus_changed_hold",
            episode_mode=episode_mode,
            label=label,
            target_issue_number=active_issue.number,
            next_state=next_state,
            missing_legs=legs,
            env_changes=receipt_diff.summary_lines,
            prior_receipts_unavailable=receipt_diff.prior_receipts_unavailable,
        )

    # Row 6: Same corpus, missing/invalid/expired rolling baseline
    if not rolling_valid or rolling_baseline is None:
        return EpisodeDecision(
            action="noop",
            reason="row_6_missing_rolling_baseline",
            episode_mode=episode_mode,
            label=label,
            target_issue_number=active_issue.number,
        )

    anchor_delta = compute_slowdown_percent(state.anchor_seconds, current_pinned.median_seconds)
    rolling_delta = compute_slowdown_percent(
        rolling_baseline.median_seconds, current_pinned.median_seconds
    )
    receipt_diff = diff_receipts(state.anchor_receipts, current_receipts)
    entry = HistoryEntry(
        date=_date_part(current_pinned.created_at),
        run_id=context.run_id,
        current_seconds=current_pinned.median_seconds,
        anchor_delta_pct=anchor_delta,
        rolling_seconds=rolling_baseline.median_seconds,
        rolling_delta_pct=rolling_delta,
        env_changed=receipt_diff.env_changed,
        missing_legs=legs,
    )
    next_run_ids = _append_recorded_run_id(
        state.recorded_run_ids, context.run_id, state.opened_run_id
    )

    # Row 9: Recovery (<= pre-episode anchor)
    if is_anchor_recovered(state.anchor_seconds, current_pinned.median_seconds):
        next_state = _copy_state(
            state,
            status="recovered",
            recorded_run_ids=next_run_ids,
            history=[*state.history, entry],
        )
        return EpisodeDecision(
            action="close",
            reason="row_9_recovered",
            episode_mode=episode_mode,
            label=label,
            target_issue_number=active_issue.number,
            next_state=next_state,
            anchor_delta_pct=anchor_delta,
            rolling_delta_pct=rolling_delta,
            missing_legs=legs,
            env_changes=receipt_diff.summary_lines,
            prior_receipts_unavailable=receipt_diff.prior_receipts_unavailable,
        )

    # Row 8: Still slower than anchor (worse, flat, or partial recovery per D-24-07)
    next_state = _copy_state(
        state,
        status="open",
        recorded_run_ids=next_run_ids,
        history=[*state.history, entry],
    )
    return EpisodeDecision(
        action="update",
        reason="row_8_continuation",
        episode_mode=episode_mode,
        label=label,
        target_issue_number=active_issue.number,
        next_state=next_state,
        anchor_delta_pct=anchor_delta,
        rolling_delta_pct=rolling_delta,
        missing_legs=legs,
        env_changes=receipt_diff.summary_lines,
        prior_receipts_unavailable=receipt_diff.prior_receipts_unavailable,
    )


def _evaluate_manually_closed_episode(
    *,
    context: AlertContext,
    state: EpisodeState,
    active_issue: IssueRecord,
    current_pinned: TimingReport | None,
    rolling_baseline: TimingReport | None,
    current_valid: bool,
    rolling_valid: bool,
    current_receipts: ReceiptSnapshot | None,
    legs: tuple[str, ...],
) -> EpisodeDecision:
    episode_mode = context.episode_mode
    label = context.alert_label

    # Row 10: Degraded, corpus changed, or missing rolling baseline -> respect manual closure
    if (
        not current_valid
        or current_pinned is None
        or current_pinned.manifest_sha256 != state.anchor_manifest_sha256
        or not rolling_valid
        or rolling_baseline is None
    ):
        return EpisodeDecision(
            action="noop",
            reason="row_10_manually_closed_degraded_or_repinned",
            episode_mode=episode_mode,
            label=label,
            target_issue_number=active_issue.number,
        )

    anchor_delta = compute_slowdown_percent(state.anchor_seconds, current_pinned.median_seconds)
    rolling_delta = compute_slowdown_percent(
        rolling_baseline.median_seconds, current_pinned.median_seconds
    )

    # Row 12: Valid recovery <= anchor -> silently retire closed body marker
    if is_anchor_recovered(state.anchor_seconds, current_pinned.median_seconds):
        receipt_diff = diff_receipts(state.anchor_receipts, current_receipts)
        entry = HistoryEntry(
            date=_date_part(current_pinned.created_at),
            run_id=context.run_id,
            current_seconds=current_pinned.median_seconds,
            anchor_delta_pct=anchor_delta,
            rolling_seconds=rolling_baseline.median_seconds,
            rolling_delta_pct=rolling_delta,
            env_changed=receipt_diff.env_changed,
            missing_legs=legs,
        )
        next_state = _copy_state(
            state,
            status="recovered",
            recorded_run_ids=_append_recorded_run_id(
                state.recorded_run_ids, context.run_id, state.opened_run_id
            ),
            history=[*state.history, entry],
        )
        return EpisodeDecision(
            action="retire_manually_closed",
            reason="row_12_retire_manually_closed",
            episode_mode=episode_mode,
            label=label,
            target_issue_number=active_issue.number,
            next_state=next_state,
            anchor_delta_pct=anchor_delta,
            rolling_delta_pct=rolling_delta,
            missing_legs=legs,
            env_changes=receipt_diff.summary_lines,
            prior_receipts_unavailable=receipt_diff.prior_receipts_unavailable,
        )

    # Row 11: Still unrecovered (> anchor) -> respect manual closure, never reopen/duplicate
    return EpisodeDecision(
        action="noop",
        reason="row_11_manually_closed_unrecovered",
        episode_mode=episode_mode,
        label=label,
        target_issue_number=active_issue.number,
        anchor_delta_pct=anchor_delta,
        rolling_delta_pct=rolling_delta,
    )


def evaluate_episode(
    *,
    context: AlertContext,
    current_pinned: TimingReport | None,
    rolling_baseline: TimingReport | None,
    is_drifted: bool,
    active_issue: IssueRecord | None = None,
    active_state: EpisodeState | None = None,
    current_receipts: ReceiptSnapshot | None = None,
    prior_receipts: ReceiptSnapshot | None = None,
    missing_legs: Sequence[str] = (),
) -> EpisodeDecision:
    """Evaluate one perf-evidence run across the complete 13-row episode matrix."""
    episode_mode = context.episode_mode
    label = context.alert_label
    legs = tuple(missing_legs)

    state = active_state
    if active_issue is not None and state is None:
        state = active_issue.episode_state or parse_state_marker(active_issue.body)
    if state is not None and state.episode_mode != episode_mode:
        raise PerfAlertError(
            f"Episode mode mismatch: active state is {state.episode_mode!r}, "
            f"context is {episode_mode!r}"
        )

    # Row 13: Replay idempotency always runs first.
    if state is not None and context.run_id in state.recorded_run_ids:
        return EpisodeDecision(
            action="noop",
            reason="row_13_replay",
            episode_mode=episode_mode,
            label=label,
            target_issue_number=active_issue.number if active_issue else None,
        )

    current_valid = _is_valid_current_pinned(context, current_pinned, is_drifted=is_drifted)
    rolling_valid = _is_valid_rolling_baseline(context, current_pinned, rolling_baseline)

    # Rows 5-9: Active open episode (issue open AND marker status == "open")
    if (
        active_issue is not None
        and state is not None
        and state.status == "open"
        and active_issue.state == "open"
    ):
        return _evaluate_open_episode(
            context=context,
            state=state,
            active_issue=active_issue,
            current_pinned=current_pinned,
            rolling_baseline=rolling_baseline,
            current_valid=current_valid,
            rolling_valid=rolling_valid,
            current_receipts=current_receipts,
            legs=legs,
        )

    # Rows 10-12: Manually closed episode (issue closed while marker status == "open")
    if (
        active_issue is not None
        and state is not None
        and state.status == "open"
        and active_issue.state == "closed"
    ):
        return _evaluate_manually_closed_episode(
            context=context,
            state=state,
            active_issue=active_issue,
            current_pinned=current_pinned,
            rolling_baseline=rolling_baseline,
            current_valid=current_valid,
            rolling_valid=rolling_valid,
            current_receipts=current_receipts,
            legs=legs,
        )

    # Rows 1-4: No prior episode (or latest status == "recovered")
    if not current_valid or current_pinned is None:
        return EpisodeDecision(
            action="noop",
            reason="row_1_degraded_current",
            episode_mode=episode_mode,
            label=label,
        )
    if not rolling_valid or rolling_baseline is None:
        return EpisodeDecision(
            action="noop",
            reason="row_2_missing_rolling_baseline",
            episode_mode=episode_mode,
            label=label,
        )

    slowdown_pct = compute_slowdown_percent(
        rolling_baseline.median_seconds, current_pinned.median_seconds
    )
    if not is_regression_breach(rolling_baseline.median_seconds, current_pinned.median_seconds):
        return EpisodeDecision(
            action="noop",
            reason="row_3_below_threshold",
            episode_mode=episode_mode,
            label=label,
            anchor_delta_pct=slowdown_pct,
            rolling_delta_pct=slowdown_pct,
        )

    receipt_diff = diff_receipts(prior_receipts, current_receipts)
    anchor_receipts = prior_receipts.to_anchor_dict() if prior_receipts is not None else {}
    opened_at = current_pinned.created_at or _utc_timestamp()
    entry = HistoryEntry(
        date=_date_part(opened_at),
        run_id=context.run_id,
        current_seconds=current_pinned.median_seconds,
        anchor_delta_pct=slowdown_pct,
        rolling_seconds=rolling_baseline.median_seconds,
        rolling_delta_pct=slowdown_pct,
        env_changed=receipt_diff.env_changed,
        missing_legs=legs,
    )
    next_state = EpisodeState(
        schema_version=STATE_SCHEMA_VERSION,
        episode_mode=episode_mode,
        status="open",
        anchor_seconds=rolling_baseline.median_seconds,
        anchor_manifest_sha256=rolling_baseline.manifest_sha256,
        anchor_run_id=context.baseline_run_id,
        anchor_created_at=rolling_baseline.created_at,
        anchor_receipts=anchor_receipts,
        opened_at=opened_at,
        opened_run_id=context.run_id,
        recorded_run_ids=[context.run_id],
        notified_corpus_digests=[],
        history=[entry],
    )
    return EpisodeDecision(
        action="open",
        reason="row_4_breach_open",
        episode_mode=episode_mode,
        label=label,
        next_state=next_state,
        anchor_delta_pct=slowdown_pct,
        rolling_delta_pct=slowdown_pct,
        missing_legs=legs,
        env_changes=receipt_diff.summary_lines,
        prior_receipts_unavailable=receipt_diff.prior_receipts_unavailable,
    )


# =========================================================================
# RENDERING & COMPACTION
# =========================================================================


def _format_missing_legs(missing_legs: Sequence[str]) -> str:
    parts: list[str] = []
    for leg in missing_legs:
        safe_leg = sanitize_markdown_text(leg)
        desc = _LEG_DESCRIPTIONS.get(safe_leg)
        parts.append(f"`{safe_leg}` ({desc})" if desc else f"`{safe_leg}`")
    return ", ".join(parts)


def render_issue_title(state: EpisodeState, context: AlertContext) -> str:
    """Render concise searchable issue title for an alert episode."""
    latest = state.history[-1] if state.history else None
    delta_str = f"{latest.anchor_delta_pct:+.2f}%" if latest is not None else "n/a"
    is_smoke = state.episode_mode == "smoke" or context.episode_mode == "smoke"
    prefix = "[SMOKE TEST] " if is_smoke else ""
    opened_date = sanitize_markdown_text(_date_part(state.opened_at))
    return f"{prefix}Perf regression: pinned compile {delta_str} slower ({opened_date})"


def _format_history_row(row: HistoryEntry, context: AlertContext) -> str:
    env_cell = "changed" if row.env_changed else "same"
    legs_cell = ", ".join(sanitize_markdown_text(leg) for leg in row.missing_legs) or "none"
    safe_run_id = sanitize_markdown_text(row.run_id)
    run_url = _derive_workflow_run_url(context, safe_run_id)
    run_cell = f"[{safe_run_id}]({run_url})" if run_url else f"`{safe_run_id}`"
    return (
        f"| {sanitize_markdown_text(row.date)} | {run_cell} | "
        f"{row.current_seconds:.3f} | {row.anchor_delta_pct:+.2f}% | "
        f"{row.rolling_delta_pct:+.2f}% | {env_cell} | {legs_cell} |"
    )


def _assemble_issue_body(
    state: EpisodeState,
    context: AlertContext,
    table_rows: list[str],
    *,
    env_changes: Sequence[str],
    prior_receipts_unavailable: bool,
    missing_legs: Sequence[str],
) -> str:
    is_smoke = state.episode_mode == "smoke" or context.episode_mode == "smoke"
    baseline_ref = _format_run_reference(context, state.anchor_run_id, is_smoke_baseline=is_smoke)
    run_ref = _format_run_reference(context, context.run_id)
    latest = state.history[-1] if state.history else None
    latest_delta = f"{latest.anchor_delta_pct:+.2f}%" if latest is not None else "n/a"
    latest_seconds = f"{latest.current_seconds:.3f}s" if latest is not None else "n/a"

    if env_changes:
        caveat = (
            "> **Advisory notice (runner environment changed):** The weekly pinned-corpus "
            f"benchmark ran at least `{REGRESSION_THRESHOLD_PERCENT:.1f}%` slower than its "
            "baseline, and the runner environment changed between runs. This slowdown was "
            "observed across changed environments and is not proven to be a code regression. "
            "Shared CI runner speeds can also vary with host noise, and performance alerts "
            "never block blocklist publishing."
        )
    else:
        caveat = (
            "> **Advisory notice:** The weekly pinned-corpus benchmark ran at least "
            f"`{REGRESSION_THRESHOLD_PERCENT:.1f}%` slower than its baseline. Shared GitHub "
            "Actions runners can have timing noise from host load or hardware differences, "
            "so treat this alert as an early signal rather than an automatic failure. Performance "
            "alerts never block blocklist publishing."
        )

    lines = [
        "## Advisory Pinned Performance Regression",
        "",
        caveat,
        "",
        f"- **Status:** `{sanitize_markdown_text(state.status)}`",
        f"- **Mode:** `{sanitize_markdown_text(state.episode_mode)}`",
        f"- **Latest Anchor Delta:** `{latest_delta}` (`{latest_seconds}` vs pre-episode anchor "
        f"`{state.anchor_seconds:.3f}s`)",
        f"- **Baseline Reference:** {baseline_ref}",
        f"- **Latest Run:** {run_ref}",
        f"- **Corpus Manifest:** `{sanitize_markdown_text(state.anchor_manifest_sha256[:12])}`",
    ]
    if context.baseline_run_id and context.baseline_run_id != state.anchor_run_id and not is_smoke:
        rolling_ref = _format_run_reference(context, context.baseline_run_id)
        lines.append(f"- **Rolling Prior Baseline:** {rolling_ref}")

    if state.notified_corpus_digests:
        digests_str = ", ".join(
            f"`{sanitize_markdown_text(d[:12])}`" for d in state.notified_corpus_digests
        )
        lines.append(f"- **Corpus Re-Pin Holds:** {digests_str} (held open without false recovery)")

    if env_changes:
        lines.extend(
            [
                "",
                "### Environment Changes Observed",
                "",
                (
                    "> **Observed across changed environments:** The slowdown was observed after "
                    "the runner environment changed and is not proven to be a code regression."
                ),
                "",
            ]
        )
        for change in env_changes:
            lines.append(f"- {sanitize_markdown_text(change)}")
    elif prior_receipts_unavailable:
        lines.append(
            "- **Environment Note:** prior receipts unavailable "
            "(first run after Phase 24 upgrade); CPU/runner comparison omitted."
        )

    if missing_legs:
        lines.extend(
            [
                "",
                "### Missing Supporting Evidence",
                "",
                (
                    "The pinned-corpus timing result is valid and this alert remains active, even "
                    "though these supporting checks did not complete: "
                    + _format_missing_legs(missing_legs)
                ),
            ]
        )

    lines.extend(
        [
            "",
            "### Episode History",
            "",
            "| Date | Run | Current (s) | Anchor Delta | Rolling Delta | Env | Missing Legs |",
            "| --- | --- | ---: | ---: | ---: | --- | --- |",
            *table_rows,
            "",
            format_state_marker(state),
            "",
        ]
    )
    return "\n".join(lines)


def _compact_table_rows(
    rows: Sequence[HistoryEntry], context: AlertContext, keep_tail: int
) -> list[str]:
    if len(rows) <= keep_tail + 1:
        return [_format_history_row(row, context) for row in rows]
    omitted = len(rows) - 1 - keep_tail
    compacted_note = f"| ... | *(compacted {omitted} earlier rows)* | - | - | - | - | - |"
    tail_rows = (
        [_format_history_row(row, context) for row in rows[-keep_tail:]] if keep_tail > 0 else []
    )
    return [_format_history_row(rows[0], context), compacted_note, *tail_rows]


def _normalize_render_state(state: EpisodeState, context: AlertContext) -> EpisodeState:
    effective_opened_run_id = (
        state.opened_run_id
        or next((entry.run_id for entry in state.history if entry.run_id), "")
        or context.run_id
    )
    effective_anchor_run_id = (
        state.anchor_run_id or context.baseline_run_id or effective_opened_run_id
    )
    clean_recorded_ids = [rid for rid in state.recorded_run_ids if rid]
    has_empty_entry_run = any(not entry.run_id for entry in state.history)
    if (
        effective_opened_run_id == state.opened_run_id
        and effective_anchor_run_id == state.anchor_run_id
        and len(clean_recorded_ids) == len(state.recorded_run_ids)
        and not has_empty_entry_run
    ):
        return state
    normalized_history = (
        [
            entry
            if entry.run_id
            else HistoryEntry(
                date=entry.date,
                run_id=effective_opened_run_id,
                current_seconds=entry.current_seconds,
                anchor_delta_pct=entry.anchor_delta_pct,
                rolling_seconds=entry.rolling_seconds,
                rolling_delta_pct=entry.rolling_delta_pct,
                env_changed=entry.env_changed,
                missing_legs=entry.missing_legs,
            )
            for entry in state.history
        ]
        if has_empty_entry_run
        else state.history
    )
    return _copy_state(
        state,
        anchor_run_id=effective_anchor_run_id,
        opened_run_id=effective_opened_run_id,
        recorded_run_ids=clean_recorded_ids,
        history=normalized_history,
    )


def _compact_worst_case_body(
    state: EpisodeState,
    context: AlertContext,
    *,
    env_changes: Sequence[str],
    prior_receipts_unavailable: bool,
    missing_legs: Sequence[str],
) -> str:
    preserved_history = (
        [state.history[0], state.history[-1]] if len(state.history) >= 2 else list(state.history)
    )
    compact_state = _copy_state(state, history=preserved_history)
    cur_rows = _compact_table_rows(compact_state.history, context, 1)
    cur_changes: Sequence[str] = env_changes
    cur_legs: Sequence[str] = missing_legs

    def _render_candidate() -> str:
        return _assemble_issue_body(
            compact_state,
            context,
            cur_rows,
            env_changes=cur_changes,
            prior_receipts_unavailable=prior_receipts_unavailable,
            missing_legs=cur_legs,
        )

    body = _render_candidate()
    if len(body) <= MAX_ISSUE_BODY_CHARS:
        return body

    # Step 1: Shed oversized env_changes prose progressively.
    capped_changes = list(env_changes[:10])
    short_changes = [f"{item[:240]}..." if len(item) > 240 else item for item in capped_changes]
    for next_changes in (capped_changes, short_changes, ()):
        cur_changes = next_changes
        body = _render_candidate()
        if len(body) <= MAX_ISSUE_BODY_CHARS:
            return body

    # Step 2: Shed oversized missing_legs prose and per-row missing_legs if needed.
    for next_legs in (list(missing_legs[:10]), ()):
        cur_legs = next_legs
        body = _render_candidate()
        if len(body) <= MAX_ISSUE_BODY_CHARS:
            return body

    if any(entry.missing_legs for entry in compact_state.history):
        stripped_history = [
            HistoryEntry(
                date=entry.date,
                run_id=entry.run_id,
                current_seconds=entry.current_seconds,
                anchor_delta_pct=entry.anchor_delta_pct,
                rolling_seconds=entry.rolling_seconds,
                rolling_delta_pct=entry.rolling_delta_pct,
                env_changed=entry.env_changed,
                missing_legs=(),
            )
            for entry in compact_state.history
        ]
        compact_state = _copy_state(compact_state, history=stripped_history)
        cur_rows = _compact_table_rows(compact_state.history, context, 1)
        body = _render_candidate()
        if len(body) <= MAX_ISSUE_BODY_CHARS:
            return body

    # Step 3: Shed older notified_corpus_digests.
    for next_digests in (compact_state.notified_corpus_digests[-20:], []):
        compact_state = _copy_state(compact_state, notified_corpus_digests=next_digests)
        body = _render_candidate()
        if len(body) <= MAX_ISSUE_BODY_CHARS:
            return body

    # Step 4: Shed older recorded_run_ids while preserving opened_run_id (non-empty) & latest.
    recent_tail = [
        rid for rid in compact_state.recorded_run_ids if rid and rid != compact_state.opened_run_id
    ][-19:]
    capped_ids = (
        [compact_state.opened_run_id, *recent_tail] if compact_state.opened_run_id else recent_tail
    )
    minimal_ids = [compact_state.opened_run_id] if compact_state.opened_run_id else []
    for next_ids in (capped_ids, minimal_ids, []):
        compact_state = _copy_state(compact_state, recorded_run_ids=next_ids)
        body = _render_candidate()
        if len(body) <= MAX_ISSUE_BODY_CHARS:
            return body

    # Step 5: Shed anchor_receipts before falling back to marker-only output.
    compact_state = _copy_state(compact_state, anchor_receipts={})
    body = _render_candidate()
    if len(body) <= MAX_ISSUE_BODY_CHARS:
        return body
    return format_state_marker(compact_state)


def render_issue_body(
    state: EpisodeState,
    context: AlertContext,
    *,
    env_changes: Sequence[str] = (),
    prior_receipts_unavailable: bool = False,
    missing_legs: Sequence[str] = (),
) -> str:
    """Render issue body with history table and embedded state marker under MAX_ISSUE_BODY_CHARS."""
    working_state = _normalize_render_state(state, context)
    all_rows = [_format_history_row(row, context) for row in working_state.history]
    body = _assemble_issue_body(
        working_state,
        context,
        all_rows,
        env_changes=env_changes,
        prior_receipts_unavailable=prior_receipts_unavailable,
        missing_legs=missing_legs,
    )
    if len(body) <= MAX_ISSUE_BODY_CHARS:
        return body

    # Stage 1: Compact middle Markdown table rows while keeping full JSON state intact.
    for keep_tail in (20, 10, 5, 2, 1):
        compact_rows = _compact_table_rows(working_state.history, context, keep_tail)
        candidate = _assemble_issue_body(
            working_state,
            context,
            compact_rows,
            env_changes=env_changes,
            prior_receipts_unavailable=prior_receipts_unavailable,
            missing_legs=missing_legs,
        )
        if len(candidate) <= MAX_ISSUE_BODY_CHARS:
            return candidate

    # Stage 2: Compact middle entries inside embedded JSON history if marker itself exceeds budget.
    minimal_rows = _compact_table_rows(working_state.history, context, 1)
    if len(working_state.history) > 2:
        low, high = 1, len(working_state.history) - 1
        best_body: str | None = None
        while low <= high:
            mid = (low + high) // 2
            trimmed_history = [working_state.history[0], *working_state.history[-mid:]]
            trimmed_state = _copy_state(working_state, history=trimmed_history)
            candidate = _assemble_issue_body(
                trimmed_state,
                context,
                minimal_rows,
                env_changes=env_changes,
                prior_receipts_unavailable=prior_receipts_unavailable,
                missing_legs=missing_legs,
            )
            if len(candidate) <= MAX_ISSUE_BODY_CHARS:
                best_body = candidate
                low = mid + 1
            else:
                high = mid - 1
        if best_body is not None:
            return best_body

    return _compact_worst_case_body(
        working_state,
        context,
        env_changes=env_changes,
        prior_receipts_unavailable=prior_receipts_unavailable,
        missing_legs=missing_legs,
    )


def render_continuation_comment(
    state: EpisodeState,
    context: AlertContext,
    *,
    env_changes: Sequence[str] = (),
    prior_receipts_unavailable: bool = False,
    missing_legs: Sequence[str] = (),
) -> str:
    """Render dated continuation comment for Row 8 updates (D-24-10)."""
    latest = state.history[-1]
    is_smoke = state.episode_mode == "smoke" or context.episode_mode == "smoke"
    anchor_ref = _format_run_reference(context, state.anchor_run_id, is_smoke_baseline=is_smoke)
    run_ref = _format_run_reference(context, context.run_id)
    marker = (
        f"{COMMENT_MARKER_PREFIX}run-"
        f"{sanitize_markdown_text(context.run_id)}{COMMENT_MARKER_SUFFIX}"
    )
    lines = [
        marker,
        f"### Weekly Episode Update ({sanitize_markdown_text(latest.date)})",
        "",
        f"- **Current Median:** `{latest.current_seconds:.3f}s`",
        (
            f"- **Anchor Delta:** `{latest.anchor_delta_pct:+.2f}%` "
            f"(vs pre-episode anchor `{state.anchor_seconds:.3f}s` from {anchor_ref})"
        ),
        (
            f"- **Rolling Delta:** `{latest.rolling_delta_pct:+.2f}%` "
            f"(vs prior `{latest.rolling_seconds:.3f}s`)"
        ),
        f"- **Workflow Run:** {run_ref}",
    ]
    if env_changes:
        lines.append(
            "- **Environment Changes Observed** (slowdown observed across changed environments, "
            "not proven to be a code regression): "
            + "; ".join(sanitize_markdown_text(item) for item in env_changes)
        )
    elif prior_receipts_unavailable:
        lines.append("- **Environment Note:** prior receipts unavailable for anchor comparison.")
    if missing_legs:
        lines.append(
            "- **Missing Supporting Evidence:** Supporting checks did not complete ("
            + _format_missing_legs(missing_legs)
            + "), while the pinned timing result remained valid."
        )
    lines.append("")
    return "\n".join(lines)


def render_corpus_changed_comment(
    state: EpisodeState,
    context: AlertContext,
    new_manifest_sha256: str,
) -> str:
    """Render one-time idempotent hold notice when corpus re-pins mid-episode (D-24-08)."""
    safe_new12 = sanitize_markdown_text(new_manifest_sha256[:12])
    safe_old12 = sanitize_markdown_text(state.anchor_manifest_sha256[:12])
    marker = f"{COMMENT_MARKER_PREFIX}corpus-changed-{safe_new12}{COMMENT_MARKER_SUFFIX}"
    run_ref = _format_run_reference(context, context.run_id)
    return "\n".join(
        [
            marker,
            "### Pinned Corpus Changed Mid-Episode (Holding Open)",
            "",
            (
                f"The pinned corpus re-pinned from `{safe_old12}` to `{safe_new12}` during "
                f"{run_ref}. Because timings from a different pinned corpus cannot be compared "
                "directly against the pre-episode baseline anchor, this issue stays open without "
                "claiming recovery or adding misleading delta rows."
            ),
            "",
        ]
    )


def render_recovery_comment(
    state: EpisodeState,
    context: AlertContext,
    *,
    env_changes: Sequence[str] = (),
    missing_legs: Sequence[str] = (),
) -> str:
    """Render recovery summary comment for episode closure (D-24-11)."""
    latest = state.history[-1] if state.history else None
    close_val = f"{latest.current_seconds:.3f}s" if latest is not None else "n/a"
    close_delta = f"{latest.anchor_delta_pct:+.2f}%" if latest is not None else "n/a"
    rolling_delta = f"{latest.rolling_delta_pct:+.2f}%" if latest is not None else "n/a"
    is_smoke = state.episode_mode == "smoke" or context.episode_mode == "smoke"
    anchor_ref = _format_run_reference(context, state.anchor_run_id, is_smoke_baseline=is_smoke)
    opened_date = sanitize_markdown_text(_date_part(state.opened_at))
    opened_ref = _format_run_reference(context, state.opened_run_id)
    recovered_ref = _format_run_reference(context, context.run_id)
    marker = (
        f"{COMMENT_MARKER_PREFIX}recovery-"
        f"{sanitize_markdown_text(context.run_id)}{COMMENT_MARKER_SUFFIX}"
    )
    lines = [
        marker,
        "### Performance Recovered",
        "",
        (
            f"Pinned timing returned to `{close_val}` (`{close_delta}` vs pre-episode anchor "
            f"`{state.anchor_seconds:.3f}s` from {anchor_ref})."
        ),
        (
            f"- **Opened:** `{opened_date}` (`{sanitize_markdown_text(state.opened_at)}`, "
            f"{opened_ref})"
        ),
        f"- **Immutable Anchor:** `{state.anchor_seconds:.3f}s` ({anchor_ref})",
        f"- **Close Value & Delta:** `{close_val}` (`{close_delta}` vs anchor; "
        f"`{rolling_delta}` vs prior week)",
        f"- **Recovered Run:** {recovered_ref}",
    ]
    if env_changes:
        lines.append(
            "- **Environment Changes Observed** (observed across changed environments, "
            "not proven to be a code regression): "
            + "; ".join(sanitize_markdown_text(item) for item in env_changes)
        )
    if missing_legs:
        lines.append("- **Missing Supporting Evidence:** " + _format_missing_legs(missing_legs))
    lines.append("")
    return "\n".join(lines)


def _comment_marker_exists(client: GitHubIssueClient, issue_number: int, marker: str) -> bool:
    for comment in client.list_comments(issue_number):
        body = comment.get("body")
        if isinstance(body, str) and marker in body:
            return True
    return False


def _format_safe_error(exc: BaseException) -> str:
    if isinstance(exc, subprocess.CalledProcessError):
        stderr = (exc.stderr or "").strip() if isinstance(exc.stderr, str) else ""
        detail = f": {stderr}" if stderr else ""
        return _redact_secrets(f"gh command failed ({exc.returncode}){detail}")
    return _redact_secrets(str(exc))


def _append_step_warning(message: str, summary_path: str | None) -> None:
    if not summary_path:
        return
    try:
        with open(summary_path, "a", encoding="utf-8", newline="\n") as handle:
            handle.write(f"> **Warning:** {_redact_secrets(message)}\n")
    except OSError:
        pass


def _append_step_summary(decision: EpisodeDecision, summary_path: str | None) -> None:
    if not summary_path:
        return
    try:
        with open(summary_path, "a", encoding="utf-8", newline="\n") as handle:
            if decision.action == "noop":
                handle.write(
                    f"Perf alert sync: NO-OP (`noop`) reason=`{decision.reason}` "
                    f"mode=`{decision.episode_mode}`\n"
                )
            else:
                handle.write(
                    f"Perf alert sync: action=`{decision.action}` reason=`{decision.reason}` "
                    f"mode=`{decision.episode_mode}`\n"
                )
    except OSError:
        pass


def _dispatch_issue_sync(
    issue_client: GitHubIssueClient,
    bundle: HandoffBundle,
    decision: EpisodeDecision,
) -> None:
    if decision.action == "open" and decision.next_state is not None:
        color = "fbca04" if bundle.context.episode_mode == "smoke" else "d93f0b"
        desc = (
            "Isolated smoke test issue for perf-evidence regression alerts"
            if bundle.context.episode_mode == "smoke"
            else "Advisory weekly pinned-corpus performance regression alert"
        )
        issue_client.ensure_label(decision.label, color=color, description=desc)
        issue_client.create_issue(
            title=render_issue_title(decision.next_state, bundle.context),
            body=render_issue_body(
                decision.next_state,
                bundle.context,
                env_changes=decision.env_changes,
                prior_receipts_unavailable=decision.prior_receipts_unavailable,
                missing_legs=decision.missing_legs,
            ),
            labels=[decision.label],
        )
    elif (
        decision.action == "update"
        and decision.next_state is not None
        and decision.target_issue_number is not None
    ):
        marker = (
            f"{COMMENT_MARKER_PREFIX}run-"
            f"{_sanitize_cell(bundle.context.run_id)}{COMMENT_MARKER_SUFFIX}"
        )
        if not _comment_marker_exists(issue_client, decision.target_issue_number, marker):
            issue_client.create_comment(
                decision.target_issue_number,
                body=render_continuation_comment(
                    decision.next_state,
                    bundle.context,
                    env_changes=decision.env_changes,
                    prior_receipts_unavailable=decision.prior_receipts_unavailable,
                    missing_legs=decision.missing_legs,
                ),
            )
        issue_client.update_issue(
            decision.target_issue_number,
            body=render_issue_body(
                decision.next_state,
                bundle.context,
                env_changes=decision.env_changes,
                prior_receipts_unavailable=decision.prior_receipts_unavailable,
                missing_legs=decision.missing_legs,
            ),
        )
    elif (
        decision.action == "hold_open"
        and decision.next_state is not None
        and decision.target_issue_number is not None
        and bundle.current_pinned is not None
    ):
        new_digest = bundle.current_pinned.manifest_sha256
        marker = f"{COMMENT_MARKER_PREFIX}corpus-changed-{new_digest[:12]}{COMMENT_MARKER_SUFFIX}"
        if not _comment_marker_exists(issue_client, decision.target_issue_number, marker):
            issue_client.create_comment(
                decision.target_issue_number,
                body=render_corpus_changed_comment(decision.next_state, bundle.context, new_digest),
            )
        issue_client.update_issue(
            decision.target_issue_number,
            body=render_issue_body(
                decision.next_state,
                bundle.context,
                env_changes=decision.env_changes,
                prior_receipts_unavailable=decision.prior_receipts_unavailable,
                missing_legs=decision.missing_legs,
            ),
        )
    elif (
        decision.action == "close"
        and decision.next_state is not None
        and decision.target_issue_number is not None
    ):
        comment_body = render_recovery_comment(
            decision.next_state,
            bundle.context,
            env_changes=decision.env_changes,
            missing_legs=bundle.missing_legs,
        )
        marker = (
            f"{COMMENT_MARKER_PREFIX}recovery-"
            f"{_sanitize_cell(bundle.context.run_id)}{COMMENT_MARKER_SUFFIX}"
        )
        if not _comment_marker_exists(issue_client, decision.target_issue_number, marker):
            issue_client.create_comment(decision.target_issue_number, body=comment_body)
        issue_client.update_issue(
            decision.target_issue_number,
            body=render_issue_body(
                decision.next_state,
                bundle.context,
                env_changes=decision.env_changes,
                prior_receipts_unavailable=decision.prior_receipts_unavailable,
                missing_legs=decision.missing_legs,
            ),
            state="closed",
            state_reason="completed",
        )
    elif (
        decision.action == "retire_manually_closed"
        and decision.next_state is not None
        and decision.target_issue_number is not None
    ):
        issue_client.update_issue(
            decision.target_issue_number,
            body=render_issue_body(
                decision.next_state,
                bundle.context,
                env_changes=decision.env_changes,
                prior_receipts_unavailable=decision.prior_receipts_unavailable,
                missing_legs=decision.missing_legs,
            ),
        )


def sync_handoff(
    handoff_dir: Path,
    *,
    client: GitHubIssueClient | None = None,
    summary_path: str | None = None,
) -> EpisodeDecision:
    """Evaluate staged handoff evidence and synchronize GitHub alert issue state."""
    resolved_summary = (
        summary_path if summary_path is not None else os.environ.get("GITHUB_STEP_SUMMARY")
    )

    if not handoff_dir.exists() and not handoff_dir.is_symlink():
        decision = EpisodeDecision(
            action="noop",
            episode_mode="production",
            label=PRODUCTION_ALERT_LABEL,
            reason="missing_handoff",
        )
        _append_step_summary(decision, resolved_summary)
        return decision

    try:
        if handoff_dir.is_dir():
            context_raw = handoff_dir / HANDOFF_LAYOUT["alert_context"]
            if not context_raw.exists() and not context_raw.is_symlink():
                decision = EpisodeDecision(
                    action="noop",
                    episode_mode="production",
                    label=PRODUCTION_ALERT_LABEL,
                    reason="missing_handoff",
                )
                _append_step_summary(decision, resolved_summary)
                return decision

        bundle = load_handoff_bundle(handoff_dir)
        issue_client = (
            client if client is not None else GhCliIssueClient(repo=bundle.context.repo or None)
        )

        issues = issue_client.list_issues(bundle.context.alert_label)
        active_issue = select_active_episode_issue(
            issues,
            episode_mode=bundle.context.episode_mode,
            required_label=bundle.context.alert_label,
        )
        decision = evaluate_episode(
            context=bundle.context,
            current_pinned=bundle.current_pinned,
            rolling_baseline=bundle.rolling_baseline,
            is_drifted=bundle.is_drifted,
            active_issue=active_issue,
            current_receipts=bundle.current_receipts,
            prior_receipts=bundle.prior_receipts,
            missing_legs=bundle.missing_legs,
        )
        _dispatch_issue_sync(issue_client, bundle, decision)
    except (PerfAlertError, subprocess.CalledProcessError, OSError) as exc:
        safe_msg = _format_safe_error(exc)
        _append_step_warning(f"Perf alert sync warning: {safe_msg}", resolved_summary)
        raise PerfAlertError(safe_msg) from exc

    _append_step_summary(decision, resolved_summary)
    return decision


def write_alert_context(
    output_path: Path,
    env: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Assemble and atomically write ``alert-context.json`` from workflow environment variables."""
    source_env = os.environ if env is None else env
    run_id = _validate_run_id(
        source_env.get("RUN_ID", ""),
        error_message="RUN_ID environment variable is missing or invalid",
    )

    run_attempt = str(source_env.get("RUN_ATTEMPT", "1")).strip() or "1"
    raw_server_url = str(source_env.get("SERVER_URL", "https://github.com"))
    if _CONTROL_CHARS_RE.search(raw_server_url):
        raise PerfAlertError("SERVER_URL environment variable contains control characters")
    server_url = (raw_server_url.strip() or "https://github.com").rstrip("/")
    sanitized_server_url = _sanitize_http_url(server_url)
    if not sanitized_server_url or sanitized_server_url != server_url:
        raise PerfAlertError(f"Invalid SERVER_URL: {server_url!r}")
    repo = str(source_env.get("REPO", "")).strip()
    if repo and not _is_valid_repo_slug(repo):
        raise PerfAlertError(f"Invalid REPO slug: {repo!r}")
    git_sha = str(source_env.get("GIT_SHA", "")).strip()
    event_name = str(source_env.get("EVENT_NAME", "schedule")).strip() or "schedule"
    raw_smoke_mode = str(source_env.get("SMOKE_MODE", "")).strip() or "none"

    if event_name == "workflow_dispatch":
        if raw_smoke_mode not in _SMOKE_MODES:
            raise PerfAlertError(f"Unsupported SMOKE_MODE: {raw_smoke_mode!r}")
        effective_smoke = raw_smoke_mode
    else:
        if raw_smoke_mode != "none":
            print(
                f"WARNING: ignoring SMOKE_MODE={raw_smoke_mode!r} on event {event_name!r}; "
                "smoke mode is only allowed on workflow_dispatch.",
                file=sys.stderr,
            )
        effective_smoke = "none"

    run_url = f"{server_url}/{repo}/actions/runs/{run_id}" if (server_url and repo) else ""

    if effective_smoke != "none":
        raw_smoke_drifted = str(source_env.get("SMOKE_PINNED_DRIFTED", "true")).strip()
        pinned_drifted = (raw_smoke_drifted or "true").lower()
        baseline_run_id = str(source_env.get("SMOKE_BASELINE_RUN_ID", "")).strip()
        baseline_run_url = ""
        pinned_snapshot_digest = SMOKE_SYNTHETIC_DIGEST
        pinned_snapshot_run_id = "smoke-synthetic"
    else:
        pinned_drifted = (str(source_env.get("PINNED_DRIFTED", "true")).strip() or "true").lower()
        baseline_run_id = str(source_env.get("BASELINE_RUN_ID", "")).strip()
        baseline_run_url = (
            f"{server_url}/{repo}/actions/runs/{baseline_run_id}"
            if (server_url and repo and baseline_run_id.isdigit())
            else ""
        )
        pinned_snapshot_digest = str(source_env.get("PERF_SNAPSHOT_DIGEST", "")).strip()
        pinned_snapshot_run_id = str(source_env.get("PERF_SNAPSHOT_RUN_ID", "")).strip()

    step_outcomes = {
        outcome_key: str(source_env.get(env_key, "")).strip()
        for env_key, outcome_key in _OUTCOME_ENV_MAP
    }

    payload: dict[str, object] = {
        "schema_version": 1,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "run_url": run_url,
        "repo": repo,
        "git_sha": git_sha,
        "event_name": event_name,
        "smoke_mode": effective_smoke,
        "pinned_snapshot_digest": pinned_snapshot_digest,
        "pinned_snapshot_run_id": pinned_snapshot_run_id,
        "pinned_drifted": pinned_drifted,
        "baseline_run_id": baseline_run_id,
        "baseline_run_url": baseline_run_url,
        "step_outcomes": step_outcomes,
    }
    _atomic_write_json(output_path, payload)
    return payload


def _clear_smoke_fixtures(output_dir: Path) -> None:
    for rel_dir in ("runs", "previous"):
        target = output_dir / rel_dir
        if target.is_symlink() or target.is_file():
            target.unlink()
        elif target.is_dir():
            shutil.rmtree(target)
    for rel_file in ("receipts.json", "source-health.json", "pinned-drifted"):
        target = output_dir / rel_file
        if target.is_symlink() or target.is_file():
            target.unlink()
        elif target.is_dir():
            shutil.rmtree(target)


def _smoke_timing_doc(
    *,
    median_seconds: float,
    manifest_sha256: str,
    created_at: str,
    git_revision: str = "smoke-synthetic",
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "report_type": "corpus_benchmark",
        "mode": "timing",
        "created_at": created_at,
        "corpus": {"manifest_sha256": manifest_sha256},
        "summary": {"median_seconds": median_seconds},
        "identity": {
            "python_version": "3.14.0",
            "platform": "Linux",
            "git_revision": git_revision,
        },
    }


def _smoke_memory_doc(
    *,
    peak_bytes: int,
    manifest_sha256: str,
    created_at: str,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "report_type": "corpus_benchmark",
        "mode": "memory",
        "created_at": created_at,
        "corpus": {"manifest_sha256": manifest_sha256},
        "tracemalloc_peak_bytes": peak_bytes,
        "tracemalloc_current_bytes": peak_bytes // 2,
        "identity": {
            "python_version": "3.14.0",
            "platform": "Linux",
            "git_revision": "smoke-synthetic",
        },
    }


def _write_github_output(outputs: Mapping[str, str], github_output: Path | None) -> None:
    target = github_output
    if target is None:
        env_path = os.environ.get("GITHUB_OUTPUT", "").strip()
        if not env_path:
            return
        target = Path(env_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"{key}={value}\n" for key, value in outputs.items()]
    needs_newline = False
    if target.exists():
        existing = target.read_text(encoding="utf-8")
        needs_newline = bool(existing) and not existing.endswith("\n")
    with open(target, "a", encoding="utf-8", newline="\n") as handle:
        if needs_newline:
            handle.write("\n")
        handle.writelines(lines)


def prepare_smoke_fixtures(
    smoke_mode: str,
    output_dir: Path,
    *,
    github_output: Path | None = None,
) -> dict[str, str]:
    """Generate isolated synthetic smoke-test fixtures inside ``output_dir``."""
    if smoke_mode not in _SMOKE_ACTIVE_MODES:
        raise PerfAlertError(f"Unsupported smoke_mode for prepare-smoke: {smoke_mode!r}")

    output_dir.mkdir(parents=True, exist_ok=True)
    _clear_smoke_fixtures(output_dir)

    current_receipts = {
        "schema_version": 1,
        "cpu_model": "AMD EPYC 7763 64-Core Processor",
        "runner_image": "ubuntu-24.04",
        "runner_image_version": "20260901.1",
        "python_version": "Python 3.14.0",
        "git_revision": "smoke-synthetic",
        "run_id": f"smoke-{smoke_mode}",
        "pinned_manifest_sha256": SMOKE_SYNTHETIC_DIGEST,
        "live_manifest_sha256": _SMOKE_LIVE_DIGEST,
    }
    _atomic_write_json(output_dir / HANDOFF_LAYOUT["receipts"], current_receipts)

    if smoke_mode == "degraded":
        drifted_path = output_dir / HANDOFF_LAYOUT["pinned_drifted"]
        drifted_path.write_text("smoke degraded fixture\n", encoding="utf-8", newline="\n")
        outputs = {"drifted": "true", "baseline-run-id": ""}
    else:
        cur_seconds, prev_seconds = _SMOKE_BASELINE_TIMES[smoke_mode]
        baseline_id = f"smoke-baseline-{smoke_mode}"
        _atomic_write_json(
            output_dir / HANDOFF_LAYOUT["pinned_timing"],
            _smoke_timing_doc(
                median_seconds=cur_seconds,
                manifest_sha256=SMOKE_SYNTHETIC_DIGEST,
                created_at="2026-09-20T03:30:00Z",
            ),
        )
        _atomic_write_json(
            output_dir / HANDOFF_LAYOUT["previous_pinned_timing"],
            _smoke_timing_doc(
                median_seconds=prev_seconds,
                manifest_sha256=SMOKE_SYNTHETIC_DIGEST,
                created_at="2026-09-13T03:30:00Z",
            ),
        )
        prev_receipts = dict(current_receipts)
        prev_receipts["run_id"] = baseline_id
        _atomic_write_json(output_dir / HANDOFF_LAYOUT["previous_receipts"], prev_receipts)

        # Populate valid supporting-leg files so clean smoke runs have zero D-24-05 false positives.
        _atomic_write_json(
            output_dir / HANDOFF_LAYOUT["pinned_memory"],
            _smoke_memory_doc(
                peak_bytes=2048,
                manifest_sha256=SMOKE_SYNTHETIC_DIGEST,
                created_at="2026-09-20T03:30:00Z",
            ),
        )
        _atomic_write_json(
            output_dir / HANDOFF_LAYOUT["live_timing"],
            _smoke_timing_doc(
                median_seconds=185.0,
                manifest_sha256=_SMOKE_LIVE_DIGEST,
                created_at="2026-09-20T03:30:00Z",
            ),
        )
        _atomic_write_json(
            output_dir / HANDOFF_LAYOUT["live_memory"],
            _smoke_memory_doc(
                peak_bytes=4096,
                manifest_sha256=_SMOKE_LIVE_DIGEST,
                created_at="2026-09-20T03:30:00Z",
            ),
        )
        _atomic_write_json(
            output_dir / HANDOFF_LAYOUT["source_health"],
            {
                "schema_version": 1,
                "version": 1,
                "generated_at": "2026-09-20T03:30:00Z",
                "source_count": 1,
                "totals_by_status": {"ok": 1},
                "sources": [],
            },
        )
        _atomic_write_json(
            output_dir / HANDOFF_LAYOUT["previous_live_timing"],
            _smoke_timing_doc(
                median_seconds=180.0,
                manifest_sha256=_SMOKE_LIVE_DIGEST,
                created_at="2026-09-13T03:30:00Z",
            ),
        )
        outputs = {"drifted": "false", "baseline-run-id": baseline_id}

    _write_github_output(outputs, github_output)
    return outputs


# =========================================================================
# CLI INTERFACE
# =========================================================================


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m scripts.perf_alert",
        description="Advisory pinned-corpus performance regression alert evaluator.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    sync_parser = subparsers.add_parser(
        "sync",
        help="Evaluate staged handoff evidence and sync GitHub alert issues.",
    )
    sync_parser.add_argument(
        "--handoff-dir",
        type=Path,
        required=True,
        help="Path to staged perf-alert handoff directory.",
    )

    write_ctx_parser = subparsers.add_parser(
        "write-context",
        help="Write normalized alert-context.json from workflow environment variables.",
    )
    write_ctx_parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Output path for alert-context.json.",
    )

    smoke_parser = subparsers.add_parser(
        "prepare-smoke",
        help="Prepare synthetic handoff fixtures for workflow_dispatch smoke runs.",
    )
    smoke_parser.add_argument(
        "--smoke-mode",
        choices=_SMOKE_ACTIVE_MODES,
        required=True,
        help="Smoke scenario to synthesize.",
    )
    smoke_parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Target handoff directory for synthetic fixtures.",
    )
    smoke_parser.add_argument(
        "--github-output",
        type=Path,
        default=None,
        help="Optional output file path (defaults to GITHUB_OUTPUT env var).",
    )
    return parser


def main(argv: list[str] | None = None, *, client: GitHubIssueClient | None = None) -> int:
    """CLI entry point returning 0 on success or 1 on operational failure."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "sync":
            sync_handoff(args.handoff_dir, client=client)
            return 0
        if args.command == "write-context":
            write_alert_context(args.output)
            return 0
        if args.command == "prepare-smoke":
            prepare_smoke_fixtures(
                args.smoke_mode,
                args.output_dir,
                github_output=args.github_output,
            )
            return 0
    except Exception as exc:
        print(f"ERROR: {_redact_secrets(str(exc))}", file=sys.stderr)
        return 1
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
