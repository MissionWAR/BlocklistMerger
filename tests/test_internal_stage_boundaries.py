"""Static guards for Phase 9 internal diagnostics boundaries."""

import io
import subprocess
import tokenize
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

FORBIDDEN_PUBLIC_SCOPE_TOKENS = (
    "--profile",
    "--source-profile",
    "--transform",
    "--per-source",
    "--output-target",
    "--output-profile",
    "--telemetry",
    "opentelemetry",
    "--benchmark",
    "--profile-output",
    "stage gate",
)

ALLOWED_DIAGNOSTIC_TOKENS = (
    "--json-stats",
    "--coverage-proof",
    "stage_summaries",
    "semantics",
    "runtime_profile",
)


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def _git_ls_files() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    return [line.replace("\\", "/") for line in result.stdout.splitlines() if line]


def _non_comment_text(path: str) -> str:
    lines = []
    for line in _read(path).splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        lines.append(line)
    return "\n".join(lines).lower()


def _python_code_without_strings(path: str) -> str:
    tokens = tokenize.generate_tokens(io.StringIO(_read(path)).readline)
    return " ".join(
        token.string.lower()
        for token in tokens
        if token.type not in {tokenize.COMMENT, tokenize.STRING}
    )


def _python_string_literals(path: str) -> str:
    tokens = tokenize.generate_tokens(io.StringIO(_read(path)).readline)
    return " ".join(
        token.string.lower()
        for token in tokens
        if token.type == tokenize.STRING
    )


def test_pipeline_cli_does_not_add_deferred_platform_controls() -> None:
    text = _non_comment_text("scripts/pipeline.py")

    assert "--json-stats" in text
    assert "--coverage-proof" in text
    for token in FORBIDDEN_PUBLIC_SCOPE_TOKENS:
        assert token not in text


def test_default_stage_diagnostics_stay_in_pipeline_stats_only() -> None:
    pipeline_text = _non_comment_text("scripts/pipeline.py")
    diagnostics_code = _python_code_without_strings("scripts/stage_diagnostics.py")

    for token in ALLOWED_DIAGNOSTIC_TOKENS:
        if token in {"--json-stats", "--coverage-proof"}:
            assert token in pipeline_text

    assert '"stage_summaries"' in pipeline_text
    assert "sample_buckets" not in diagnostics_code
    assert "fingerprint" not in diagnostics_code
    assert "raw_rule" not in diagnostics_code
    assert "records" not in diagnostics_code


def test_scheduled_workflow_does_not_promote_stage_or_proof_gates() -> None:
    text = _non_comment_text(".github/workflows/update.yml")

    forbidden_workflow_tokens = (
        "stage_summaries",
        "--coverage-proof",
        "coverage-proof",
        "--profile",
        "--source-profile",
        "--transform",
        "--output-target",
        "--telemetry",
        "opentelemetry",
        "--benchmark",
        "stage gate",
    )
    for token in forbidden_workflow_tokens:
        assert token not in text


def test_source_tree_has_no_non_python_rewrite_artifacts() -> None:
    """RUN-04 is a language gate only, not a tracked rewrite prototype."""
    tracked_files = _git_ls_files()

    forbidden_project_files = {
        "go.mod",
        "cargo.toml",
        "package.json",
        "tsconfig.json",
    }
    forbidden_source_suffixes = (".go", ".rs", ".ts", ".tsx")
    illegal_files: list[str] = []

    for tracked_file in tracked_files:
        parts = Path(tracked_file).parts
        lower_parts = tuple(part.lower() for part in parts)
        lower_path = tracked_file.lower()
        name = lower_parts[-1]

        if name in forbidden_project_files:
            illegal_files.append(tracked_file)
            continue

        if lower_path.endswith(forbidden_source_suffixes) and lower_parts[0] not in {
            "docs",
            "tests",
        }:
            illegal_files.append(tracked_file)
            continue

        if lower_parts[0] == "scripts" and any(
            marker in name for marker in ("rewrite", "prototype")
        ):
            illegal_files.append(tracked_file)

    assert illegal_files == []


def test_scheduled_workflow_has_no_runtime_language_hard_gates() -> None:
    """Scheduled CI may summarize runtime_profile but must not enforce RUN-04 gates."""
    text = _non_comment_text(".github/workflows/update.yml")

    assert "runtime_profile" in text
    forbidden_workflow_tokens = (
        "scripts.benchmark_pipeline",
        "scripts.profile_pipeline",
        "py-spy",
        "pyperf",
        "dnspython",
        "go build",
        "cargo",
        "npm",
        "pnpm",
        "node",
        "tsc",
        "p95",
        "headroom",
        "runtime threshold",
        "runtime-threshold",
        "language gate",
        "language-gate",
    )
    for token in forbidden_workflow_tokens:
        assert token not in text


def test_dedicated_profile_wrapper_is_only_manual_profiling_surface() -> None:
    wrapper = _non_comment_text("scripts/profile_pipeline.py")
    normal_surfaces = [
        "scripts/pipeline.py",
        "scripts/release_validator.py",
        ".github/workflows/update.yml",
    ]
    if Path("run.py").exists():
        normal_surfaces.append("run.py")

    assert "cprofile" in wrapper
    assert "--py-spy-speedscope" in wrapper
    assert "--pyperf-json" in wrapper
    assert "--dns-diagnostics" in wrapper

    for path in normal_surfaces:
        text = _non_comment_text(path)
        assert "scripts.profile_pipeline" not in text
        assert "--py-spy-speedscope" not in text
        assert "--py-spy-flamegraph" not in text
        assert "--pyperf-json" not in text
        assert "--dns-diagnostics" not in text


def test_release_validator_has_no_stage_threshold_logic() -> None:
    code = _python_code_without_strings("scripts/release_validator.py")
    strings = _python_string_literals("scripts/release_validator.py")

    assert "stage_summaries" not in code
    for token in (
        "stage_summaries",
        "normalize",
        "prefilter",
        "compatibility",
        "compress",
        "prune",
    ):
        assert token not in strings
