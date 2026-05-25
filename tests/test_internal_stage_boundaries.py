"""Static guards for Phase 9 internal diagnostics boundaries."""

import io
import tokenize
from pathlib import Path

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
    return Path(path).read_text(encoding="utf-8")


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
