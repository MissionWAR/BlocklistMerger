"""Static guards for Phase 9 internal diagnostics boundaries."""

import ast
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
INSPECT_ONLY_FINDING_CODE_TOKENS = (
    "benchmark",
    "profile",
    "runtime",
    "stage",
    "semantic",
    "churn",
    "fingerprint",
    "membership",
    "language",
    "headroom",
    "p95",
)
HEAVY_EVIDENCE_SURFACE_TOKENS = (
    "scripts.benchmark_pipeline",
    "scripts.profile_pipeline",
    "reports/benchmarks",
    "reports/profiles",
    ".[profile]",
    "--py-spy-speedscope",
    "--py-spy-flamegraph",
    "--pyperf-json",
    "--dns-diagnostics",
    "py-spy",
    "pyperf",
    "dnspython",
    "adguardhome",
    "adguard/adguardhome",
    "agh oracle",
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


def _python_tree(path: str) -> ast.AST:
    return ast.parse(_read(path), filename=path)


def _release_validator_finding_codes() -> set[str]:
    codes: set[str] = set()
    for node in ast.walk(_python_tree("scripts/release_validator.py")):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Name) or node.func.id != "_finding":
            continue
        if node.args and isinstance(node.args[0], ast.Constant):
            value = node.args[0].value
            if isinstance(value, str):
                codes.add(value)
    return codes


def _release_threshold_field_names() -> set[str]:
    for node in ast.walk(_python_tree("scripts/release_validator.py")):
        if not isinstance(node, ast.ClassDef) or node.name != "ReleaseThresholds":
            continue
        return {
            statement.target.id
            for statement in node.body
            if isinstance(statement, ast.AnnAssign)
            and isinstance(statement.target, ast.Name)
        }
    raise AssertionError("ReleaseThresholds class not found")


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


def test_manual_heavy_evidence_workflow_is_not_a_scheduled_publish_gate() -> None:
    """Manual heavy evidence may collect reports but must not affect scheduled release."""
    text = _non_comment_text(".github/workflows/heavy-evidence.yml")

    assert "workflow_dispatch" in text
    assert "reports/heavy-evidence/**" in text
    assert "reports/benchmarks/**" in text
    assert "reports/profiles/**" in text
    assert "schedule:" not in text
    assert "cron:" not in text
    assert "publish:" not in text
    assert "needs: build_validate" not in text
    assert "contents: write" not in text
    assert "actions: write" not in text
    assert "softprops/action-gh-release" not in text
    assert "actions/download-artifact" not in text
    assert "actions/cache" not in text
    assert "gh cache" not in text


def test_release_guard_promotion_doc_preserves_inspect_only_boundaries() -> None:
    """Promotion docs must match the deterministic-only release gate policy."""
    text = _non_comment_text("docs/RELEASE_GUARD_PROMOTION.md")
    update = _non_comment_text(".github/workflows/update.yml")
    heavy = _non_comment_text(".github/workflows/heavy-evidence.yml")

    assert "--evidence-json reports/release-evidence.json" in update
    assert "release evidence sidecar" in text
    assert "deterministic artifact safety" in text
    assert "evidence-integrity failures" in text
    assert "scoped hard canary failures" in text
    assert "inspect-only" in text

    for token in (
        "membership churn",
        "output fingerprints",
        "runtime profiles",
        "stage summaries",
        "semantic diagnostics",
        "heavy evidence",
    ):
        assert token in text

    for phrase in (
        "membership churn blocks scheduled publishing",
        "output fingerprints block scheduled publishing",
        "runtime profiles block scheduled publishing",
        "stage summaries block scheduled publishing",
        "semantic diagnostics block scheduled publishing",
        "heavy evidence blocks scheduled publishing",
    ):
        assert phrase not in text

    assert "workflow_dispatch" in text
    assert "workflow_dispatch" in heavy
    assert "weekly heavy-evidence schedule is not active" in text
    assert "schedule:" not in heavy


def test_release_guard_promotion_doc_lists_required_promotion_evidence() -> None:
    """Docs should require explicit evidence before any diagnostic becomes a gate."""
    text = _non_comment_text("docs/RELEASE_GUARD_PROMOTION.md")

    for phrase in (
        "deterministic fixture coverage",
        "stable report schema",
        "stable budgets from repeated manual runs",
        "low-noise false-positive behavior",
        "explicit threshold ownership",
        "intentional source change",
    ):
        assert phrase in text

    assert "weekly cron" not in text
    assert "automatic promotion" not in text


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


def test_default_command_surfaces_do_not_call_heavy_evidence_wrappers() -> None:
    """Default public commands may expose compact diagnostics, not heavy evidence entrypoints."""
    normal_surfaces = [
        "scripts/pipeline.py",
        "scripts/release_validator.py",
        "run.py",
    ]

    for path in normal_surfaces:
        text = _non_comment_text(path)
        for token in HEAVY_EVIDENCE_SURFACE_TOKENS:
            assert token not in text


def test_release_validator_has_no_heavy_evidence_imports_or_threshold_fields() -> None:
    """Benchmark, profile, and language evidence must not become validator hard gates."""
    code = _python_code_without_strings("scripts/release_validator.py")
    threshold_fields = _release_threshold_field_names()

    for token in (
        "benchmark_pipeline",
        "profile_pipeline",
        "benchmark_evidence",
        "profile_evidence",
        "language_gate",
        "py_spy",
        "pyperf",
        "dnspython",
    ):
        assert token not in code

    assert "minimum_output_rules" in threshold_fields
    assert "previous_extreme_drop_ratio" in threshold_fields
    assert {
        field
        for field in threshold_fields
        if any(token in field for token in ("benchmark", "profile", "language", "p95"))
    } == set()


def test_release_validator_finding_codes_stay_limited_to_deterministic_gates() -> None:
    """Inspect-only diagnostics must not appear as validator error or warning codes."""
    finding_codes = _release_validator_finding_codes()
    promoted_diagnostic_codes = {
        code
        for code in finding_codes
        if any(token in code for token in INSPECT_ONLY_FINDING_CODE_TOKENS)
    }

    assert promoted_diagnostic_codes == set()
    assert {
        "output_invalid_syntax",
        "pipeline_output_count_mismatch",
        "canary_must_block_missing",
        "source_health_catastrophic_failed_stale",
        "previous_output_extreme_drop",
    } <= finding_codes


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
