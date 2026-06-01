"""Static checks for public documentation and fork-reuse boundaries."""

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
AGH_SEMANTICS = ROOT / "docs" / "AGH_SEMANTICS.md"
SCOPE_DOC = ROOT / "docs" / "SCOPE.md"
RUNTIME_LANGUAGE_GATE = ROOT / "docs" / "RUNTIME_LANGUAGE_GATE.md"
WORKFLOW = ROOT / ".github" / "workflows" / "update.yml"

MAINTAINER_RELEASE_URL = (
    "https://github.com/MissionWAR/BlocklistMerger/releases/download/latest/merged.txt"
)


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _position(text: str, needle: str) -> int:
    position = text.find(needle)
    assert position != -1, f"Missing text: {needle!r}"
    return position


def _git_check_ignore(path: str, *, no_index: bool = False) -> int:
    args = ["git", "check-ignore", "-q"]
    if no_index:
        args.insert(2, "--no-index")
    args.append(path)
    return subprocess.run(args, cwd=ROOT, check=False).returncode


def _git_ls_files(*paths: str) -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", *paths],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    return [line for line in result.stdout.splitlines() if line]


def test_readme_public_reuse_paths() -> None:
    """README should keep quick usage first and document current fork surfaces."""
    text = _read_text(README)

    assert MAINTAINER_RELEASE_URL in text
    assert _position(text, MAINTAINER_RELEASE_URL) < _position(text, "## 🔧 Forking This Workflow")

    required_snippets = [
        "config/sources.txt",
        "Python 3.14",
        "pip install .",
        "python -m scripts.downloader",
        "python -m scripts.pipeline",
        "lists/_raw",
        ".cache",
        "lists/merged.txt",
        "reports/source-health.json",
        "reports/pipeline-stats.json",
        "reports/validation-summary.md",
        "SOURCES=config/sources.txt",
        "RAW_DIR=lists/_raw",
        "OUTPUT=lists/merged.txt",
        "--concurrency",
        "--timeout",
        "--retries",
        "--health-report",
        "--json-stats",
        "https://github.com/<owner>/<repo>/releases/download/latest/merged.txt",
    ]
    for snippet in required_snippets:
        assert snippet in text

    assert "python run.py" not in text


def test_workflow_public_reuse_surface_has_no_manual_inputs() -> None:
    """Manual release dispatch should stay input-free for the public fork path."""
    text = _read_text(WORKFLOW)

    assert "workflow_dispatch:" in text
    assert "inputs:" not in text
    assert 'cron: "0 */12 * * *"' in text
    assert "SOURCES: config/sources.txt" in text
    assert "RAW_DIR: lists/_raw" in text
    assert "OUTPUT: lists/merged.txt" in text
    assert "--health-report reports/source-health.json" in text
    assert "--json-stats reports/pipeline-stats.json" in text


def test_ignore_policy_source_runtime_boundary() -> None:
    """Public docs/tests should be trackable while runtime and private paths stay ignored."""
    assert _git_check_ignore("docs/SCOPE.md") == 1
    assert _git_check_ignore("tests/test_public_docs.py") == 1

    assert _git_check_ignore("reports/pipeline-stats.json") == 0
    assert _git_check_ignore("AGENTS.md") == 0
    assert _git_check_ignore("run.py") == 0

    assert _git_ls_files("lists", ".cache", "reports") == []


def test_scope_doc_defers_v2_config_platform() -> None:
    """Public scope docs should park v2 configuration-platform ideas outside v1 commands."""
    readme = _read_text(README)
    scope = _read_text(SCOPE_DOC)

    assert SCOPE_DOC.exists()
    assert "docs/SCOPE.md" in readme
    assert _position(readme, MAINTAINER_RELEASE_URL) < _position(readme, "## Scope and Non-Goals")
    assert "AdGuard Home-compatible `merged.txt` release asset" in scope
    assert "config/sources.txt" in scope
    assert "AdGuard Home" in scope
    assert "Deferred to v2" in scope

    deferred_items = [
        "Structured JSON/YAML source metadata",
        "Per-source transformations",
        "Inclusion and exclusion list semantics",
        "Named pruning policies",
        "Multiple output profiles",
    ]
    for item in deferred_items:
        assert item in scope


def test_agh_semantics_matrix_is_publicly_discoverable() -> None:
    """README should link the AGH semantics baseline and preserve required vocabulary."""
    readme = _read_text(README)

    assert AGH_SEMANTICS.exists()
    assert "docs/AGH_SEMANTICS.md" in readme
    semantics = _read_text(AGH_SEMANTICS)

    required_vocabulary = [
        "badfilter",
        "denyallow",
        "dnsrewrite",
        "dnstype",
        "client",
        "ctag",
        "coverage-broadening compression",
        "unsupported",
        "uncertain",
        "regex",
    ]
    for term in required_vocabulary:
        assert term in semantics


def test_runtime_language_gate_is_publicly_discoverable() -> None:
    """README should link the Python-first runtime/language decision gate."""
    readme = _read_text(README)

    assert RUNTIME_LANGUAGE_GATE.exists()
    assert "docs/RUNTIME_LANGUAGE_GATE.md" in readme
    assert _position(readme, "## 📥 Usage") < _position(readme, "## Scope and Non-Goals")
    assert _position(readme, "docs/SCOPE.md") < _position(
        readme,
        "docs/RUNTIME_LANGUAGE_GATE.md",
    )


def test_runtime_language_gate_records_required_evidence() -> None:
    """RUN-04 gate should keep Python first and require proof before rewrites."""
    text = _read_text(RUNTIME_LANGUAGE_GATE)

    required_vocabulary = [
        "Python remains the default",
        "2x",
        "p95",
        "build_validate",
        "30-minute",
        "15 minutes",
        "memory",
        "disk",
        "algorithmic fixes",
        "cProfile",
        "pstats",
        "reports/benchmarks",
        "reports/profiles",
        "Go",
        "Rust",
        "JavaScript",
        "TypeScript",
        "no lost/changed coverage",
        "proof-ledger",
        "inspect-only",
    ]
    for term in required_vocabulary:
        assert term in text

    assert "release findings" in text
    assert "not a rewrite plan" in text
    assert "tracked rewrite artifacts" in text


def test_runtime_docs_do_not_move_optional_tools_into_build_validate() -> None:
    """Runtime docs should keep optional profiler installs out of scheduled CI."""
    doc_paths = [
        RUNTIME_LANGUAGE_GATE,
        ROOT / "docs" / "BENCHMARKS.md",
        ROOT / "docs" / "PROFILING.md",
    ]
    optional_tool_tokens = (
        "py-spy",
        "pyperf",
        "dnspython",
        ".[profile]",
        "scripts.profile_pipeline",
    )

    for path in doc_paths:
        if not path.exists():
            continue
        text = _read_text(path)
        lines = text.splitlines()
        for index, line in enumerate(lines):
            lowered = line.lower()
            scheduled_context = "build_validate" in lowered or "scheduled" in lowered
            if not scheduled_context:
                continue
            assert "pip install" not in lowered
            for token in optional_tool_tokens:
                assert token not in lowered, f"{path} line {index + 1}: {line}"

        install_blocks = [
            line.lower()
            for line in lines
            if "pip install" in line.lower() or "python -m pip install" in line.lower()
        ]
        for install_line in install_blocks:
            assert "build_validate" not in install_line
            assert ".[dev,profile]" not in install_line
            assert "pyperf" not in install_line
