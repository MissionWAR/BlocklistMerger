"""Static checks for public documentation and fork-reuse boundaries."""

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
SCOPE_DOC = ROOT / "docs" / "SCOPE.md"
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
    assert _git_check_ignore(".planning/STATE.md", no_index=True) == 0
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
