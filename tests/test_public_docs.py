"""Static checks for public documentation and fork-reuse boundaries."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
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
        "https://github.com/<owner>/<repo>/releases/latest/download/merged.txt",
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
