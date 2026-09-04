"""Static checks for public documentation and fork-reuse boundaries."""

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
AGH_SEMANTICS = ROOT / "docs" / "AGH_SEMANTICS.md"
SCOPE_DOC = ROOT / "docs" / "SCOPE.md"
RUNTIME_LANGUAGE_GATE = ROOT / "docs" / "RUNTIME_LANGUAGE_GATE.md"
WORKFLOW = ROOT / ".github" / "workflows" / "update.yml"
GIT_BLAME_IGNORE_REVS = ROOT / ".git-blame-ignore-revs"

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


def _git_rev_parse_verify(revision: str) -> bool:
    result = subprocess.run(
        ["git", "rev-parse", "--verify", revision],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def _git_is_ancestor(sha: str) -> bool:
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", sha, "HEAD"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


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
    """Public docs/tests should be trackable while runtime and private paths stay ignored.

    Phase 17 (D-17-02/D-17-07) carves exactly one exception out of the
    reports/ ignore: reports/shadow-gate/ is a committed evidence home
    for apex-shadow summary manifests. Every other reports/ subtree and
    all other generated/runtime outputs stay untracked.
    """
    assert _git_check_ignore("docs/SCOPE.md") == 1
    assert _git_check_ignore("tests/test_public_docs.py") == 1

    assert _git_check_ignore("reports/pipeline-stats.json") == 0
    assert _git_check_ignore("AGENTS.md") == 0
    assert _git_check_ignore("run.py") == 0

    # The shadow-gate evidence home itself stays trackable (manifests are
    # versioned stems, so pin a future-shaped path, not just current files).
    assert _git_check_ignore("reports/shadow-gate/apex-shadow-v1.json") == 1

    tracked = _git_ls_files("lists", ".cache", "reports")
    bulk_tracked = [path for path in tracked if not path.startswith("reports/shadow-gate/")]
    assert bulk_tracked == []


def test_blame_ignore_revs_reference_resolves_to_head_ancestor() -> None:
    """The formatter-normalization exemption must pin one real ancestor commit."""
    assert GIT_BLAME_IGNORE_REVS.exists()

    shas = [
        line
        for line in _read_text(GIT_BLAME_IGNORE_REVS).splitlines()
        if re.fullmatch(r"[0-9a-f]{40}", line)
    ]
    assert len(shas) == 1

    sha = shas[0]
    assert _git_rev_parse_verify(f"{sha}^{{commit}}"), f"SHA does not resolve: {sha}"
    assert _git_is_ancestor(sha), f"SHA is not an ancestor of HEAD: {sha}"


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


def test_readme_direction_a_closure_paragraph_is_contained_with_evidence_link() -> None:
    """README should keep the apex-shadow verdict inside Scope and Non-Goals."""
    text = _read_text(README)
    scope_heading = _position(text, "## Scope and Non-Goals")
    paragraph_start = _position(
        text,
        "**Apex-covered wildcard pruning (v1.3): measured, not enabled.**",
    )
    paragraph_end = text.find("\n\n", paragraph_start)
    sources_heading = _position(text, "## 📋 Sources")

    assert scope_heading < paragraph_start < paragraph_end < sources_heading

    paragraph = text[paragraph_start:paragraph_end]
    required_fragments = [
        "A full-corpus shadow run over 10,348,336 input rules",
        "no surviving TLD wildcard has a same-key apex coverer",
        "would have cost +23.4% median wall-clock",
        "ships permanently disabled and the direction is closed",
    ]
    for fragment in required_fragments:
        assert fragment in paragraph

    assert (
        "[`reports/shadow-gate/apex-shadow-v1.md`](reports/shadow-gate/apex-shadow-v1.md)"
        in paragraph
    )

    assert "APEX_SHADOW_DATASET_ID" not in text


def test_readme_direction_b_closure_paragraph_is_contained_with_evidence_link() -> None:
    """README should keep the dirb-shadow verdict inside Scope and Non-Goals."""
    text = _read_text(README)
    scope_heading = _position(text, "## Scope and Non-Goals")
    apex_start = _position(
        text,
        "**Apex-covered wildcard pruning (v1.3): measured, not enabled.**",
    )
    paragraph_start = _position(
        text,
        "**Wildcard-covers-sub pruning: measured, not enabled.**",
    )
    paragraph_end = text.find("\n\n", paragraph_start)
    sources_heading = _position(text, "## 📋 Sources")

    assert scope_heading < apex_start < paragraph_start < paragraph_end < sources_heading

    paragraph = text[paragraph_start:paragraph_end]
    required_fragments = [
        "A full-corpus shadow run over 10,257,217 input rules",
        "nothing remained that only the new pass can remove",
        "-3.69% median wall-clock overhead, an informational figure that never gates",
        "stays deliberately default-OFF and the direction is closed",
    ]
    for fragment in required_fragments:
        assert fragment in paragraph

    assert (
        "[`reports/shadow-gate/dirb-shadow-v1.md`](reports/shadow-gate/dirb-shadow-v1.md)"
        in paragraph
    )

    assert "DIRB_SHADOW_DATASET_ID" not in text


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
