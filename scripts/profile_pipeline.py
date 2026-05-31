#!/usr/bin/env python3
"""Stdlib profiling wrapper for the blocklist pipeline."""

import argparse
import cProfile
import importlib.util
import json
import pstats
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Final

from scripts.pipeline import process_files_with_profile, save_stats_json

PROFILE_ROOT: Final[Path] = Path("reports/profiles")
_RUN_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _rooted(path: Path) -> Path:
    """Return an absolute path rooted at the current working directory."""
    return path if path.is_absolute() else Path.cwd() / path


def _profile_root() -> Path:
    """Return the resolved profile report root."""
    return _rooted(PROFILE_ROOT).resolve(strict=False)


def _validate_run_id(run_id: str) -> str:
    """Return a run id that is safe to use as one profile directory name."""
    if not _RUN_ID_PATTERN.fullmatch(run_id):
        msg = "run-id must contain only letters, numbers, dots, dashes, or underscores"
        raise ValueError(msg)
    run_path = Path(run_id)
    if run_path.is_absolute() or run_path.name != run_id or ".." in run_path.parts:
        raise ValueError("run-id must be a single safe path segment")
    return run_id


def _resolve_report_root(report_dir: str | None) -> Path:
    """Resolve an optional report root and require it under reports/profiles."""
    root = _profile_root()
    if report_dir is None:
        return root

    candidate = _rooted(Path(report_dir)).resolve(strict=False)
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        msg = f"report-dir must resolve under {PROFILE_ROOT.as_posix()}"
        raise ValueError(msg) from exc
    if candidate.exists() and not candidate.is_dir():
        raise ValueError("report-dir must be a directory")
    return candidate


def _resolve_run_dir(run_id: str, report_dir: str | None) -> Path:
    """Return the validated profile run directory."""
    safe_run_id = _validate_run_id(run_id)
    report_root = _resolve_report_root(report_dir)
    run_dir = (report_root / safe_run_id).resolve(strict=False)
    try:
        run_dir.relative_to(_profile_root())
    except ValueError as exc:
        msg = f"profile run directory must stay under {PROFILE_ROOT.as_posix()}"
        raise ValueError(msg) from exc
    return run_dir


def _positive_int(value: str) -> int:
    """Parse a positive integer CLI option."""
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def _module_available(name: str) -> bool:
    """Return True when an optional Python module can be imported."""
    return importlib.util.find_spec(name) is not None


def _missing_optional_tool(tool: str, artifact: str, flag: str) -> RuntimeError:
    """Build an actionable error for an explicitly requested optional artifact."""
    detail = (
        f"{tool} is unavailable for requested {artifact} ({flag}); "
        f"{tool} is manual/profiling-only and is not installed by scheduled "
        "publish dependencies."
    )
    if tool == "pyperf":
        detail += (
            " pyperf is intentionally omitted from tracked dependency and install "
            "documentation until a human package-legitimacy check approves it."
        )
    detail += " Install or expose the verified tool in a manual profiling environment, then rerun."
    return RuntimeError(detail)


def _validate_optional_tools(args: argparse.Namespace) -> None:
    """Fail before writing artifacts when a requested optional tool is unavailable."""
    if (args.py_spy_speedscope or args.py_spy_flamegraph) and shutil.which("py-spy") is None:
        artifact = "py-spy speedscope/flamegraph artifact"
        raise _missing_optional_tool("py-spy", artifact, "--py-spy-*")

    if args.pyperf_json and not (_module_available("pyperf") or shutil.which("pyperf")):
        raise _missing_optional_tool("pyperf", "pyperf JSON artifact", "--pyperf-json")

    if args.dns_diagnostics and not _module_available("dns"):
        raise _missing_optional_tool(
            "dnspython",
            "DNS diagnostics artifact",
            "--dns-diagnostics",
        )


def _pipeline_command(input_dir: Path, output_path: Path, stats_path: Path) -> list[str]:
    """Return a production-shaped pipeline command for optional external tools."""
    return [
        sys.executable,
        "-m",
        "scripts.pipeline",
        str(input_dir),
        str(output_path),
        "--json-stats",
        str(stats_path),
    ]


def _run_checked(command: list[str], artifact: str) -> None:
    """Run an optional external artifact command and surface failures clearly."""
    try:
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as exc:
        msg = f"{artifact} generation failed with exit code {exc.returncode}"
        raise RuntimeError(msg) from exc


def _run_py_spy(
    input_dir: Path,
    run_dir: Path,
    *,
    output_name: str,
    format_name: str,
) -> None:
    """Generate one optional py-spy artifact through an explicit manual request."""
    py_spy = shutil.which("py-spy")
    if py_spy is None:
        raise _missing_optional_tool("py-spy", f"py-spy {format_name} artifact", "--py-spy-*")

    output_path = run_dir / output_name
    pipeline_output = run_dir / f"py-spy-{format_name}-merged.txt"
    stats_path = run_dir / f"py-spy-{format_name}-pipeline-stats.json"
    command = [
        py_spy,
        "record",
        "--format",
        format_name,
        "-o",
        str(output_path),
        "--",
        *_pipeline_command(input_dir, pipeline_output, stats_path),
    ]
    _run_checked(command, f"py-spy {format_name}")


def _run_pyperf(input_dir: Path, run_dir: Path) -> None:
    """Generate optional pyperf JSON through an explicit manual request."""
    if _module_available("pyperf"):
        pyperf_command = [sys.executable, "-m", "pyperf"]
    else:
        pyperf_path = shutil.which("pyperf")
        if pyperf_path is None:
            raise _missing_optional_tool("pyperf", "pyperf JSON artifact", "--pyperf-json")
        pyperf_command = [pyperf_path]

    command = [
        *pyperf_command,
        "command",
        "-o",
        str(run_dir / "pipeline.pyperf.json"),
        "--",
        *_pipeline_command(
            input_dir,
            run_dir / "pyperf-merged.txt",
            run_dir / "pyperf-pipeline-stats.json",
        ),
    ]
    _run_checked(command, "pyperf JSON")


def _write_json_atomic(path: Path, data: dict[str, object]) -> None:
    """Write JSON through an atomic sibling temp file."""
    temp_path = path.with_suffix(".tmp")
    with open(temp_path, "w", encoding="utf-8", newline="\n") as stream:
        json.dump(data, stream, indent=2, sort_keys=True)
        stream.write("\n")
    temp_path.replace(path)


def _write_dns_diagnostics(input_dir: Path, run_dir: Path, merged_path: Path) -> None:
    """Write a local dnspython availability diagnostic artifact."""
    try:
        import dns.version
    except ModuleNotFoundError as exc:
        raise _missing_optional_tool(
            "dnspython",
            "DNS diagnostics artifact",
            "--dns-diagnostics",
        ) from exc

    _write_json_atomic(
        run_dir / "dns-diagnostics.json",
        {
            "artifact": "dns-diagnostics.json",
            "dnspython_version": dns.version.version,
            "input_dir": str(input_dir),
            "manual_profiling_only": True,
            "profile_output": str(merged_path),
            "tool": "dnspython",
        },
    )


def _write_pstats_summary(
    profile_path: Path,
    output_path: Path,
    *,
    sort_by: str,
    limit: int,
) -> None:
    """Write one capped pstats text summary from a cProfile data file."""
    temp_path = output_path.with_suffix(".tmp")
    with open(temp_path, "w", encoding="utf-8", newline="\n") as stream:
        stats = pstats.Stats(str(profile_path), stream=stream)
        stats.strip_dirs().sort_stats(sort_by).print_stats(limit)
    temp_path.replace(output_path)


def _build_parser() -> argparse.ArgumentParser:
    """Build the profiling CLI parser."""
    parser = argparse.ArgumentParser(
        prog="scripts.profile_pipeline",
        description="Run the blocklist pipeline under stdlib cProfile.",
    )
    parser.add_argument("input_dir", help="Directory containing raw blocklist .txt files")
    parser.add_argument(
        "--run-id",
        required=True,
        help="Safe profile run identifier used under reports/profiles/",
    )
    parser.add_argument(
        "--report-dir",
        help="Optional profile report root; must resolve under reports/profiles/",
    )
    parser.add_argument(
        "--pstats-limit",
        type=_positive_int,
        default=40,
        help="Maximum rows to include in each pstats summary (default: 40)",
    )
    parser.add_argument(
        "--py-spy-speedscope",
        action="store_true",
        help="Request an optional manual py-spy speedscope artifact.",
    )
    parser.add_argument(
        "--py-spy-flamegraph",
        action="store_true",
        help="Request an optional manual py-spy flamegraph artifact.",
    )
    parser.add_argument(
        "--pyperf-json",
        action="store_true",
        help="Request an optional manual pyperf JSON artifact.",
    )
    parser.add_argument(
        "--dns-diagnostics",
        action="store_true",
        help="Request an optional manual dnspython diagnostics artifact.",
    )
    return parser


def main() -> int:
    """CLI entry point for stdlib profile artifact generation."""
    parser = _build_parser()
    args = parser.parse_args()

    try:
        input_dir = Path(args.input_dir)
        if not input_dir.is_dir():
            raise FileNotFoundError(f"input_dir not found: {args.input_dir}")

        run_dir = _resolve_run_dir(args.run_id, args.report_dir)
        _validate_optional_tools(args)
        run_dir.mkdir(parents=True, exist_ok=True)

        profile_path = run_dir / "pipeline.cprofile"
        cumulative_path = run_dir / "pstats-cumulative.txt"
        total_time_path = run_dir / "pstats-total-time.txt"
        stats_path = run_dir / "pipeline-stats.json"
        merged_path = run_dir / "merged.txt"

        profiler = cProfile.Profile()
        start = time.perf_counter()
        result = profiler.runcall(process_files_with_profile, input_dir, merged_path)
        elapsed = time.perf_counter() - start
        profiler.dump_stats(profile_path)

        _write_pstats_summary(
            profile_path,
            cumulative_path,
            sort_by="cumulative",
            limit=args.pstats_limit,
        )
        _write_pstats_summary(
            profile_path,
            total_time_path,
            sort_by="tottime",
            limit=args.pstats_limit,
        )
        save_stats_json(
            result.stats,
            str(stats_path),
            elapsed,
            runtime_profile=result.runtime_profile,
        )
        if args.py_spy_speedscope:
            _run_py_spy(
                input_dir,
                run_dir,
                output_name="py-spy-speedscope.json",
                format_name="speedscope",
            )
        if args.py_spy_flamegraph:
            _run_py_spy(
                input_dir,
                run_dir,
                output_name="py-spy-flamegraph.svg",
                format_name="flamegraph",
            )
        if args.pyperf_json:
            _run_pyperf(input_dir, run_dir)
        if args.dns_diagnostics:
            _write_dns_diagnostics(input_dir, run_dir, merged_path)

        print(f"Profile report: {run_dir.as_posix()}")
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
