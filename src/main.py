"""CLI entry point for the Decoding 2000 pipeline.

Reads raw logs from input/, analyses them into frames, and exports the
results to output/.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from exporters import (
    export_canid_summary_csv,
    export_csv,
    export_json,
    export_module_discovery_csv,
    export_report,
    export_telemetry_candidates_csv,
)
from frame_analyser import AnalysisResult, Frame, build_analysis_result, analyse
from log_reader import RawLogEntry, read_all_logs

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT_DIR = REPO_ROOT / "input"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "output"

# Source-log stems (filename without extension) that have been identified as
# useful diagnostic references for building the future GreatScan 3.5
# database (see AGENTS.md "Future expansion"). This is purely a convenience
# export within Decoding 2000's own output/ tree — it does not touch the
# GreatScan project itself (strict project separation). Add more stems here
# as further logs are identified.
GREATSCAN_DIAGNOSTIC_SOURCES: set[str] = {"log_009"}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Decode Decoder 2000 log files.")
    parser.add_argument(
        "--input-dir",
        type=Path,
        default=DEFAULT_INPUT_DIR,
        help="Directory containing raw log files (default: input/)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Directory to write decoded output to (default: output/)",
    )
    parser.add_argument(
        "--pattern",
        default="*.csv",
        help="Glob pattern for log files to read (default: *.csv)",
    )
    return parser.parse_args(argv)


def _export_all(result: AnalysisResult, output_dir: Path) -> None:
    """Write the standard set of decoded-output files to `output_dir`."""
    export_json(result, output_dir / "decoded.json")
    export_csv(result, output_dir / "decoded.csv")
    export_canid_summary_csv(result, output_dir / "can_id_summary.csv")
    export_module_discovery_csv(result, output_dir / "module_discovery.csv")
    export_report(result, output_dir / "report.txt")
    export_telemetry_candidates_csv(result, output_dir / "telemetry" / "candidates.csv")


def export_greatscan_diagnostics(
    entries: list[RawLogEntry], result: AnalysisResult, diagnostics_dir: Path
) -> None:
    """Export a standalone decoded-output set per log flagged in
    GREATSCAN_DIAGNOSTIC_SOURCES, under output/diagnostics/greatscan_3.5/.
    """
    frames_by_source: dict[str, list[Frame]] = {}
    for frame in result.frames:
        if frame.source is None:
            continue
        stem = Path(frame.source.source_file).stem
        frames_by_source.setdefault(stem, []).append(frame)

    for stem in GREATSCAN_DIAGNOSTIC_SOURCES:
        frames = frames_by_source.get(stem)
        if not frames:
            continue
        total_entries = sum(1 for e in entries if Path(e.source_file).stem == stem)
        sub_result = build_analysis_result(frames, total_entries)
        _export_all(sub_result, diagnostics_dir / stem)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    entries = read_all_logs(args.input_dir, args.pattern)
    result = analyse(entries)

    _export_all(result, args.output_dir)
    export_greatscan_diagnostics(
        entries, result, args.output_dir / "diagnostics" / "greatscan_3.5"
    )

    print(
        f"Processed {result.summary.get('total_entries', 0)} entries -> "
        f"{result.summary.get('total_frames', 0)} frames "
        f"({result.summary.get('total_errors', 0)} errors, "
        f"{result.summary.get('unique_can_ids', 0)} unique CAN IDs)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
