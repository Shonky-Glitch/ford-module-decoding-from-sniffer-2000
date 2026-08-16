"""CLI entry point for the BMW-specific decoding pipeline.

Kept entirely separate from src/main.py (the Ford pipeline) per AGENTS.md
"strict project separation" -- BMW captures are read from input/bmw/ and
written to output/bmw/ only, using bmw_analyser.py's raw-traffic-only
analysis (no ISO-TP/UDS decoding, no module-name/DID assumptions -- BMW's
diagnostic addressing/protocol is not confirmed, see
reference/bmw_ecu_reference.md).
"""

from __future__ import annotations

import argparse
from pathlib import Path

from raw_can_analyser import analyse, build_analysis_result
from raw_can_exporters import (
    export_byte_variability_csv,
    export_can_id_summary_csv,
    export_csv,
    export_json,
    export_report,
    export_telemetry_candidates_csv,
)
from log_reader import RawLogEntry, read_all_logs
from models import BmwAnalysisResult, BmwFrame

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT_DIR = REPO_ROOT / "input" / "bmw"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "output" / "bmw"

# Source-log stems (filename without extension) flagged as useful
# diagnostic references for future BMW protocol/module research -- mirrors
# main.py's GREATSCAN_DIAGNOSTIC_SOURCES mechanism, but purely a
# convenience export within this repo's own output/ tree (no equivalent
# sibling project for BMW yet). Add more stems here as further notable
# captures are identified.
BMW_DIAGNOSTIC_SOURCES: set[str] = {"log_001"}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyse BMW capture log files.")
    parser.add_argument(
        "--input-dir",
        type=Path,
        default=DEFAULT_INPUT_DIR,
        help="Directory containing raw BMW log files (default: input/bmw/)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Directory to write BMW analysis output to (default: output/bmw/)",
    )
    parser.add_argument(
        "--pattern",
        default="*.csv",
        help="Glob pattern for log files to read (default: *.csv)",
    )
    return parser.parse_args(argv)


def _export_all(result: BmwAnalysisResult, output_dir: Path) -> None:
    """Write the standard set of BMW decoded-output files to `output_dir`."""
    export_json(result, output_dir / "decoded.json")
    export_csv(result, output_dir / "decoded.csv")
    export_can_id_summary_csv(result, output_dir / "can_id_summary.csv")
    export_byte_variability_csv(result, output_dir / "byte_variability.csv")
    export_report(result, output_dir / "report.txt", "BMW")
    export_telemetry_candidates_csv(
        result, output_dir / "telemetry" / "candidates.csv"
    )


def export_bmw_diagnostics(
    entries: list[RawLogEntry], result: BmwAnalysisResult, diagnostics_dir: Path
) -> None:
    """Export a standalone decoded-output set per log flagged in
    BMW_DIAGNOSTIC_SOURCES, under output/bmw/diagnostics/.
    """
    frames_by_source: dict[str, list[BmwFrame]] = {}
    for frame in result.frames:
        if frame.source is None:
            continue
        stem = Path(frame.source.source_file).stem
        frames_by_source.setdefault(stem, []).append(frame)

    for stem in BMW_DIAGNOSTIC_SOURCES:
        frames = frames_by_source.get(stem)
        if not frames:
            continue
        total_entries = sum(1 for e in entries if Path(e.source_file).stem == stem)
        sub_result = build_analysis_result(frames, [], total_entries)
        _export_all(sub_result, diagnostics_dir / stem)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    entries = read_all_logs(args.input_dir, args.pattern)
    result = analyse(entries)

    _export_all(result, args.output_dir)
    export_bmw_diagnostics(entries, result, args.output_dir / "diagnostics")

    print(
        f"Processed {result.summary.get('total_entries', 0)} entries -> "
        f"{result.summary.get('total_frames', 0)} frames "
        f"({result.summary.get('total_errors', 0)} errors, "
        f"{result.summary.get('unique_can_ids', 0)} unique CAN IDs)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
