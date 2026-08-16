"""CLI entry point for Hyundai raw broadcast-CAN analysis."""

from __future__ import annotations

import argparse
from pathlib import Path

from log_reader import read_all_logs
from hyundai_signals import HYUNDAI_CAN_ID_NAMES, HYUNDAI_CONFIRMED_SIGNALS
from raw_can_analyser import analyse
from raw_can_exporters import (
    export_byte_variability_csv,
    export_can_id_summary_csv,
    export_csv,
    export_json,
    export_known_signals_csv,
    export_report,
    export_telemetry_candidates_csv,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT_DIR = REPO_ROOT / "input" / "hyundai"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "output" / "hyundai"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyse Hyundai raw broadcast-CAN capture logs."
    )
    parser.add_argument(
        "--input-dir",
        type=Path,
        default=DEFAULT_INPUT_DIR,
        help="Directory containing raw Hyundai logs (default: input/hyundai/)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Directory for Hyundai analysis output (default: output/hyundai/)",
    )
    parser.add_argument(
        "--pattern",
        default="*.csv",
        help="Glob pattern for log files to read (default: *.csv)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    entries = read_all_logs(args.input_dir, args.pattern)
    result = analyse(entries)

    export_json(result, args.output_dir / "decoded.json")
    export_csv(result, args.output_dir / "decoded.csv")
    export_can_id_summary_csv(
        result, args.output_dir / "can_id_summary.csv", HYUNDAI_CAN_ID_NAMES
    )
    export_byte_variability_csv(result, args.output_dir / "byte_variability.csv")
    export_known_signals_csv(
        HYUNDAI_CONFIRMED_SIGNALS, args.output_dir / "known_pids.csv"
    )
    export_report(result, args.output_dir / "report.txt", "Hyundai")
    export_telemetry_candidates_csv(
        result, args.output_dir / "telemetry" / "candidates.csv"
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
