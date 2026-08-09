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

from bmw_analyser import analyse
from bmw_exporters import (
    export_byte_variability_csv,
    export_can_id_summary_csv,
    export_report,
)
from log_reader import read_all_logs

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT_DIR = REPO_ROOT / "input" / "bmw"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "output" / "bmw"


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


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    entries = read_all_logs(args.input_dir, args.pattern)
    result = analyse(entries)

    export_can_id_summary_csv(result, args.output_dir / "can_id_summary.csv")
    export_byte_variability_csv(result, args.output_dir / "byte_variability.csv")
    export_report(result, args.output_dir / "report.txt")

    print(
        f"Processed {result.summary.get('total_entries', 0)} entries -> "
        f"{result.summary.get('total_frames', 0)} frames "
        f"({result.summary.get('total_errors', 0)} errors, "
        f"{result.summary.get('unique_can_ids', 0)} unique CAN IDs)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
