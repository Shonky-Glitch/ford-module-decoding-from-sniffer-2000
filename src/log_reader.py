"""Reads raw log files from the input/ directory.

Responsible only for turning raw files into RawLogEntry objects — no parsing
or interpretation of frame contents happens here (see frame_analyser.py).
"""

from __future__ import annotations

from pathlib import Path

from models import RawLogEntry

# Header row observed in real CAN Sniffer 2000 captures (input/log_*.csv).
# Skipped on read since it is structural, not a data record.
CSV_HEADER = "ms,bus,id_hex,ext,rtr,dlc,data_hex"


def find_log_files(input_dir: Path, pattern: str = "*.csv") -> list[Path]:
    """Return all log files in `input_dir` matching `pattern`, sorted by name."""
    return sorted(input_dir.glob(pattern))


def read_log_file(path: Path) -> list[RawLogEntry]:
    """Read a single log file into a list of RawLogEntry records."""
    entries: list[RawLogEntry] = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line_number, line in enumerate(f, start=1):
            text = line.rstrip("\n\r")
            if not text:
                continue
            if line_number == 1 and text.strip().lower() == CSV_HEADER:
                continue
            entries.append(
                RawLogEntry(
                    line_number=line_number,
                    raw_text=text,
                    source_file=str(path),
                )
            )
    return entries


def read_all_logs(input_dir: Path, pattern: str = "*.csv") -> list[RawLogEntry]:
    """Read every matching log file in `input_dir` into RawLogEntry records."""
    entries: list[RawLogEntry] = []
    for path in find_log_files(input_dir, pattern):
        entries.extend(read_log_file(path))
    return entries
