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

# Extended header seen in newer captures (input/log_021.csv onward, 2026-08-
# 05) that add `mode` (e.g. "Listen-Only") and J1939-style `pgn`/`sa` columns.
# Also skipped on read; FrameParser handles both column layouts.
CSV_HEADER_EXTENDED = "ms,bus,mode,id_hex,ext,rtr,dlc,pgn,sa,data_hex"

# Variant of the extended header seen in input/log_038-040.csv (2026-08-09)
# that adds J1939-style `pgn`/`sa` columns but omits `mode` (9 columns, not
# 10). FrameParser treats `mode` as None for rows in this layout.
CSV_HEADER_EXTENDED_NO_MODE = "ms,bus,id_hex,ext,rtr,dlc,pgn,sa,data_hex"

# Header seen in the first BMW capture (input/bmw/log_001.csv, imported
# 2026-08-10, approved same day). Also 10 columns like CSV_HEADER_EXTENDED,
# but structurally different: no `mode` column; instead adds a `protocol`
# column (e.g. "STD_OBD") right before `data_hex`. `pgn`/`sa` are always "-"
# in this capture, same as the other extended layouts.
CSV_HEADER_BMW_PROTOCOL = "ms,bus,id_hex,ext,rtr,dlc,pgn,sa,protocol,data_hex"

# Ford diagnostic capture layout first observed in
# input/ford/log_012-TCM-P,R,N,D.csv and
# input/ford/log_014-TCM P,R,N,D,S,S-,S+.csv (approved 2026-08-31). This is
# the 10-column protocol layout above with an explicit TX/RX direction column
# appended after the payload.
CSV_HEADER_PROTOCOL_DIRECTION = (
    "ms,bus,id_hex,ext,rtr,dlc,pgn,sa,protocol,data_hex,direction"
)

# Discovery-tool capture layout first seen in
# input/ford/FORD_003 first 2min dis on IPC.CSV (approved 2026-08-20).
# Unlike the CAN Sniffer layouts above it supplies scan/direction metadata
# and uses a space-separated payload, but still represents ordinary CAN
# frames and is tagged separately so parsers never infer it by column count.
CSV_HEADER_DISCOVERY = "x2_ms,scan,bus,direction,id,dlc,data"

# Tags stored on RawLogEntry.column_layout so FrameParser can disambiguate
# column layouts that share the same column COUNT but different meaning
# (CSV_HEADER_EXTENDED vs CSV_HEADER_BMW_PROTOCOL are both 10 columns).
COLUMN_LAYOUT_7 = "7col"
COLUMN_LAYOUT_9_NO_MODE = "9col_no_mode"
COLUMN_LAYOUT_10_MODE = "10col_mode"
COLUMN_LAYOUT_10_PROTOCOL = "10col_protocol"
COLUMN_LAYOUT_11_PROTOCOL_DIRECTION = "11col_protocol_direction"
COLUMN_LAYOUT_7_DISCOVERY = "7col_discovery"

_HEADER_TO_LAYOUT = {
    CSV_HEADER: COLUMN_LAYOUT_7,
    CSV_HEADER_EXTENDED: COLUMN_LAYOUT_10_MODE,
    CSV_HEADER_EXTENDED_NO_MODE: COLUMN_LAYOUT_9_NO_MODE,
    CSV_HEADER_BMW_PROTOCOL: COLUMN_LAYOUT_10_PROTOCOL,
    CSV_HEADER_PROTOCOL_DIRECTION: COLUMN_LAYOUT_11_PROTOCOL_DIRECTION,
    CSV_HEADER_DISCOVERY: COLUMN_LAYOUT_7_DISCOVERY,
}


def find_log_files(input_dir: Path, pattern: str = "*.csv") -> list[Path]:
    """Return all log files in `input_dir` matching `pattern`, sorted by name."""
    return sorted(input_dir.glob(pattern))


def read_log_file(path: Path) -> list[RawLogEntry]:
    """Read a single log file into a list of RawLogEntry records."""
    entries: list[RawLogEntry] = []
    column_layout: str | None = None
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line_number, line in enumerate(f, start=1):
            text = line.rstrip("\n\r")
            if not text:
                continue
            header_text = text.strip().lower()
            if line_number == 1 and header_text in _HEADER_TO_LAYOUT:
                column_layout = _HEADER_TO_LAYOUT[header_text]
                continue
            entries.append(
                RawLogEntry(
                    line_number=line_number,
                    raw_text=text,
                    source_file=str(path),
                    column_layout=column_layout,
                )
            )
    return entries


def read_all_logs(input_dir: Path, pattern: str = "*.csv") -> list[RawLogEntry]:
    """Read every matching log file in `input_dir` into RawLogEntry records."""
    entries: list[RawLogEntry] = []
    for path in find_log_files(input_dir, pattern):
        entries.extend(read_log_file(path))
    return entries
