"""Parses and analyses BMW capture logs.

Deliberately separate from frame_analyser.py: BMW captures are NOT known to
use Ford's ISO-TP/UDS diagnostic convention (see
reference/bmw_ecu_reference.md and AGENTS.md "never guess the input file
format" / "never guess PID/DID meaning"). This module treats every frame as
an opaque raw CAN broadcast frame -- id, timestamp, payload bytes -- and
only derives generic traffic/shape statistics (cycle time, per-byte-offset
variability). No module-name or DID/PID interpretation is attached here.
"""

from __future__ import annotations

import csv
import statistics

from models import (
    BmwAnalysisResult,
    BmwByteVariability,
    BmwCanIdCycleStats,
    BmwFrame,
    RawLogEntry,
)


class BmwFrameParser:
    """Turns a single raw CSV log entry into a BmwFrame.

    Reuses the same column layouts as log_reader.py/frame_analyser.py
    (7/9/10 columns, disambiguated via RawLogEntry.column_layout for the
    two 10-column variants) but does NOT run any ISO-TP/UDS decoding over
    the payload -- BMW's framing has not been confirmed to be ISO 15765-2
    at all (see reference/bmw_ecu_reference.md).
    """

    def parse(self, entry: RawLogEntry) -> BmwFrame | None:
        text = entry.raw_text.strip()
        if not text:
            return None

        try:
            row = next(csv.reader([text]))
        except Exception as exc:  # noqa: BLE001 - surfaced as a parse error
            raise ValueError(f"malformed CSV row: {exc}") from exc

        protocol: str | None = None
        if len(row) == 7:
            ms_str, bus, id_hex, _ext_str, _rtr_str, dlc_str, data_hex = (
                col.strip() for col in row
            )
        elif len(row) == 9:
            (
                ms_str,
                bus,
                id_hex,
                _ext_str,
                _rtr_str,
                dlc_str,
                _pgn,
                _sa,
                data_hex,
            ) = (col.strip() for col in row)
        elif len(row) == 10 and entry.column_layout == "10col_protocol":
            (
                ms_str,
                bus,
                id_hex,
                _ext_str,
                _rtr_str,
                dlc_str,
                _pgn,
                _sa,
                protocol,
                data_hex,
            ) = (col.strip() for col in row)
            protocol = protocol or None
        elif len(row) == 10:
            (
                ms_str,
                bus,
                _mode,
                id_hex,
                _ext_str,
                _rtr_str,
                dlc_str,
                _pgn,
                _sa,
                data_hex,
            ) = (col.strip() for col in row)
        else:
            raise ValueError(f"expected 7, 9, or 10 columns, got {len(row)}: {row!r}")

        return BmwFrame(
            frame_id=id_hex.upper(),
            timestamp_ms=int(ms_str),
            bus=bus,
            protocol=protocol,
            dlc=int(dlc_str),
            payload=bytes.fromhex(data_hex.replace("-", "")),
            source=entry,
        )


def parse_all(entries: list[RawLogEntry]) -> tuple[list[BmwFrame], list[str]]:
    """Parse every entry into a BmwFrame, collecting any parse errors."""
    parser = BmwFrameParser()
    frames: list[BmwFrame] = []
    errors: list[str] = []
    for entry in entries:
        try:
            frame = parser.parse(entry)
        except Exception as exc:  # noqa: BLE001 - surfaced per-entry
            errors.append(f"{entry.source_file}:{entry.line_number}: {exc}")
            continue
        if frame is not None:
            frames.append(frame)
    return frames, errors


class BmwStatisticsEngine:
    """Per-CAN-ID traffic + cycle-time statistics."""

    def compute(self, frames: list[BmwFrame]) -> dict[str, BmwCanIdCycleStats]:
        by_id: dict[str, list[BmwFrame]] = {}
        for frame in frames:
            by_id.setdefault(frame.frame_id, []).append(frame)

        stats: dict[str, BmwCanIdCycleStats] = {}
        for frame_id, id_frames in by_id.items():
            id_frames = sorted(id_frames, key=lambda f: f.timestamp_ms)
            timestamps = [f.timestamp_ms for f in id_frames]
            dlcs = [f.dlc for f in id_frames]
            intervals = [b - a for a, b in zip(timestamps, timestamps[1:]) if b >= a]
            stats[frame_id] = BmwCanIdCycleStats(
                frame_id=frame_id,
                count=len(id_frames),
                first_seen_ms=timestamps[0] if timestamps else None,
                last_seen_ms=timestamps[-1] if timestamps else None,
                min_dlc=min(dlcs) if dlcs else None,
                max_dlc=max(dlcs) if dlcs else None,
                median_interval_ms=(
                    statistics.median(intervals) if intervals else None
                ),
                min_interval_ms=min(intervals) if intervals else None,
                max_interval_ms=max(intervals) if intervals else None,
            )
        return stats


class ByteVariabilityAnalyser:
    """Per-byte-offset distinct-value counts for each CAN ID.

    A shape/triage hint only (which byte positions are static vs vary
    across the capture) -- NOT a meaning/name guess. See AGENTS.md: never
    guess PID/DID meaning.
    """

    def analyse(self, frames: list[BmwFrame]) -> list[BmwByteVariability]:
        by_id: dict[str, list[BmwFrame]] = {}
        for frame in frames:
            by_id.setdefault(frame.frame_id, []).append(frame)

        results: list[BmwByteVariability] = []
        for frame_id, id_frames in sorted(by_id.items()):
            max_len = max((len(f.payload) for f in id_frames), default=0)
            for offset in range(max_len):
                values = [
                    f.payload[offset] for f in id_frames if len(f.payload) > offset
                ]
                if not values:
                    continue
                distinct = set(values)
                results.append(
                    BmwByteVariability(
                        frame_id=frame_id,
                        byte_offset=offset,
                        distinct_value_count=len(distinct),
                        min_value=min(values),
                        max_value=max(values),
                        always_constant=len(distinct) == 1,
                    )
                )
        return results


def build_analysis_result(
    frames: list[BmwFrame], parse_errors: list[str], total_entries: int
) -> BmwAnalysisResult:
    canid_stats = BmwStatisticsEngine().compute(frames)
    byte_variability = ByteVariabilityAnalyser().analyse(frames)

    summary = {
        "total_entries": total_entries,
        "total_frames": len(frames),
        "total_errors": len(parse_errors),
        "unique_can_ids": len(canid_stats),
    }

    return BmwAnalysisResult(
        frames=frames,
        canid_stats=canid_stats,
        byte_variability=byte_variability,
        summary=summary,
        errors=parse_errors,
    )


def analyse(entries: list[RawLogEntry]) -> BmwAnalysisResult:
    """Parse and analyse every raw entry in one step."""
    frames, errors = parse_all(entries)
    return build_analysis_result(frames, errors, total_entries=len(entries))
