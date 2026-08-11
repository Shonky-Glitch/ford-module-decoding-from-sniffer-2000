"""Writes BMW analysis results to output/bmw/.

Deliberately does NOT reuse exporters.py's known-PID/module-discovery
sections -- none of that Ford-specific reference data applies to BMW
captures (see AGENTS.md / reference/bmw_ecu_reference.md). Only generic
traffic/shape output is written here.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from models import BmwAnalysisResult


def export_json(result: BmwAnalysisResult, output_path: Path) -> None:
    """Write raw frames, CAN-ID stats, and summary to a JSON file.

    No ISO-TP/UDS fields -- BMW frames are stored as-parsed only (see
    bmw_analyser.py's module docstring).
    """
    data = {
        "summary": result.summary,
        "errors": result.errors,
        "frames": [
            {
                "frame_id": frame.frame_id,
                "timestamp_ms": frame.timestamp_ms,
                "bus": frame.bus,
                "protocol": frame.protocol,
                "dlc": frame.dlc,
                "data_hex": frame.payload.hex(" ").upper(),
            }
            for frame in result.frames
        ],
        "can_id_summary": [
            {
                "frame_id": stats.frame_id,
                "count": stats.count,
                "first_seen_ms": stats.first_seen_ms,
                "last_seen_ms": stats.last_seen_ms,
                "median_interval_ms": stats.median_interval_ms,
            }
            for stats in result.canid_stats.values()
        ],
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def export_csv(result: BmwAnalysisResult, output_path: Path) -> None:
    """Write raw parsed frames to a CSV file (decoded.csv equivalent).

    No ISO-TP/UDS decoding -- just the parsed fields off each row (see
    bmw_analyser.py's module docstring for why).
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            ["frame_id", "timestamp_ms", "bus", "protocol", "dlc", "data_hex"]
        )
        for frame in result.frames:
            writer.writerow(
                [
                    frame.frame_id,
                    frame.timestamp_ms,
                    frame.bus,
                    frame.protocol or "",
                    frame.dlc,
                    frame.payload.hex(" ").upper(),
                ]
            )


def export_telemetry_candidates_csv(
    result: BmwAnalysisResult, output_path: Path
) -> None:
    """Write candidate live-telemetry byte offsets to a CSV file.

    These are (CAN id, byte offset) pairs whose value changed across
    repeated frames in the capture -- see BmwTelemetryCandidateAnalyser in
    bmw_analyser.py. Column layout mirrors Ford's telemetry/candidates.csv
    for parity, but `possible_name`/`confidence` are always
    empty/"unidentified" -- no module/signal name or formula exists for
    BMW yet (see AGENTS.md / reference/bmw_ecu_reference.md).
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "frame_id",
                "byte_offset",
                "read_count",
                "distinct_value_count",
                "first_seen_ms",
                "last_seen_ms",
                "sample_values",
                "possible_name",
                "confidence",
                "observed_pattern",
                "notes",
            ]
        )
        for entry in result.telemetry_candidates:
            writer.writerow(
                [
                    entry.frame_id,
                    entry.byte_offset,
                    entry.read_count,
                    entry.distinct_value_count,
                    entry.first_seen_ms if entry.first_seen_ms is not None else "",
                    entry.last_seen_ms if entry.last_seen_ms is not None else "",
                    "; ".join(entry.sample_values),
                    "",
                    "unidentified",
                    entry.observed_pattern,
                    "",
                ]
            )


def export_can_id_summary_csv(result: BmwAnalysisResult, output_path: Path) -> None:
    """Write per-CAN-ID traffic + cycle-time stats to a CSV file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "frame_id",
                "count",
                "first_seen_ms",
                "last_seen_ms",
                "min_dlc",
                "max_dlc",
                "median_interval_ms",
                "min_interval_ms",
                "max_interval_ms",
            ]
        )
        for stats in sorted(result.canid_stats.values(), key=lambda s: s.frame_id):
            writer.writerow(
                [
                    stats.frame_id,
                    stats.count,
                    stats.first_seen_ms,
                    stats.last_seen_ms,
                    stats.min_dlc,
                    stats.max_dlc,
                    (
                        round(stats.median_interval_ms, 2)
                        if stats.median_interval_ms is not None
                        else ""
                    ),
                    stats.min_interval_ms if stats.min_interval_ms is not None else "",
                    stats.max_interval_ms if stats.max_interval_ms is not None else "",
                ]
            )


def export_byte_variability_csv(result: BmwAnalysisResult, output_path: Path) -> None:
    """Write per-byte-offset variability (shape hint only) to a CSV file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "frame_id",
                "byte_offset",
                "distinct_value_count",
                "min_value",
                "max_value",
                "always_constant",
                "observed_pattern",
            ]
        )
        for entry in result.byte_variability:
            writer.writerow(
                [
                    entry.frame_id,
                    entry.byte_offset,
                    entry.distinct_value_count,
                    entry.min_value,
                    entry.max_value,
                    entry.always_constant,
                    entry.observed_pattern,
                ]
            )


def export_report(result: BmwAnalysisResult, output_path: Path) -> None:
    """Write a plain-text summary report to a text file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "Decoding 2000 - Multi-Vehicle Engineering Report",
        "=" * 60,
        "NOTE: BMW diagnostic addressing/protocol is NOT confirmed for this",
        "project (see reference/bmw_ecu_reference.md). This report is raw",
        "traffic statistics only -- no ISO-TP/UDS decoding, no module names,",
        "no DID/PID interpretation. See AGENTS.md: never guess packet format.",
        "",
        f"Total log entries:  {result.summary.get('total_entries', 0)}",
        f"Total frames:       {result.summary.get('total_frames', 0)}",
        f"Parse errors:       {result.summary.get('total_errors', 0)}",
        f"Unique CAN IDs:     {result.summary.get('unique_can_ids', 0)}",
        "",
        "Top CAN IDs by frame count (id: count, cycle time if periodic):",
    ]
    top_ids = sorted(result.canid_stats.values(), key=lambda s: s.count, reverse=True)
    for stats in top_ids:
        cycle = (
            f", ~{stats.median_interval_ms:.0f}ms cycle"
            if stats.median_interval_ms is not None
            else ""
        )
        lines.append(f"  {stats.frame_id}: {stats.count} frames{cycle}")

    if result.byte_variability:
        lines.append("")
        lines.append(
            "Byte-level shape by CAN ID (offset: distinct/min-max, pattern "
            "-- shape hint only, no meaning/name guessed):"
        )
        by_id: dict[str, list] = {}
        for entry in result.byte_variability:
            by_id.setdefault(entry.frame_id, []).append(entry)
        for frame_id in sorted(by_id):
            lines.append(f"  {frame_id}:")
            for entry in sorted(by_id[frame_id], key=lambda e: e.byte_offset):
                lines.append(
                    f"    byte {entry.byte_offset}: "
                    f"{entry.distinct_value_count} distinct, "
                    f"{entry.min_value}-{entry.max_value}, "
                    f"{entry.observed_pattern}"
                )

    if result.errors:
        lines.append("")
        lines.append("Parse errors:")
        lines.extend(f"  {err}" for err in result.errors)

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
