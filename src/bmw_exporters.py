"""Writes BMW analysis results to output/bmw/.

Deliberately does NOT reuse exporters.py's known-PID/module-discovery
sections -- none of that Ford-specific reference data applies to BMW
captures (see AGENTS.md / reference/bmw_ecu_reference.md). Only generic
traffic/shape output is written here.
"""

from __future__ import annotations

import csv
from pathlib import Path

from models import BmwAnalysisResult


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
                ]
            )


def export_report(result: BmwAnalysisResult, output_path: Path) -> None:
    """Write a plain-text summary report to a text file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "Decoding 2000 - BMW Engineering Report",
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

    if result.errors:
        lines.append("")
        lines.append("Parse errors:")
        lines.extend(f"  {err}" for err in result.errors)

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
