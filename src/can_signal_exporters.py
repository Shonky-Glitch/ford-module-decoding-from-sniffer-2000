"""CSV exports for passive broadcast CAN signal analysis."""

from __future__ import annotations

import csv
from pathlib import Path

from models import CanSignalAnalysisResult


def export_signal_candidates(result: CanSignalAnalysisResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "bus", "frame_id", "byte_offset", "start_bit", "bit_length",
                "active_bit_mask", "frame_count", "distinct_value_count",
                "first_seen_ms", "last_seen_ms", "sample_values",
                "observed_pattern", "signal_name", "confidence", "evidence",
            ]
        )
        for item in result.candidates:
            writer.writerow(
                [
                    item.bus, item.frame_id, item.byte_offset, item.start_bit,
                    item.bit_length, f"0x{item.active_bit_mask:02X}", item.frame_count,
                    item.distinct_value_count, item.first_seen_ms, item.last_seen_ms,
                    "; ".join(item.sample_values), item.observed_pattern,
                    item.signal_name, item.confidence, item.evidence,
                ]
            )


def export_signal_observations(result: CanSignalAnalysisResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["bus", "frame_id", "byte_offset", "timestamp_ms", "raw_value"])
        for item in result.observations:
            writer.writerow(
                [item.bus, item.frame_id, item.byte_offset, item.timestamp_ms, f"0x{item.raw_value:02X}"]
            )
