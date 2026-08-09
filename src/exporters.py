"""Writes decoded analysis results to the output/ directory.

Only formatting/writing happens here — no analysis or decoding logic.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from models import AnalysisResult


def export_json(result: AnalysisResult, output_path: Path) -> None:
    """Write frames, CAN-ID stats, and summary to a JSON file."""
    data = {
        "summary": result.summary,
        "errors": result.errors,
        "frames": [
            {
                "frame_id": frame.frame_id,
                "fields": frame.fields,
                "valid": frame.valid,
                "validation_errors": frame.validation_errors,
            }
            for frame in result.frames
        ],
        "can_id_summary": [
            {
                "frame_id": stats.frame_id,
                "count": stats.count,
                "first_seen_ms": stats.first_seen_ms,
                "last_seen_ms": stats.last_seen_ms,
                "min_payload_len": stats.min_payload_len,
                "max_payload_len": stats.max_payload_len,
            }
            for stats in result.canid_stats.values()
        ],
        "module_discovery": [
            {
                "arbitration_id": entry.arbitration_id,
                "role": entry.role,
                "paired_id": entry.paired_id,
                "module_present": entry.module_present,
                "frame_count": entry.frame_count,
                "positive_response_count": entry.positive_response_count,
                "negative_response_count": entry.negative_response_count,
                "first_seen_ms": entry.first_seen_ms,
                "last_seen_ms": entry.last_seen_ms,
                "candidate_module_name": entry.candidate_module_name,
            }
            for entry in result.module_discovery
        ],
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def export_csv(result: AnalysisResult, output_path: Path) -> None:
    """Write cleaned, decoded frames to a CSV file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "frame_id",
                "timestamp_ms",
                "bus",
                "dlc",
                "data_hex",
                "iso_tp_type",
                "uds_service_id",
                "uds_service_name",
                "uds_direction",
                "uds_nrc",
                "valid",
                "validation_errors",
            ]
        )
        for frame in result.frames:
            writer.writerow(
                [
                    frame.frame_id,
                    frame.fields.get("timestamp_ms", ""),
                    frame.fields.get("bus", ""),
                    frame.fields.get("dlc", ""),
                    frame.fields.get("data_hex", ""),
                    frame.fields.get("iso_tp_type", ""),
                    frame.fields.get("uds_service_id") or "",
                    frame.fields.get("uds_service_name") or "",
                    frame.fields.get("uds_direction") or "",
                    frame.fields.get("uds_nrc") or "",
                    frame.valid,
                    "; ".join(frame.validation_errors),
                ]
            )


def export_canid_summary_csv(result: AnalysisResult, output_path: Path) -> None:
    """Write per-CAN-ID traffic statistics to a CSV file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "frame_id",
                "count",
                "first_seen_ms",
                "last_seen_ms",
                "min_payload_len",
                "max_payload_len",
            ]
        )
        for stats in result.canid_stats.values():
            writer.writerow(
                [
                    stats.frame_id,
                    stats.count,
                    stats.first_seen_ms if stats.first_seen_ms is not None else "",
                    stats.last_seen_ms if stats.last_seen_ms is not None else "",
                    stats.min_payload_len,
                    stats.max_payload_len,
                ]
            )


def export_module_discovery_csv(result: AnalysisResult, output_path: Path) -> None:
    """Write the module-discovery ("available modules") table to CSV.

    `candidate_module_name` is filled in for modules confirmed by the
    vehicle owner/technician plus standard OBD-II ids — see
    CONFIRMED_MODULE_NAMES in frame_analyser.py. Unlabeled arbitration ids
    are unidentified, not confirmed absent.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "arbitration_id",
                "role",
                "paired_id",
                "module_present",
                "frame_count",
                "positive_response_count",
                "negative_response_count",
                "first_seen_ms",
                "last_seen_ms",
                "candidate_module_name",
            ]
        )
        for entry in result.module_discovery:
            writer.writerow(
                [
                    entry.arbitration_id,
                    entry.role,
                    entry.paired_id or "",
                    entry.module_present,
                    entry.frame_count,
                    entry.positive_response_count,
                    entry.negative_response_count,
                    entry.first_seen_ms if entry.first_seen_ms is not None else "",
                    entry.last_seen_ms if entry.last_seen_ms is not None else "",
                    entry.candidate_module_name or "",
                ]
            )


def export_telemetry_candidates_csv(result: AnalysisResult, output_path: Path) -> None:
    """Write candidate live-telemetry DIDs to a CSV file.

    These are ReadDataByIdentifier (UDS service 0x22) DIDs whose value
    changed across repeated single-frame reads in the capture -- see
    TelemetryCandidateAnalyser in frame_analyser.py. This flags DIDs worth
    polling for a gauge/telemetry display; it does not claim to know what
    any DID physically represents (units/scaling are not guessed).
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "arbitration_id",
                "did",
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
                    entry.arbitration_id,
                    entry.did,
                    entry.read_count,
                    entry.distinct_value_count,
                    entry.first_seen_ms if entry.first_seen_ms is not None else "",
                    entry.last_seen_ms if entry.last_seen_ms is not None else "",
                    "; ".join(entry.sample_values),
                    entry.possible_name or "",
                    entry.confidence,
                    entry.observed_pattern,
                    entry.notes,
                ]
            )


def export_known_pids_csv(result: AnalysisResult, output_path: Path) -> None:
    """Write the static "known PIDs/DIDs by module" reference table to CSV.

    Rows come from AnalysisResult.known_dids (built by
    build_known_did_reference() in frame_analyser.py from
    DID_NAME_HYPOTHESES/DID_MODULE_HINTS) -- a reference listing, not
    derived from this specific capture's frames. `confidence` distinguishes
    confirmed entries from unconfirmed research hypotheses; see AGENTS.md:
    never guess packet meaning.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "module_name",
                "code_type",
                "request_id",
                "did",
                "possible_name",
                "confidence",
                "notes",
            ]
        )
        for entry in result.known_dids:
            writer.writerow(
                [
                    entry.module_name,
                    entry.code_type,
                    entry.request_id,
                    entry.did,
                    entry.possible_name,
                    entry.confidence,
                    entry.notes,
                ]
            )


def export_report(result: AnalysisResult, output_path: Path) -> None:
    """Write a human-readable engineering summary report."""
    lines = [
        "Decoding 2000 - Engineering Report",
        "=" * 34,
        f"Total log entries:  {result.summary.get('total_entries', 0)}",
        f"Total frames:       {result.summary.get('total_frames', 0)}",
        f"Valid frames:       {result.summary.get('valid_frames', 0)}",
        f"Unique CAN IDs:     {result.summary.get('unique_can_ids', 0)}",
        f"Sessions:           {result.summary.get('total_sessions', 0)}",
        f"Errors:             {result.summary.get('total_errors', 0)}",
        f"Protocols detected: {', '.join(result.summary.get('protocols', [])) or 'none'}",
        "",
        "Top CAN IDs by frame count:",
    ]
    top_ids = sorted(result.canid_stats.values(), key=lambda s: s.count, reverse=True)[:10]
    for stats in top_ids:
        lines.append(f"  {stats.frame_id}: {stats.count} frames")

    if result.module_discovery:
        lines.append("")
        lines.append("Available modules (module-discovery scan):")
        lines.append("  NOTE: candidate_module_name is unlabeled for arbitration ids not yet identified.")
        for entry in result.module_discovery:
            presence = "responded" if entry.module_present else "no response"
            name = f" [{entry.candidate_module_name}]" if entry.candidate_module_name else ""
            paired = f" <-> {entry.paired_id}" if entry.paired_id else ""
            lines.append(
                f"  {entry.arbitration_id}{paired} ({entry.role}): {presence}"
                f" - {entry.frame_count} frames"
                f" ({entry.positive_response_count} pos / "
                f"{entry.negative_response_count} neg){name}"
            )

    if result.known_dids:
        lines.append("")
        lines.append("Known PIDs/DIDs by module:")
        lines.append("  NOTE: [confirmed] entries are field/reference-verified; [hypothesis-*] entries are unconfirmed guesses.")
        lines.append("  NOTE: [DID] = UDS Mode 0x22 ReadDataByIdentifier (Ford-specific); [PID] = standard SAE J1979 Mode 0x01.")
        current_module = None
        for entry in result.known_dids:
            if entry.module_name != current_module:
                current_module = entry.module_name
                lines.append(f"  {entry.module_name} ({entry.request_id}):")
            lines.append(f"    [{entry.code_type}] {entry.did} - {entry.possible_name} [{entry.confidence}]")

    if result.errors:
        lines.append("")
        lines.append("Errors:")
        lines.extend(f"  {err}" for err in result.errors)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
