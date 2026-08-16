"""Parses and analyses OEM-neutral raw CAN capture logs.

Deliberately separate from frame_analyser.py: an OEM's diagnostic protocol
must not be inferred from broadcast traffic. This module treats every frame as
an opaque raw CAN broadcast frame -- id, timestamp, payload bytes -- and
only derives generic traffic/shape statistics (cycle time, per-byte-offset
variability). No module-name or DID/PID interpretation is attached here.
"""

from __future__ import annotations

import csv
import statistics

from models import (
    RawCanAnalysisResult,
    RawCanByteVariability,
    RawCanIdCycleStats,
    RawCanFrame,
    RawCanTelemetryCandidateEntry,
    RawLogEntry,
)


class RawCanFrameParser:
    """Turns a single raw CSV log entry into a RawCanFrame.

    Reuses the same column layouts as log_reader.py/frame_analyser.py
    (7/9/10 columns, disambiguated via RawLogEntry.column_layout for the
    two 10-column variants) but does NOT run any ISO-TP/UDS decoding over
    the payload; diagnostic framing is not assumed.
    """

    def parse(self, entry: RawLogEntry) -> RawCanFrame | None:
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

        return RawCanFrame(
            frame_id=id_hex.upper(),
            timestamp_ms=int(ms_str),
            bus=bus,
            protocol=protocol,
            dlc=int(dlc_str),
            payload=bytes.fromhex(data_hex.replace("-", "")),
            source=entry,
        )


def parse_all(entries: list[RawLogEntry]) -> tuple[list[RawCanFrame], list[str]]:
    """Parse every entry into a RawCanFrame, collecting any parse errors."""
    parser = RawCanFrameParser()
    frames: list[RawCanFrame] = []
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


class RawCanStatisticsEngine:
    """Per-CAN-ID traffic + cycle-time statistics."""

    def compute(self, frames: list[RawCanFrame]) -> dict[str, RawCanIdCycleStats]:
        by_id: dict[str, list[RawCanFrame]] = {}
        for frame in frames:
            by_id.setdefault(frame.frame_id, []).append(frame)

        stats: dict[str, RawCanIdCycleStats] = {}
        for frame_id, id_frames in by_id.items():
            id_frames = sorted(id_frames, key=lambda f: f.timestamp_ms)
            timestamps = [f.timestamp_ms for f in id_frames]
            dlcs = [f.dlc for f in id_frames]
            intervals = [b - a for a, b in zip(timestamps, timestamps[1:]) if b >= a]
            stats[frame_id] = RawCanIdCycleStats(
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


def _classify_observed_pattern(ordered_values: list[int]) -> str:
    """Classify how a single byte offset's value moves over time, purely
    from the observed values themselves -- NOT a claim about what the byte
    means. Mirrors frame_analyser.py's _classify_observed_pattern (kept as
    a separate copy here, not imported, to preserve the Ford/OEM-neutral raw CAN module
    separation described at the top of this file).

    Returns one of:
      "Constant"             -- only one value ever seen (always_constant)
      "On/Off switch"       -- exactly 2 distinct values, differing by 1 bit
      "Bitfield / multi-switch" -- few distinct values, all differing from
                                   the most common value by only a handful
                                   of bits (discrete states/flags)
      "Ramp / counter"       -- distinct values trend consistently in one
                                direction over time (monotonic, allowing
                                repeats)
      "Sensor (varies)"      -- fallback: many/irregular distinct values
                                with no bitfield or monotonic pattern
    """
    distinct = sorted(set(ordered_values))

    if len(distinct) == 1:
        return "Constant"

    if len(distinct) == 2:
        hamming = bin(distinct[0] ^ distinct[1]).count("1")
        if hamming == 1:
            return "On/Off switch"
        return "Bitfield / multi-switch"

    baseline = max(set(ordered_values), key=ordered_values.count)
    active_bits_mask = 0
    for v in distinct:
        active_bits_mask |= v ^ baseline
    if bin(active_bits_mask).count("1") <= 3 and len(distinct) <= 8:
        return "Bitfield / multi-switch"

    diffs = [b - a for a, b in zip(ordered_values, ordered_values[1:]) if b != a]
    if diffs:
        positive = sum(1 for d in diffs if d > 0)
        negative = sum(1 for d in diffs if d < 0)
        if positive == 0 or negative == 0:
            return "Ramp / counter"

    return "Sensor (varies)"


class ByteVariabilityAnalyser:
    """Per-byte-offset distinct-value counts for each CAN ID.

    A shape/triage hint only (which byte positions are static vs vary
    across the capture) -- NOT a meaning/name guess. See AGENTS.md: never
    guess PID/DID meaning.
    """

    def analyse(self, frames: list[RawCanFrame]) -> list[RawCanByteVariability]:
        by_id: dict[str, list[RawCanFrame]] = {}
        for frame in frames:
            by_id.setdefault(frame.frame_id, []).append(frame)

        results: list[RawCanByteVariability] = []
        for frame_id, id_frames in sorted(by_id.items()):
            id_frames = sorted(id_frames, key=lambda f: f.timestamp_ms)
            max_len = max((len(f.payload) for f in id_frames), default=0)
            for offset in range(max_len):
                values = [
                    f.payload[offset] for f in id_frames if len(f.payload) > offset
                ]
                if not values:
                    continue
                distinct = set(values)
                results.append(
                    RawCanByteVariability(
                        frame_id=frame_id,
                        byte_offset=offset,
                        distinct_value_count=len(distinct),
                        min_value=min(values),
                        max_value=max(values),
                        always_constant=len(distinct) == 1,
                        observed_pattern=_classify_observed_pattern(values),
                    )
                )
        return results


class RawCanTelemetryCandidateAnalyser:
    """Flags (CAN id, byte offset) pairs worth polling for a live gauge/
    telemetry display -- mirrors frame_analyser.py's
    TelemetryCandidateAnalyser structurally, for output/report parity with
    the Ford pipeline, but with no DID/service framing (OEM-neutral raw CAN frames are
    plain broadcast traffic, not request/response) and no name/formula
    guessed. A byte offset is flagged only when it took more than one
    value across the capture -- purely observed behaviour, not an
    assumption about which bytes carry live data.
    """

    def discover(self, frames: list[RawCanFrame]) -> list[RawCanTelemetryCandidateEntry]:
        by_id: dict[str, list[RawCanFrame]] = {}
        for frame in frames:
            by_id.setdefault(frame.frame_id, []).append(frame)

        entries: list[RawCanTelemetryCandidateEntry] = []
        for frame_id, id_frames in by_id.items():
            id_frames = sorted(id_frames, key=lambda f: f.timestamp_ms)
            max_len = max((len(f.payload) for f in id_frames), default=0)
            for offset in range(max_len):
                reads = [
                    (f.timestamp_ms, f.payload[offset])
                    for f in id_frames
                    if len(f.payload) > offset
                ]
                if not reads:
                    continue
                values = [v for _, v in reads]
                distinct = set(values)
                if len(reads) < 2 or len(distinct) < 2:
                    continue  # read once, or never changed -- not a candidate

                timestamps = [ts for ts, _ in reads]
                entries.append(
                    RawCanTelemetryCandidateEntry(
                        frame_id=frame_id,
                        byte_offset=offset,
                        read_count=len(reads),
                        distinct_value_count=len(distinct),
                        first_seen_ms=min(timestamps),
                        last_seen_ms=max(timestamps),
                        sample_values=[f"{v:02X}" for v in values[:5]],
                        observed_pattern=_classify_observed_pattern(values),
                    )
                )

        entries.sort(key=lambda e: (-e.read_count, e.frame_id, e.byte_offset))
        return entries


def build_analysis_result(
    frames: list[RawCanFrame], parse_errors: list[str], total_entries: int
) -> RawCanAnalysisResult:
    canid_stats = RawCanStatisticsEngine().compute(frames)
    byte_variability = ByteVariabilityAnalyser().analyse(frames)
    telemetry_candidates = RawCanTelemetryCandidateAnalyser().discover(frames)

    summary = {
        "total_entries": total_entries,
        "total_frames": len(frames),
        "total_errors": len(parse_errors),
        "unique_can_ids": len(canid_stats),
    }

    return RawCanAnalysisResult(
        frames=frames,
        canid_stats=canid_stats,
        byte_variability=byte_variability,
        telemetry_candidates=telemetry_candidates,
        summary=summary,
        errors=parse_errors,
    )


def analyse(entries: list[RawLogEntry]) -> RawCanAnalysisResult:
    """Parse and analyse every raw entry in one step."""
    frames, errors = parse_all(entries)
    return build_analysis_result(frames, errors, total_entries=len(entries))

