"""Analyse passive broadcast CAN traffic without assigning signal meanings."""

from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path

from bmw_analyser import BmwFrameParser, _classify_observed_pattern
from models import (
    CanSignalAnalysisResult,
    CanSignalCandidate,
    CanSignalDefinition,
    CanSignalObservation,
    RawCanFrame,
    RawLogEntry,
)


DATABASE_COLUMNS = (
    "bus",
    "frame_id",
    "signal_name",
    "start_bit",
    "bit_length",
    "byte_order",
    "formula",
    "unit",
    "confidence",
    "evidence",
)


def load_signal_database(path: Path) -> list[CanSignalDefinition]:
    """Load curated definitions, rejecting unsafe confidence values."""
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != DATABASE_COLUMNS:
            raise ValueError(f"unexpected CAN signal database columns: {reader.fieldnames}")
        definitions: list[CanSignalDefinition] = []
        for line_number, row in enumerate(reader, start=2):
            confidence = row["confidence"].strip().lower()
            if confidence not in {"unidentified", "confirmed"}:
                raise ValueError(
                    f"{path}:{line_number}: confidence must be unidentified or confirmed"
                )
            definitions.append(
                CanSignalDefinition(
                    bus=row["bus"].strip(),
                    frame_id=row["frame_id"].strip().upper(),
                    signal_name=row["signal_name"].strip(),
                    start_bit=int(row["start_bit"]),
                    bit_length=int(row["bit_length"]),
                    byte_order=row["byte_order"].strip(),
                    formula=row["formula"].strip(),
                    unit=row["unit"].strip(),
                    confidence=confidence,
                    evidence=row["evidence"].strip(),
                )
            )
    return definitions


class CanSignalAnalyser:
    """Discover changing byte regions and retain raw transition evidence."""

    def analyse(
        self,
        frames: list[RawCanFrame],
        definitions: list[CanSignalDefinition] | None = None,
    ) -> CanSignalAnalysisResult:
        known = definitions or []
        definition_index = {
            (item.bus, item.frame_id, item.start_bit, item.bit_length): item
            for item in known
        }
        grouped: dict[tuple[str, str], list[RawCanFrame]] = {}
        for frame in frames:
            grouped.setdefault((frame.bus, frame.frame_id), []).append(frame)

        candidates: list[CanSignalCandidate] = []
        observations: list[CanSignalObservation] = []
        for (bus, frame_id), id_frames in sorted(grouped.items()):
            ordered = sorted(id_frames, key=lambda frame: frame.timestamp_ms)
            max_length = max((len(frame.payload) for frame in ordered), default=0)
            for offset in range(max_length):
                reads = [
                    (frame.timestamp_ms, frame.payload[offset])
                    for frame in ordered
                    if len(frame.payload) > offset
                ]
                values = [value for _, value in reads]
                if len(set(values)) < 2:
                    continue
                baseline = Counter(values).most_common(1)[0][0]
                active_mask = 0
                for value in values:
                    active_mask |= baseline ^ value
                definition = definition_index.get((bus, frame_id, offset * 8, 8))
                candidates.append(
                    CanSignalCandidate(
                        bus=bus,
                        frame_id=frame_id,
                        byte_offset=offset,
                        start_bit=offset * 8,
                        bit_length=8,
                        active_bit_mask=active_mask,
                        frame_count=len(reads),
                        distinct_value_count=len(set(values)),
                        first_seen_ms=reads[0][0],
                        last_seen_ms=reads[-1][0],
                        sample_values=[f"{value:02X}" for value in list(dict.fromkeys(values))[:8]],
                        observed_pattern=_classify_observed_pattern(values),
                        signal_name=definition.signal_name if definition else "",
                        confidence=definition.confidence if definition else "unidentified",
                        evidence=definition.evidence if definition else "",
                    )
                )
                previous: int | None = None
                for timestamp_ms, value in reads:
                    if value == previous:
                        continue
                    observations.append(
                        CanSignalObservation(bus, frame_id, offset, timestamp_ms, value)
                    )
                    previous = value

        candidates.sort(key=lambda item: (item.bus, item.frame_id, item.byte_offset))
        observations.sort(
            key=lambda item: (item.timestamp_ms, item.bus, item.frame_id, item.byte_offset)
        )
        return CanSignalAnalysisResult(candidates, observations, known)


def analyse_entries(
    entries: list[RawLogEntry], definitions: list[CanSignalDefinition] | None = None
) -> CanSignalAnalysisResult:
    """Parse approved CSV layouts as opaque CAN frames, then analyse them."""
    parser = BmwFrameParser()
    frames: list[RawCanFrame] = []
    for entry in entries:
        frame = parser.parse(entry)
        if frame is not None:
            frames.append(frame)
    return CanSignalAnalyser().analyse(frames, definitions)
