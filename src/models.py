"""Shared data models for the Decoding 2000 pipeline.

This module intentionally contains no I/O — only data structures used to pass
information between log_reader, frame_analyser, and exporters.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class RawLogEntry:
    """A single raw line/record read from an input log file."""

    line_number: int
    raw_text: str
    source_file: str


@dataclass
class Frame:
    """A decoded frame extracted from one raw log entry.

    Field layout is intentionally generic until a real CAN Sniffer 2000
    capture is inspected — see frame_analyser.FrameParser.
    """

    timestamp: datetime | None
    frame_id: str
    payload: bytes
    fields: dict[str, object] = field(default_factory=dict)
    source: RawLogEntry | None = None
    valid: bool = True
    validation_errors: list[str] = field(default_factory=list)


@dataclass
class CanIdStats:
    """Traffic statistics for a single CAN identifier."""

    frame_id: str
    count: int = 0
    first_timestamp: datetime | None = None
    last_timestamp: datetime | None = None
    min_payload_len: int | None = None
    max_payload_len: int | None = None
    # Raw capture-relative millisecond counter from the log's `ms` column.
    # Preferred over first_timestamp/last_timestamp for this log format since
    # `ms` is not a wall-clock time.
    first_seen_ms: int | None = None
    last_seen_ms: int | None = None


@dataclass
class Session:
    """A logical grouping of related frames (e.g. one contiguous exchange)."""

    frames: list[Frame] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)


@dataclass
class ModuleDiscoveryEntry:
    """One row of the module-discovery ("available modules") report.

    Pairing is derived from the standard ISO 15765-4 physical addressing
    convention actually observed in the capture (response id = request id
    + 8, e.g. 7E0/7E8, 726/72E) plus the standard OBD-II functional
    broadcast id (0x7DF). No vehicle-specific module map is assumed here.
    """

    arbitration_id: str
    role: str  # "request" | "response" | "functional" | "unknown"
    paired_id: str | None
    module_present: bool
    frame_count: int
    positive_response_count: int
    negative_response_count: int
    first_seen_ms: int | None
    last_seen_ms: int | None
    candidate_module_name: str | None = None


@dataclass
class AnalysisResult:
    """The result of analysing a collection of frames."""

    frames: list[Frame] = field(default_factory=list)
    canid_stats: dict[str, CanIdStats] = field(default_factory=dict)
    sessions: list[Session] = field(default_factory=list)
    module_discovery: list[ModuleDiscoveryEntry] = field(default_factory=list)
    summary: dict[str, object] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
