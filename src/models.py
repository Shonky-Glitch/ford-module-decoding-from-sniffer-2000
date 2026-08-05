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
class TelemetryCandidateEntry:
    """A ReadDataByIdentifier (UDS service 0x22) DID whose value changed
    across repeated single-frame reads within a capture -- a candidate for
    live telemetry/gauge display.

    This only flags a DID as dynamic/worth polling further; it does NOT
    infer what the DID means (units/scaling) on its own. `possible_name`/
    `confidence`/`notes` carry an OPTIONAL, clearly-labelled research
    hypothesis (from public reference lookups or byte-pattern reasoning) for
    a human to field-test -- never treat these as confirmed without an
    actual correlation test. See AGENTS.md: never guess packet meaning.
    """

    arbitration_id: str
    did: str
    read_count: int
    distinct_value_count: int
    first_seen_ms: int | None
    last_seen_ms: int | None
    sample_values: list[str] = field(default_factory=list)
    possible_name: str | None = None
    confidence: str = "unidentified"
    notes: str = ""


@dataclass
class KnownDidEntry:
    """One row of the static "known PIDs/DIDs by module" reference table.

    Unlike TelemetryCandidateEntry (built from what a specific capture's
    frames actually show), this is a reference listing of every DID in
    DID_NAME_HYPOTHESES (frame_analyser.py), grouped by the module it was
    observed under -- confirmed entries and research hypotheses alike, each
    clearly labelled via `confidence`. See AGENTS.md: never guess packet
    meaning -- `confidence` must always be shown alongside `possible_name`.

    `code_type` distinguishes a UDS (ISO 14229) Mode 0x22 ReadDataByIdentifier
    `did` ("DID") from a standard SAE J1979/ISO 15031 Mode 0x01 Show-Current-
    Data `pid` ("PID") -- the `did` field holds the raw hex code either way.
    """

    module_name: str
    request_id: str
    did: str
    possible_name: str
    confidence: str
    notes: str = ""
    code_type: str = "DID"


@dataclass
class AnalysisResult:
    """The result of analysing a collection of frames."""

    frames: list[Frame] = field(default_factory=list)
    canid_stats: dict[str, CanIdStats] = field(default_factory=dict)
    sessions: list[Session] = field(default_factory=list)
    module_discovery: list[ModuleDiscoveryEntry] = field(default_factory=list)
    telemetry_candidates: list[TelemetryCandidateEntry] = field(default_factory=list)
    known_dids: list[KnownDidEntry] = field(default_factory=list)
    summary: dict[str, object] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
