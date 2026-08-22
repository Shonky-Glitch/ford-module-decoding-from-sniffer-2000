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
    # Which known CSV header layout this entry's file was detected under
    # (see log_reader.py's CSV_HEADER* constants / COLUMN_LAYOUT_* tags).
    # None means no recognised header was found for this file (legacy
    # behaviour: FrameParser falls back to column-count alone).
    column_layout: str | None = None


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
class SupportedDiagnosticCode:
    """A PID/DID that returned positively from one discovered module.

    Names and scaling are attached only from the curated reference tables;
    an observed positive response by itself proves support, not meaning.
    """

    code_type: str  # "DID" | "PID"
    code: str
    possible_name: str = ""
    confidence: str = "unidentified"
    formula: str = ""
    unit: str = ""


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
    supported_codes: list[SupportedDiagnosticCode] = field(default_factory=list)


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
    `observed_pattern` is a purely shape-based classification of how the
    raw value moves (e.g. "On/Off switch", "Bitfield / multi-switch",
    "Ramp / counter", "Sensor (varies)") derived only from the byte values
    themselves -- it is NOT a claim about what the DID represents.
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
    observed_pattern: str = ""


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
    formula: str = ""
    unit: str = ""
    bus: str = ""
    response_id: str = ""
    supported_status: str = ""
    entry_session: str = ""
    exit_session: str = ""


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


@dataclass
class RawCanFrame:
    """A minimally parsed, OEM-neutral broadcast CAN frame.

    Deliberately NOT a decoded Frame: the source OEM's diagnostic protocol
    is not inferred, so this holds only raw CSV fields -- no ISO-TP/UDS
    interpretation, no module-name/DID lookups. See AGENTS.md: never guess
    the input file format / packet meaning.
    """

    frame_id: str
    timestamp_ms: int
    bus: str
    protocol: str | None
    dlc: int
    payload: bytes
    source: RawLogEntry | None = None


@dataclass
class RawCanIdCycleStats:
    """Traffic and cycle-time statistics for one raw CAN identifier.

    `median_interval_ms` (and min/max) describe the time between
    consecutive frames of this id -- a low, consistent interval suggests a
    periodic broadcast signal; a None/absent value means only one frame was
    seen. Purely descriptive, not a meaning guess.
    """

    frame_id: str
    count: int
    first_seen_ms: int | None
    last_seen_ms: int | None
    min_dlc: int | None
    max_dlc: int | None
    median_interval_ms: float | None
    min_interval_ms: int | None
    max_interval_ms: int | None


@dataclass
class RawCanByteVariability:
    """Per-byte-offset variability for one raw CAN identifier.

    A shape/triage hint only (which byte positions change vs stay
    constant across the capture) -- NOT a meaning/name guess. See
    AGENTS.md: never guess PID/DID meaning.
    """

    frame_id: str
    byte_offset: int
    distinct_value_count: int
    min_value: int
    max_value: int
    always_constant: bool
    observed_pattern: str


@dataclass
class RawCanTelemetryCandidateEntry:
    """A (CAN id, byte offset) worth polling for a live gauge/telemetry
    display -- flagged purely because its value changed across repeated
    reads in the capture. Mirrors frame_analyser.py's
    TelemetryCandidateEntry structurally (for output/report parity with
    the Ford pipeline), but does NOT claim to know what any byte
    physically represents -- no module/signal name or formula exists for
    the source OEM yet (see AGENTS.md).
    """

    frame_id: str
    byte_offset: int
    read_count: int
    distinct_value_count: int
    first_seen_ms: int | None
    last_seen_ms: int | None
    sample_values: list[str]
    observed_pattern: str


@dataclass
class RawCanAnalysisResult:
    """The result of analysing OEM-neutral raw CAN frames."""

    frames: list[RawCanFrame] = field(default_factory=list)
    canid_stats: dict[str, RawCanIdCycleStats] = field(default_factory=dict)
    byte_variability: list[RawCanByteVariability] = field(default_factory=list)
    telemetry_candidates: list[RawCanTelemetryCandidateEntry] = field(default_factory=list)
    summary: dict[str, object] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class KnownRawCanSignal:
    """One independently sourced and capture-validated broadcast CAN signal."""

    frame_id: str
    message_name: str
    signal_name: str
    start_bit: int
    bit_length: int
    byte_order: str
    formula: str
    unit: str
    confidence: str
    notes: str


@dataclass(frozen=True)
class CanSignalDefinition:
    """A curated passive broadcast CAN signal definition."""

    bus: str
    frame_id: str
    signal_name: str
    start_bit: int
    bit_length: int
    byte_order: str
    formula: str
    unit: str
    confidence: str
    evidence: str


@dataclass
class CanSignalCandidate:
    """An observed changing byte region, without an inferred meaning."""

    bus: str
    frame_id: str
    byte_offset: int
    start_bit: int
    bit_length: int
    active_bit_mask: int
    frame_count: int
    distinct_value_count: int
    first_seen_ms: int
    last_seen_ms: int
    sample_values: list[str] = field(default_factory=list)
    observed_pattern: str = ""
    signal_name: str = ""
    confidence: str = "unidentified"
    evidence: str = ""


@dataclass
class CanSignalObservation:
    """One raw value transition for a curated or candidate signal region."""

    bus: str
    frame_id: str
    byte_offset: int
    timestamp_ms: int
    raw_value: int


@dataclass
class CanSignalAnalysisResult:
    """Passive broadcast signal candidates and their observations."""

    candidates: list[CanSignalCandidate] = field(default_factory=list)
    observations: list[CanSignalObservation] = field(default_factory=list)
    definitions: list[CanSignalDefinition] = field(default_factory=list)


# Compatibility aliases for the established BMW pipeline. New OEM pipelines
# use the neutral RawCan* names above.
BmwFrame = RawCanFrame
BmwCanIdCycleStats = RawCanIdCycleStats
BmwByteVariability = RawCanByteVariability
BmwTelemetryCandidateEntry = RawCanTelemetryCandidateEntry
BmwAnalysisResult = RawCanAnalysisResult


