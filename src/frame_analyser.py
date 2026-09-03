"""Parses, validates, and analyses raw log entries.

Implements the middle stages of the AGENTS.md data flow as small,
independently testable classes:

    FrameParser       -> Frame Parser
    FrameValidator    -> Frame Validation
    IsoTpReassembler  -> Multi-frame ISO-TP reassembly (First/Consecutive)
    StatisticsEngine  -> Statistics Engine
    ProtocolDetector  -> Protocol Detection
    SessionAnalyser   -> Session Analysis

`analyse()` orchestrates all stages and returns an AnalysisResult for
exporters.py to write out.
"""

from __future__ import annotations

import csv

from ford_profiles import FORD_MODULE_PROFILES, FORD_PROFILE_BY_NAME
from models import (
    AnalysisResult,
    CanIdStats,
    Frame,
    KnownDidEntry,
    ModuleDiscoveryEntry,
    RawLogEntry,
    Session,
    SupportedDiagnosticCode,
    TelemetryCandidateEntry,
)

# UDS (ISO 14229) request service IDs. This table is the standardised
# service identifier list from the UDS spec itself — not vehicle-specific —
# so it is safe to rely on without a real capture to confirm it.
UDS_REQUEST_SIDS: dict[int, str] = {
    0x10: "DiagnosticSessionControl",
    0x11: "ECUReset",
    0x14: "ClearDiagnosticInformation",
    0x19: "ReadDTCInformation",
    0x22: "ReadDataByIdentifier",
    0x23: "ReadMemoryByAddress",
    0x27: "SecurityAccess",
    0x28: "CommunicationControl",
    0x2E: "WriteDataByIdentifier",
    0x2F: "InputOutputControlByIdentifier",
    0x31: "RoutineControl",
    0x34: "RequestDownload",
    0x35: "RequestUpload",
    0x36: "TransferData",
    0x37: "RequestTransferExit",
    0x3D: "WriteMemoryByAddress",
    0x3E: "TesterPresent",
    0x85: "ControlDTCSetting",
}
UDS_NEGATIVE_RESPONSE_SID = 0x7F

# UDS classification placeholder used for frames that don't carry a complete
# UDS message on their own (First Frame pending reassembly, Consecutive
# Frame, Flow Control). Copied (not shared) into each frame's fields.
_PENDING_UDS_INFO: dict[str, object] = {
    "uds_service_id": None,
    "uds_service_name": None,
    "uds_direction": "unknown",
    "uds_nrc": None,
}


# Candidate arbitration-id -> module name hints. Confirmed entries below
# come directly from the vehicle owner/technician for this Ford PX2 Ranger
# (not guessed/inferred) plus the id legislated/standardised for OBD-II in
# general (SAE J1979 / ISO 15765-4). Arbitration ids not covered here are
# left unlabeled rather than guessed.
CONFIRMED_MODULE_NAMES: dict[str, str] = {
    "7E0": "PCM",
    "7A7": "FCIM",
    "7E1": "TCM",
    "726": "BdyCM",
    "791": "TRM",
    "737": "RCM",
    "760": "ABS",
    "730": "PSCM",
    "751": "RTM",
    "727": "ACM",
    "724": "SCCM",
    "716": "GWM",
    "706": "IPMA",
    "720": "IPC",
}


def _build_module_name_lookup(confirmed: dict[str, str]) -> dict[str, str]:
    """Expand a request-id -> module-name mapping to also cover the
    ISO 15765-4 paired response id (request + 8), so module-discovery rows
    are labelled regardless of which side of the pair triggered the row.
    """
    lookup: dict[str, str] = {}
    for request_id, name in confirmed.items():
        lookup[request_id] = name
        response_id = f"{int(request_id, 16) + 8:X}"
        lookup[response_id] = name
    return lookup


# Ids NOT yet seen/confirmed in any input/log_*.csv capture from this
# vehicle. Sourced from commaai/opendbc (MIT-licensed, open source; these
# physical request addresses are reverse engineered and have shipped in
# production `openpilot` builds on real Ford vehicles for years), so they
# are a reasonable starting guess for a Ford platform -- but they are NOT
# vehicle-specific to this PX2 Ranger and NOT independently verified
# against a capture from it. Every value is suffixed "(GUESS...)" so it can
# never be mistaken for a CONFIRMED_MODULE_NAMES entry in exported output.
# As real captures confirm/refute one of these ids, move it into (or
# explicitly drop it from) CONFIRMED_MODULE_NAMES above -- do not just
# delete this dict's guess label in place. See AGENTS.md: never guess
# packet meaning; DID_NAME_HYPOTHESES below uses the same pattern for DIDs.
GUESSED_MODULE_NAMES: dict[str, str] = {
    "764": "CCM/fwdRadar (GUESS - unconfirmed on this vehicle, source: opendbc)",
    "732": "GSM/shiftByWire (GUESS - unconfirmed on this vehicle, source: opendbc)",
    "7D0": "APIM/debug (GUESS - unconfirmed on this vehicle, source: opendbc)",
}

CANDIDATE_MODULE_NAMES: dict[str, str] = {
    "7DF": "Functional/broadcast diagnostic request (ISO 15765-4 standard)",
    **_build_module_name_lookup(GUESSED_MODULE_NAMES),
    # Spread after GUESSED_MODULE_NAMES so a real confirmed entry always
    # wins over a guess for the same id.
    **_build_module_name_lookup(CONFIRMED_MODULE_NAMES),
}


class FrameParser:
    """Turns a single raw CSV log entry into a Frame.

    Formats observed so far (verified against real input/*.csv captures):
        7 columns:  ms,bus,id_hex,ext,rtr,dlc,data_hex        (log_001-020)
        7 columns (discovery): x2_ms,scan,bus,direction,id,dlc,data
                    (FORD_003 first 2min dis on IPC.CSV, approved
                    2026-08-20) -- space-separated payload plus explicit
                    scan/direction metadata; no ext/rtr columns.
        10 columns: ms,bus,mode,id_hex,ext,rtr,dlc,pgn,sa,data_hex
                    (log_021 onward, 2026-08-05) -- adds `mode` (e.g.
                    "Listen-Only") and J1939-style `pgn`/`sa` columns, both
                    stored on the Frame but not yet interpreted (`pgn`/`sa`
                    were always "-" in every capture seen so far).
        9 columns:  ms,bus,id_hex,ext,rtr,dlc,pgn,sa,data_hex (log_038-040,
                    2026-08-09) -- same as the 10-column layout but omits
                    `mode` entirely.
        10 columns (BMW): ms,bus,id_hex,ext,rtr,dlc,pgn,sa,protocol,data_hex
                    (input/bmw/log_001.csv, 2026-08-10) -- no `mode`; adds a
                    `protocol` column (e.g. "STD_OBD") right before
                    `data_hex` instead, stored on the Frame but not yet
                    interpreted. Same column COUNT as the log_021-style
                    10-column layout but different meaning/order, so the
                    two are disambiguated via RawLogEntry.column_layout
                    (set from the file's actual header row in
                    log_reader.py), not column count alone.
        11 columns: ms,bus,id_hex,ext,rtr,dlc,pgn,sa,protocol,data_hex,
                    direction (input/ford/log_012 and log_014, approved
                    2026-08-31) -- extends the protocol layout with explicit
                    TX/RX metadata after the payload.

    `data_hex` is dash-separated CAN payload bytes. Byte 0 is decoded as an
    ISO 15765-2 (ISO-TP) PCI byte, and single-frame UDS payloads are further
    decoded via UdsDecoder.
    """

    def __init__(self) -> None:
        self._iso_tp = IsoTpDecoder()
        self._uds = UdsDecoder()

    def parse(self, entry: RawLogEntry) -> Frame | None:
        text = entry.raw_text.strip()
        if not text:
            return None

        try:
            row = next(csv.reader([text]))
        except Exception as exc:  # noqa: BLE001 - surfaced as a parse error
            raise ValueError(f"malformed CSV row: {exc}") from exc

        protocol: str | None = None
        scan: str | None = None
        direction: str | None = None
        if len(row) == 11 and entry.column_layout == "11col_protocol_direction":
            (
                ms_str,
                bus,
                id_hex,
                ext_str,
                rtr_str,
                dlc_str,
                pgn,
                sa,
                protocol,
                data_hex,
                direction,
            ) = (col.strip() for col in row)
            mode = None
            pgn = None if pgn in (None, "", "-") else pgn
            sa = None if sa in (None, "", "-") else sa
            protocol = protocol or None
            direction = direction.upper() or None
        elif len(row) == 7 and entry.column_layout == "7col_discovery":
            ms_str, scan, bus, direction, id_hex, dlc_str, data_hex = (
                col.strip() for col in row
            )
            mode, pgn, sa = None, None, None
            ext_str, rtr_str = "0", "0"
            scan = scan or None
            direction = direction.upper() or None
        elif len(row) == 7:
            ms_str, bus, id_hex, ext_str, rtr_str, dlc_str, data_hex = (
                col.strip() for col in row
            )
            mode, pgn, sa = None, None, None
        elif len(row) == 9:
            (
                ms_str,
                bus,
                id_hex,
                ext_str,
                rtr_str,
                dlc_str,
                pgn,
                sa,
                data_hex,
            ) = (col.strip() for col in row)
            mode = None
            pgn = None if pgn in (None, "", "-") else pgn
            sa = None if sa in (None, "", "-") else sa
        elif len(row) == 10 and entry.column_layout == "10col_protocol":
            (
                ms_str,
                bus,
                id_hex,
                ext_str,
                rtr_str,
                dlc_str,
                pgn,
                sa,
                protocol,
                data_hex,
            ) = (col.strip() for col in row)
            mode = None
            pgn = None if pgn in (None, "", "-") else pgn
            sa = None if sa in (None, "", "-") else sa
            protocol = protocol or None
        elif len(row) == 10:
            (
                ms_str,
                bus,
                mode,
                id_hex,
                ext_str,
                rtr_str,
                dlc_str,
                pgn,
                sa,
                data_hex,
            ) = (col.strip() for col in row)
            mode = mode or None
            pgn = None if pgn in (None, "", "-") else pgn
            sa = None if sa in (None, "", "-") else sa
        else:
            raise ValueError(
                "expected an approved 7, 9, 10, or 11-column layout, "
                f"got {len(row)} columns: {row!r}"
            )


        ms = int(ms_str)
        dlc = int(dlc_str)
        data_bytes = bytes.fromhex(data_hex.replace("-", ""))

        iso_tp_type, iso_tp_len, uds_data = self._iso_tp.decode(data_bytes)

        if iso_tp_type == "single_frame":
            # Full UDS message is available immediately.
            uds_info = self._uds.decode(uds_data)
            uds_data_hex = uds_data.hex(" ").upper() if uds_data else None
        elif iso_tp_type == "first_frame":
            # Only a partial UDS message is available; the rest arrives in
            # later Consecutive Frames. IsoTpReassembler fills in the real
            # uds_service_id/name/direction/nrc once reassembly completes.
            uds_info = _PENDING_UDS_INFO.copy()
            uds_data_hex = uds_data.hex(" ").upper() if uds_data else None
        else:
            # Consecutive Frame / Flow Control / unknown: these carry a raw
            # continuation fragment, not a standalone UDS message, so they
            # are never independently UDS-decoded (IsoTpReassembler consumes
            # them instead).
            uds_info = _PENDING_UDS_INFO.copy()
            uds_data_hex = None

        frame = Frame(
            timestamp=None,
            frame_id=id_hex.upper(),
            payload=data_bytes,
            source=entry,
        )
        frame.fields.update(
            {
                "timestamp_ms": ms,
                "bus": bus,
                "mode": mode,
                "pgn": pgn,
                "sa": sa,
                "protocol": protocol,
                "scan": scan,
                "direction": direction,
                "ext": bool(int(ext_str)),
                "rtr": bool(int(rtr_str)),
                "dlc": dlc,
                "data_hex": data_hex,
                "iso_tp_type": iso_tp_type,
                "iso_tp_len": iso_tp_len,
                "uds_data_hex": uds_data_hex,
                "iso_tp_reassembly_status": None,
                **uds_info,
            }
        )
        return frame


class IsoTpDecoder:
    """Decodes the ISO 15765-2 (ISO-TP) PCI byte from a CAN payload.

    Returns `(iso_tp_type, pci_value, remainder)` where `pci_value` means
    different things per type (as per ISO 15765-2):
      - single_frame:       remaining UDS byte count (SF_DL), 0-7
      - first_frame:        total UDS message length (FF_DL) across all frames
      - consecutive_frame:  sequence number (wraps 0-15, first CF after a
                             First Frame is always 1)
      - flow_control:       flow status (0=ContinueToSend, 1=Wait, 2=Overflow)

    Multi-frame (first_frame/consecutive_frame) reassembly into a full UDS
    message is handled separately by IsoTpReassembler, since it requires
    state carried across several CAN frames.
    """

    def decode(self, data: bytes) -> tuple[str, int | None, bytes | None]:
        if not data:
            return "unknown", None, None

        pci = data[0]
        frame_type = (pci & 0xF0) >> 4

        if frame_type == 0:
            length = pci & 0x0F
            uds = data[1 : 1 + length]
            if len(uds) != length:
                return "single_frame", length, None
            return "single_frame", length, uds
        if frame_type == 1 and len(data) >= 2:
            length = ((pci & 0x0F) << 8) | data[1]
            return "first_frame", length, data[2:]
        if frame_type == 2:
            sequence_number = pci & 0x0F
            return "consecutive_frame", sequence_number, data[1:]
        if frame_type == 3:
            flow_status = pci & 0x0F
            return "flow_control", flow_status, data[1:]
        return "unknown", None, None


class UdsDecoder:
    """Classifies a UDS (ISO 14229) payload extracted from an ISO-TP frame."""

    def decode(self, uds_data: bytes | None) -> dict[str, object]:
        if not uds_data:
            return {
                "uds_service_id": None,
                "uds_service_name": None,
                "uds_direction": "unknown",
                "uds_nrc": None,
            }

        sid = uds_data[0]

        if sid == UDS_NEGATIVE_RESPONSE_SID and len(uds_data) >= 3:
            original_sid = uds_data[1]
            nrc = uds_data[2]
            return {
                "uds_service_id": f"{original_sid:02X}",
                "uds_service_name": UDS_REQUEST_SIDS.get(original_sid),
                "uds_direction": "negative_response",
                "uds_nrc": f"{nrc:02X}",
            }

        if sid in UDS_REQUEST_SIDS:
            return {
                "uds_service_id": f"{sid:02X}",
                "uds_service_name": UDS_REQUEST_SIDS[sid],
                "uds_direction": "request",
                "uds_nrc": None,
            }

        base_sid = sid - 0x40
        if base_sid in UDS_REQUEST_SIDS:
            return {
                "uds_service_id": f"{base_sid:02X}",
                "uds_service_name": UDS_REQUEST_SIDS[base_sid],
                "uds_direction": "positive_response",
                "uds_nrc": None,
            }

        return {
            "uds_service_id": f"{sid:02X}",
            "uds_service_name": None,
            "uds_direction": "unknown",
            "uds_nrc": None,
        }


class IsoTpReassembler:
    """Reassembles multi-frame ISO-TP messages (First Frame + Consecutive
    Frames) into a single UDS payload, verified against real multi-frame
    exchanges in input/log_006.csv (First Frame FF_DL=10 + one Consecutive
    Frame; and FF_DL=43 + six Consecutive Frames) and input/log_001.csv.

    Must be run over an already-parsed, chronologically-ordered list of
    Frame objects (one call to `reassemble()` per capture/source file's
    frames). Once reassembly of a message completes, the final
    uds_service_id/uds_service_name/uds_direction/uds_nrc/uds_data_hex are
    written back onto the First Frame's `fields`. Flow Control frames are
    only marked, not consumed as payload (they carry no UDS bytes).

    Consecutive Frames are placed by their absolute position, using the
    ISO-TP sequence number to find that position rather than assuming arrival
    order — input/log_001.csv (lines 127-128)
    contains two Consecutive Frames logged with swapped sequence numbers at
    the same millisecond timestamp (a logger write-ordering quirk, not a
    bus fault), so reassembling strictly by arrival order corrupts the
    result. This mirrors what any correct ISO-TP receiver does: the
    sequence number exists precisely so reassembly is order-independent.

    Real-capture conditions handled explicitly rather than assumed away:
      - An orphan Consecutive Frame (no active First Frame for its
        (bus, arbitration_id) at that point) — input/log_006.csv line 255 —
        is flagged, not silently dropped or merged.
            - A duplicate or out-of-range sequence number is flagged. Sequence
                numbers may wrap after 15 without colliding with an earlier fragment.
      - A First Frame whose Consecutive Frames never fully arrive by the
        end of the frame list is flagged as incomplete.
    """

    def __init__(self) -> None:
        self._uds = UdsDecoder()

    def reassemble(self, frames: list[Frame]) -> None:
        active: dict[tuple[str | None, object, str], dict[str, object]] = {}

        for frame in frames:
            iso_tp_type = frame.fields.get("iso_tp_type")
            source_file = frame.source.source_file if frame.source else None
            key = (source_file, frame.fields.get("bus"), frame.frame_id)

            if iso_tp_type == "first_frame":
                if key in active:
                    self._mark_incomplete(active.pop(key))
                active[key] = self._start(frame)

            elif iso_tp_type == "consecutive_frame":
                state = active.get(key)
                if state is None:
                    frame.validation_errors.append(
                        "orphan ISO-TP consecutive frame: no active first "
                        "frame for this bus/arbitration id"
                    )
                    frame.valid = False
                    frame.fields["iso_tp_reassembly_status"] = "orphan"
                    continue
                self._consume(state, frame)
                fragments: dict[int, bytes] = state["fragments"]  # type: ignore[assignment]
                expected_count: int = state["expected_count"]  # type: ignore[assignment]
                if expected_count > 0 and all(
                    position in fragments
                    for position in range(1, expected_count + 1)
                ):
                    self._finish(state)
                    del active[key]

            elif iso_tp_type == "flow_control":
                frame.fields["iso_tp_reassembly_status"] = "flow_control"

        for state in active.values():
            self._mark_incomplete(state)

    @staticmethod
    def _start(frame: Frame) -> dict[str, object]:
        total_len: int = frame.fields.get("iso_tp_len") or 0
        partial_hex = frame.fields.get("uds_data_hex")
        partial = bytes.fromhex(partial_hex.replace(" ", "")) if partial_hex else b""
        remaining = max(total_len - len(partial), 0)
        expected_count = (remaining + 6) // 7 if remaining > 0 else 0
        # ISO-TP Consecutive Frame sequence numbers start at 1 and wrap
        # 1..15,0,1,... — the k-th (1-based) Consecutive Frame always has
        # sequence number k % 16, regardless of arrival order.
        expected_seqs = [k % 16 for k in range(1, expected_count + 1)]

        frame.fields["iso_tp_reassembly_status"] = "in_progress"
        return {
            "frame": frame,
            "total_len": total_len,
            "partial": partial,
            "expected_count": expected_count,
            "expected_seqs": expected_seqs,
            "fragments": {},
            "arrival_order": [],
        }

    @staticmethod
    def _consume(state: dict[str, object], frame: Frame) -> None:
        seq = frame.fields.get("iso_tp_len")
        expected_seqs: list[int] = state["expected_seqs"]  # type: ignore[assignment]
        fragments: dict[int, bytes] = state["fragments"]  # type: ignore[assignment]

        matching_positions = [
            position
            for position, expected_seq in enumerate(expected_seqs, start=1)
            if expected_seq == seq and position not in fragments
        ]
        if not matching_positions and seq not in expected_seqs:
            frame.validation_errors.append(
                f"unexpected ISO-TP sequence number: got {seq}, expected "
                f"one of {expected_seqs}"
            )
            frame.valid = False
            frame.fields["iso_tp_reassembly_status"] = "unexpected_sequence"
            return

        if not matching_positions:
            frame.validation_errors.append(
                f"duplicate ISO-TP consecutive frame sequence number: {seq}"
            )
            frame.valid = False
            frame.fields["iso_tp_reassembly_status"] = "duplicate_sequence"
            return

        absolute_position = matching_positions[0]
        fragments[absolute_position] = frame.payload[1:]
        state["arrival_order"].append(absolute_position)  # type: ignore[union-attr]

        in_order = absolute_position == len(state["arrival_order"])  # type: ignore[arg-type]
        frame.fields["iso_tp_reassembly_status"] = (
            "consumed" if in_order else "consumed_out_of_order"
        )

    def _finish(self, state: dict[str, object]) -> None:
        first_frame: Frame = state["frame"]  # type: ignore[assignment]
        total_len: int = state["total_len"]  # type: ignore[assignment]
        partial: bytes = state["partial"]  # type: ignore[assignment]
        expected_seqs: list[int] = state["expected_seqs"]  # type: ignore[assignment]
        fragments: dict[int, bytes] = state["fragments"]  # type: ignore[assignment]

        # Assemble by absolute CF position. The wire sequence number wraps
        # every 16 frames and therefore cannot uniquely identify a fragment.
        buffer = bytearray(partial)
        for position in range(1, len(expected_seqs) + 1):
            buffer.extend(fragments[position])

        full_uds = bytes(buffer[:total_len])
        uds_info = self._uds.decode(full_uds)
        first_frame.fields["uds_data_hex"] = full_uds.hex(" ").upper()
        first_frame.fields.update(uds_info)

        reordered = state["arrival_order"] != list(  # type: ignore[comparison-overlap]
            range(1, len(expected_seqs) + 1)
        )
        first_frame.fields["iso_tp_reassembly_status"] = (
            "complete_reordered" if reordered else "complete"
        )

    @staticmethod
    def _mark_incomplete(state: dict[str, object]) -> None:
        first_frame: Frame = state["frame"]  # type: ignore[assignment]
        total_len: int = state["total_len"]  # type: ignore[assignment]
        partial: bytes = state["partial"]  # type: ignore[assignment]
        fragments: dict[int, bytes] = state["fragments"]  # type: ignore[assignment]
        received = len(partial) + sum(len(f) for f in fragments.values())
        first_frame.validation_errors.append(
            f"incomplete ISO-TP multi-frame message: received {received} of "
            f"{total_len} UDS bytes"
        )
        first_frame.valid = False
        first_frame.fields["iso_tp_reassembly_status"] = "incomplete"


class FrameValidator:
    """Checks a parsed Frame for basic integrity."""

    def validate(self, frame: Frame) -> list[str]:
        errors: list[str] = []
        if not frame.frame_id:
            errors.append("missing frame_id")
        if not frame.payload:
            errors.append("missing payload")

        dlc = frame.fields.get("dlc")
        if dlc is not None and len(frame.payload) != dlc:
            errors.append(
                f"dlc mismatch: dlc={dlc} but payload has {len(frame.payload)} bytes"
            )

        iso_tp_type = frame.fields.get("iso_tp_type")
        iso_tp_len = frame.fields.get("iso_tp_len")
        if iso_tp_type == "single_frame":
            if iso_tp_len is None or iso_tp_len > 7:
                errors.append(f"invalid single-frame length: {iso_tp_len}")
            elif frame.fields.get("uds_data_hex") is None:
                errors.append("single-frame UDS payload truncated/malformed")

        frame.validation_errors = errors
        frame.valid = not errors
        return errors


class StatisticsEngine:
    """Builds per-CAN-ID traffic statistics from a list of frames."""

    def compute(self, frames: list[Frame]) -> dict[str, CanIdStats]:
        stats: dict[str, CanIdStats] = {}
        for frame in frames:
            entry = stats.setdefault(
                frame.frame_id, CanIdStats(frame_id=frame.frame_id)
            )
            entry.count += 1

            payload_len = len(frame.payload) if frame.payload else 0
            entry.min_payload_len = (
                payload_len
                if entry.min_payload_len is None
                else min(entry.min_payload_len, payload_len)
            )
            entry.max_payload_len = (
                payload_len
                if entry.max_payload_len is None
                else max(entry.max_payload_len, payload_len)
            )

            if frame.timestamp is not None:
                if (
                    entry.first_timestamp is None
                    or frame.timestamp < entry.first_timestamp
                ):
                    entry.first_timestamp = frame.timestamp
                if (
                    entry.last_timestamp is None
                    or frame.timestamp > entry.last_timestamp
                ):
                    entry.last_timestamp = frame.timestamp

            timestamp_ms = frame.fields.get("timestamp_ms")
            if timestamp_ms is not None:
                if entry.first_seen_ms is None or timestamp_ms < entry.first_seen_ms:
                    entry.first_seen_ms = timestamp_ms
                if entry.last_seen_ms is None or timestamp_ms > entry.last_seen_ms:
                    entry.last_seen_ms = timestamp_ms

        return stats


class ProtocolDetector:
    """Base class for protocol detectors (J1939, UDS, ISO-TP, etc.)."""

    name = "unknown"

    def matches(self, frames: list[Frame]) -> bool:
        raise NotImplementedError


class UdsIsoTpProtocolDetector(ProtocolDetector):
    """Detects UDS-over-ISO-TP traffic (ISO 14229 / ISO 15765-2)."""

    name = "UDS/ISO-TP (ISO 14229 / ISO 15765-2)"

    def matches(self, frames: list[Frame]) -> bool:
        return any(frame.fields.get("uds_service_id") for frame in frames)


def detect_protocols(
    frames: list[Frame], detectors: list[ProtocolDetector] | None = None
) -> list[str]:
    """Return the names of protocols detected in `frames`."""

    detectors = detectors if detectors is not None else [UdsIsoTpProtocolDetector()]
    return [detector.name for detector in detectors if detector.matches(frames)]


class SessionAnalyser:
    """Groups frames into logical sessions.

    NOTE: Placeholder grouping (one session per source file). Real session
    boundaries (e.g. time gaps, request/response exchanges) depend on the
    real capture format.
    """

    def build_sessions(self, frames: list[Frame]) -> list[Session]:
        sessions_by_source: dict[str, Session] = {}
        order: list[str] = []

        for frame in frames:
            source_file = frame.source.source_file if frame.source else "unknown"
            if source_file not in sessions_by_source:
                sessions_by_source[source_file] = Session()
                order.append(source_file)
            sessions_by_source[source_file].frames.append(frame)

        return [sessions_by_source[key] for key in order]


class ModuleDiscoveryAnalyser:
    """Determines which CAN arbitration IDs represent live/responding modules.

    Pairing uses the ISO 15765-4 physical addressing convention observed
    directly in this capture (response id = request id + 8, e.g. 7E0/7E8,
    726/72E) plus the standard OBD-II functional broadcast id (0x7DF),
    whose responses may come from any physical response id not otherwise
    explained by a direct physical request seen in the log.
    """

    FUNCTIONAL_REQUEST_ID = "7DF"

    def __init__(self, candidate_names: dict[str, str] | None = None) -> None:
        self._candidate_names = candidate_names or {}

    def discover(
        self,
        frames: list[Frame],
        known_dids: list[KnownDidEntry] | None = None,
    ) -> list[ModuleDiscoveryEntry]:
        by_id: dict[str, list[Frame]] = {}
        for frame in frames:
            by_id.setdefault(frame.frame_id, []).append(frame)

        roles = {arb_id: self._role_of(fs) for arb_id, fs in by_id.items()}
        request_ids = {
            arb_id
            for arb_id, role in roles.items()
            if role == "request" and arb_id != self.FUNCTIONAL_REQUEST_ID
        }
        response_ids = {arb_id for arb_id, role in roles.items() if role == "response"}

        def paired_response(req_id: str) -> str | None:
            try:
                candidate = f"{int(req_id, 16) + 8:X}"
            except ValueError:
                return None
            return candidate if candidate in response_ids else None

        explained_responses = {
            resp for req in request_ids if (resp := paired_response(req)) is not None
        }
        unexplained_responses = response_ids - explained_responses

        entries: list[ModuleDiscoveryEntry] = []

        for req_id in sorted(request_ids):
            resp_id = paired_response(req_id)
            count, _, _, first_ms, last_ms = self._stats_for(by_id[req_id])
            # positive/negative counts reflect the paired response frames
            # (if any), since the request's own frames are never responses.
            if resp_id is not None:
                _, pos, neg, _, _ = self._stats_for(by_id[resp_id])
            else:
                pos, neg = 0, 0
            entries.append(
                ModuleDiscoveryEntry(
                    arbitration_id=req_id,
                    role="request",
                    paired_id=resp_id,
                    module_present=resp_id is not None,
                    frame_count=count,
                    positive_response_count=pos,
                    negative_response_count=neg,
                    first_seen_ms=first_ms,
                    last_seen_ms=last_ms,
                    candidate_module_name=self._candidate_names.get(req_id),
                )
            )

        if self.FUNCTIONAL_REQUEST_ID in by_id:
            count, _, _, first_ms, last_ms = self._stats_for(
                by_id[self.FUNCTIONAL_REQUEST_ID]
            )
            # positive/negative counts aggregate the responses that are only
            # explained by this functional broadcast (not any direct request).
            unexplained_frames = [
                f for resp_id in unexplained_responses for f in by_id[resp_id]
            ]
            _, pos, neg, _, _ = self._stats_for(unexplained_frames)
            entries.append(
                ModuleDiscoveryEntry(
                    arbitration_id=self.FUNCTIONAL_REQUEST_ID,
                    role="functional",
                    paired_id=None,
                    module_present=len(unexplained_responses) > 0,
                    frame_count=count,
                    positive_response_count=pos,
                    negative_response_count=neg,
                    first_seen_ms=first_ms,
                    last_seen_ms=last_ms,
                    candidate_module_name=self._candidate_names.get(
                        self.FUNCTIONAL_REQUEST_ID
                    ),
                )
            )

        for resp_id in sorted(unexplained_responses):
            count, pos, neg, first_ms, last_ms = self._stats_for(by_id[resp_id])
            entries.append(
                ModuleDiscoveryEntry(
                    arbitration_id=resp_id,
                    role="response",
                    paired_id=self.FUNCTIONAL_REQUEST_ID
                    if self.FUNCTIONAL_REQUEST_ID in by_id
                    else None,
                    module_present=True,
                    frame_count=count,
                    positive_response_count=pos,
                    negative_response_count=neg,
                    first_seen_ms=first_ms,
                    last_seen_ms=last_ms,
                    candidate_module_name=self._candidate_names.get(resp_id),
                )
            )

        self._attach_supported_codes(entries, by_id, known_dids or [])
        return entries

    @staticmethod
    def _attach_supported_codes(
        entries: list[ModuleDiscoveryEntry],
        by_id: dict[str, list[Frame]],
        known_dids: list[KnownDidEntry],
    ) -> None:
        """Attach positively observed Mode 0x22 DIDs and Mode 0x01 PIDs.

        A positive response proves only that the module supports the code.
        Human-readable metadata comes exclusively from the curated known-DID
        reference and retains its explicit confidence label.
        """
        known = {
            (item.request_id, item.code_type, item.did): item
            for item in known_dids
        }

        for entry in entries:
            if entry.role == "request" and entry.paired_id is not None:
                request_id = entry.arbitration_id
                response_id = entry.paired_id
            elif (
                entry.role == "response"
                and entry.paired_id == ModuleDiscoveryAnalyser.FUNCTIONAL_REQUEST_ID
            ):
                # A functional 0x7DF request has no one-to-one physical
                # request row in the capture.  Attribute each responder's
                # supported codes to that responder and use the observed
                # ISO-TP response=request+8 convention to find any curated
                # metadata for its physical request id.
                response_id = entry.arbitration_id
                request_id = ModuleDiscoveryAnalyser._physical_request_id(
                    response_id
                )
                if request_id is None:
                    continue
            else:
                continue

            observed: set[tuple[str, str]] = set()
            for frame in by_id.get(response_id, []):
                uds_data = ModuleDiscoveryAnalyser._positive_response_payload(frame)
                if uds_data is None:
                    continue
                if len(uds_data) >= 3 and uds_data[0] == 0x62:
                    observed.add(("DID", uds_data[1:3].hex().upper()))
                elif len(uds_data) >= 2 and uds_data[0] == 0x41:
                    observed.add(("PID", f"{uds_data[1]:02X}"))

            for code_type, code in sorted(observed):
                reference = known.get((request_id, code_type, code))
                entry.supported_codes.append(
                    SupportedDiagnosticCode(
                        code_type=code_type,
                        code=code,
                        possible_name=reference.possible_name if reference else "",
                        confidence=reference.confidence if reference else "unidentified",
                        formula=reference.formula if reference else "",
                        unit=reference.unit if reference else "",
                    )
                )

    @staticmethod
    def _role_of(id_frames: list[Frame]) -> str:
        directions = [f.fields.get("uds_direction") for f in id_frames]
        if any(d == "request" for d in directions):
            return "request"
        if any(d in ("positive_response", "negative_response") for d in directions) or any(
            ModuleDiscoveryAnalyser._positive_response_payload(frame) is not None
            for frame in id_frames
        ):
            return "response"
        return "unknown"

    @staticmethod
    def _physical_request_id(response_id: str) -> str | None:
        try:
            request_id = int(response_id, 16) - 8
        except ValueError:
            return None
        return f"{request_id:X}" if request_id >= 0 else None

    @staticmethod
    def _positive_response_payload(frame: Frame) -> bytes | None:
        """Return a supported-code response payload when one is proven.

        A complete UDS response is classified by :class:`UdsDecoder`.  An
        incomplete ISO-TP First Frame cannot be fully decoded, but its
        captured ``62 DID_HI DID_LO`` or ``41 PID`` prefix still proves that
        the addressed module positively answered that code.  The remaining
        bytes are deliberately not interpreted.
        """
        uds_data_hex = frame.fields.get("uds_data_hex")
        if not isinstance(uds_data_hex, str):
            return None
        try:
            uds_data = bytes.fromhex(uds_data_hex)
        except ValueError:
            return None
        if frame.fields.get("uds_direction") == "positive_response":
            return uds_data
        if (
            frame.fields.get("iso_tp_type") == "first_frame"
            and uds_data
            and uds_data[0] in (0x41, 0x62)
        ):
            return uds_data
        return None

    @staticmethod
    def _stats_for(
        id_frames: list[Frame],
    ) -> tuple[int, int, int, int | None, int | None]:
        ms_values = [
            f.fields["timestamp_ms"]
            for f in id_frames
            if f.fields.get("timestamp_ms") is not None
        ]
        positive = sum(
            1
            for f in id_frames
            if ModuleDiscoveryAnalyser._positive_response_payload(f) is not None
        )
        negative = sum(
            1 for f in id_frames if f.fields.get("uds_direction") == "negative_response"
        )
        return (
            len(id_frames),
            positive,
            negative,
            min(ms_values) if ms_values else None,
            max(ms_values) if ms_values else None,
        )


# Research notes for DIDs found by TelemetryCandidateAnalyser, across any
# module (PCM 7E0/7E8, IPC 720/728, etc -- this table is keyed by DID value
# only, not module, since DIDs observed so far have not collided across
# modules). "confirmed" = independently sourced (public Ford Ranger PX2/
# Everest owner community PID database, saeb.net "OBD PID Information"
# forum, archived 2024-07-01) OR user-verified against a real known
# reference (e.g. dash odometer reading), and matches this capture's
# observed byte layout/values. "hypothesis-*" entries are NOT confirmed --
# they are pattern-based guesses (byte size, value drift, clustering with
# confirmed DIDs in the same 03xx/F4xx families) offered only so a human can
# field-test them (e.g. via GreatScan 3.5) against a known reference. Never
# treat a hypothesis entry as ground truth. See AGENTS.md: never guess
# packet meaning.
DID_NAME_HYPOTHESES: dict[str, tuple[str, str, str]] = {
    "03DC": (
        "Fuel Pressure Desired",
        "confirmed",
        "Module PCM (7E0 request -> 7E8 response). Source: user field-"
        "verified against a live scan-tool reading (2026-08-05, "
        "input/log_024.csv): observed min 32.27 MPa / max 88.19 MPa. "
        "Equation: raw (2 bytes) / 100 = MPa. Observed raw range "
        "3227-8819 across the whole capture, exactly matching "
        "3227/100=32.27 and 8819/100=88.19.",
    ),
    "F446": (
        "Ambient Air Temp",
        "confirmed",
        "Source: saeb.net Ford Ranger PX2/Everest community PID list "
        "(module 7E0, mode 22). Equation: raw-40=degC. Also user field-"
        "verified 2026-08-05 against input/log_023.csv (dedicated "
        "polling session, 169 reads): raw 0x3E/0x3F (62/63) -> 22/23 "
        "degC, exactly matching the user's live reading.",
    ),
    "F405": (
        "Coolant Temp",
        "confirmed",
        "Module PCM (7E0 request -> 7E8 response). Source: saeb.net Ford "
        "Ranger PX2/Everest community PID list (module 7E0, mode 22, "
        "same raw-40=degC temp-DID family as confirmed F446/0522). "
        "Equation: raw-40=degC. First observed present 2026-08-10 across "
        "the full input/ corpus: raw range 0x36-0x7F (54-127) -> "
        "14-87 degC, a physically plausible cold-to-warm coolant temp "
        "range. Not yet independently field-verified with a live "
        "reading.",
    ),
    "F40F": (
        "Intake Air Temp",
        "confirmed",
        "Module PCM (7E0 request -> 7E8 response). Source: saeb.net Ford "
        "Ranger PX2/Everest community PID list (module 7E0, mode 22, "
        "same raw-40=degC temp-DID family as confirmed F446/0522). "
        "Equation: raw-40=degC. First observed present 2026-08-10: raw "
        "0x3C/0x45 (60/69) -> 20/29 degC, a plausible intake air temp "
        "reading. Not yet independently field-verified with a live "
        "reading.",
    ),
    "DD05": (
        "Outside/Ambient Air Temp",
        "confirmed",
        "Module PCM (7E0 request -> 7E8 response). Source: saeb.net Ford "
        "Ranger PX2/Everest community PID list (module 7E0, mode 22, "
        "same raw-40=degC temp-DID family as confirmed F446/0522). "
        "Equation: raw-40=degC. NOTE: distinct from the already-confirmed "
        "F446 'Ambient Air Temp' -- saeb.net lists both as separate DIDs "
        "(the vehicle may expose the same/similar signal via two "
        "addresses, same pattern as F45E vs standard PID 0x5E). First "
        "observed present 2026-08-10: raw 0x38/0x3C (56/60) -> 16/20 "
        "degC, plausible ambient temp. Not yet independently field-"
        "verified with a live reading.",
    ),
    "0522": (
        "Fuel Temp",
        "confirmed",
        "Source: saeb.net Ford Ranger PX2/Everest community PID list "
        "(module 7E0, mode 22). Equation: raw-40=degC. Observed constant "
        "raw 0x3D (61) -> 21 degC across input/log_025.csv's dedicated "
        "polling session (2026-08-05), consistent with a stationary/ "
        "cooled-down vehicle.",
    ),
    "0579": (
        "DPF Soot Load (Inferred Closed Loop)",
        "confirmed",
        "Module PCM (7E0 request -> 7E8 response). Source: Ranger Mods "
        "'DPF MY17+ or Everest' and Ford Truck Enthusiasts 'Torque Pro "
        "Ford 6.7L Extended PIDs' discussions: DID 22 0579, equation B, "
        "units %, identified as DPF system percentage of maximum soot "
        "loading (inferred closed loop). Ranger/Everest field reports "
        "describe the value rising toward 88-100% before a regeneration "
        "and falling to approximately 23% while EGT rises. Cross-checked "
        "against local captures: input/log_006.csv response 00 40 -> 64%, "
        "input/log_012.csv 00 43/00 44 -> 67/68%, input/log_024.csv "
        "00 48 -> 72%, and input/log_056.csv plus log_057.csv 00 1E -> "
        "30%. These values match the user-observed normal 20-80% soot "
        "range and are distinct from DID 057B's inferred open-loop value.",
    ),
    "3302": (
        "Steering Wheel Angle",
        "confirmed",
        "Module PSCM (730 request -> 738 response). Equation: "
        "(raw / 10) - 780 = degrees. Confirmed 2026-09-03 from the "
        "controlled center/left/center/right/center steering test. In "
        "input/ford/log_012 headlight off-on-of X3 maby.csv, raw values "
        "1922-13563 convert to -587.8 through +576.3 degrees; the first "
        "value converts to +1.3 degrees, the trace repeatedly returns to "
        "approximately zero between opposite full-lock sweeps, and the "
        "last value converts to +0.9 degrees. Cross-checked against the "
        "public Ford enhanced-PID listing for ABS/PSCM DID 3302 using the "
        "same raw/10-780 equation. Despite its filename, log_012 contains "
        "the PSCM steering data; the file named log_010 polls the TCM.",
    ),
    "61A5": (
        "Corner Lamp / Dash Illumination State",
        "confirmed",
        "Module IPC (720 request -> 728 response). Equation: "
        "(raw & 0x00800000) != 0; unit: state. Confirmed 2026-09-03 by "
        "the user's controlled corner-lamp test in input/ford/log_011 "
        "headlight off-on-of X3 maby.csv. The four-byte response alternates "
        "between 00 00 04 00 (corner lamps off) and 00 80 04 00 (corner "
        "lamps on and dash illumination dimmed), producing exactly six "
        "transitions for three off/on/off cycles. User evidence: 'the "
        "headlight signel is from corner lamps, the IPC dosent have "
        "headlights input , this is the closest i could get ,witch when "
        "the corner lamps come on the dash lights dim'. This is not a "
        "direct headlight-input DID.",
    ),
    "404C": (
        "Total Distance (Odometer)",
        "confirmed",
        "Module IPC (720 request -> 728 response). Source: user field-"
        "verified against the vehicle's dash odometer reading at capture "
        "time (2026-08-05, input/log_028.csv). Equation: raw (3 bytes) / "
        "10 = km. Observed raw 0x1BAF99 = 1814425 -> 181442.5 km "
        "(181442.50 when displayed to two decimal places), matching the "
        "vehicle's ~181,4xx km dash reading. Cross-checked across 4,218 "
        "responses in all captures containing 404C: raw 1811175-1818905 "
        "-> 181117.5-181890.5 km, a continuous physically plausible "
        "odometer progression. The previous raw/1000 equation was two "
        "decimal places too small.",
    ),
    "F45E": (
        "Engine Fuel Rate (Instantaneous Fuel Economy)",
        "confirmed",
        "Module PCM (7E0). Source: saeb.net 'PID Calculator' thread "
        "(2026-08-05 lookup) -- posted DID/header/equation: DID 22 F45E, "
        "header 7E0, equation ((A*256)+B)/20, units L/h, applies to both "
        "2.0l and 3.2l engines. This is a Ford custom UDS Mode 22 DID, "
        "DISTINCT from the standard SAE J1979 Mode 01 PID 0x5E (also "
        "'Engine Fuel Rate', same formula/units) already in "
        "OBD2_PID_NAMES -- the vehicle may expose the same data via "
        "either addressing scheme. Observed in 3,200 responses across "
        "input/log_041.csv through log_054.csv: raw 0-771 -> 0-38.55 "
        "L/h. Cross-check against simultaneous standard PID 0x5E reads "
        "gives a median absolute difference of 0.05 L/h, independently "
        "validating both formulas.",
    ),
    "402A": (
        "Vehicle Battery Voltage (Volts)",
        "confirmed",
        "Module BdyCM (726). Source: saeb.net 'PX1 Alternator Voltage / "
        "Battery Charge Voltage PIDs' thread (2026-08-05 lookup) -- "
        "DID 22 402A, header 726, equation (A/20)+6, units V, resolution "
        "0.05V, range 6-18.75V. Multiple users confirmed this corrected "
        "formula gives realistic readings (an initial A/10.0 guess in "
        "the same thread was wrong). Observed in 4,194 responses: raw "
        "48-172 -> 8.4-14.6V. Cross-check against simultaneous standard "
        "PID 0x42 reads gives a median absolute difference of 0.08V.",
    ),
    "402B": (
        "Vehicle Battery Current",
        "confirmed",
        "Module BdyCM (726). Source: saeb.net 'PX1 Alternator Voltage / "
        "Battery Charge Voltage PIDs' thread (2026-08-05 lookup) -- "
        "DID 22 402B, header 726, equation A-127, units A. Observed in "
        "input/log_048.csv and input/log_055.csv: raw 0x81/0x80 "
        "(129/128) -> +2/+1 A. The formula is publicly sourced; these "
        "captured readings have not been field-verified against a live "
        "current measurement.",
    ),
    "4028": (
        "Vehicle Battery State of Charge (Estimated)",
        "confirmed",
        "Module BdyCM (726). Source: saeb.net 'PX1 Alternator Voltage / "
        "Battery Charge Voltage PIDs' thread (2026-08-05 lookup) -- "
        "DID 22 4028, header 726, equation A, units %, resolution 1%, "
        "range 0-255 (percent, values above 100 not expected in normal "
        "use). User-confirmed working in that thread. Observed in 4,179 "
        "responses across input/log_041.csv through log_055.csv: "
        "raw 75-100 -> 75-100%.",
    ),
    "4029": (
        "Vehicle Battery Temperature (Estimated)",
        "confirmed",
        "Module BdyCM (726). Source: saeb.net 'PX1 Alternator Voltage / "
        "Battery Charge Voltage PIDs' thread (2026-08-05 lookup) -- "
        "DID 22 4029, header 726, equation A-40, units degC, resolution "
        "1 degC, range -40 to 215. User-confirmed working in that "
        "thread. Observed in 3,649 responses across input/log_041.csv "
        "through log_055.csv: raw 57-62 -> 17-22 degC.",
    ),
    "1E1C": (
        "Automatic Transmission Fluid Temp (ATF)",
        "confirmed",
        "Module TCM (7E1 request -> 7E9 response). Equation: "
        "(raw * 5 / 72) - 17 = degC. Confirmed 2026-09-03 from the user's "
        "controlled input/ford/log_008 ATF-Temp 10 degrease to 41 "
        "degrease.csv capture: raw 391-847 converts to 10.15-41.82 degC, "
        "matching the recorded 10-to-41 degree test. This also reconciles "
        "the independent input/log_037.csv field evidence: raw 1236-1255 "
        "converts to 68.83-70.15 degC across the capture containing the "
        "68-69 degC live scan-tool observation. Independently cross-checked "
        "against the saeb.net Ranger/Everest OBDLink PID entry for header "
        "7E1, service 22, DID 1E1C, which gives the same raw*5/72-17 degC "
        "equation. The former raw/10 equation is rejected.",
    ),
    "1E1A": (
        "Transmission Main Fluid Pressure",
        "confirmed",
        "Module TCM (7E1 request -> 7E9 response). Formula: raw; unit: "
        "raw count. Source: user field-confirmed 2026-09-03 for "
        "input/ford/log_010 Steering angle-center-left-center-right-center "
        "X3.csv: 'yea it was Trand main fluid pressure'. The two-byte raw "
        "value ranges from 202 to 523 in that capture. The physical "
        "conversion and engineering unit (for example bar or kPa) remain "
        "unresolved; raw counts must not be presented as scaled pressure.",
    ),
    "1E1D": (
        "Transmission Fluid Temperature Sensor Voltage",
        "confirmed",
        "Module TCM (7E1 request -> 7E9 response). Equation: raw / 1000 "
        "= V. Source: user field-verified 2026-08-17 against a live G-scan "
        "reading captured during input/ford/log_002-TCM.csv. The log's raw "
        "value 478 gives 0.478 V, matching the photographed 0.47 V display "
        "to the scan tool's shown precision. The observed raw range "
        "478-1080 gives a physically plausible 0.478-1.080 V sensor range.",
    ),
    "1E12": (
        "Commanded Gear",
        "confirmed",
        "Module TCM (7E1 request -> 7E9 response). Equation: raw = forward "
        "gear number. Source: user field-verified 2026-08-17 against a live "
        "G-scan reading during input/ford/log_002-TCM.csv: raw 6 matched "
        "the photographed commanded gear 6. Non-forward values remain "
        "unmapped.",
    ),
    "1E23": (
        "Transmission Range Selector Position",
        "confirmed",
        "Module TCM (7E1 request -> 7E9 response). Equation: raw enum: "
        "0x46=P, 0x3C=R, 0x32=N, 0x2E=D, 0x0A=S. Source: user-confirmed "
        "controlled field captures 2026-08-31 in input/ford/log_016 TCM1.csv "
        "and input/ford/log_017 TCM2.csv. Both captures recorded the deliberate "
        "P, R, N, D, S selector sequence and produced the same raw transition "
        "order. TCM1 also repeated 0x2E=D -> 0x0A=S -> 0x2E=D twice; TCM2 "
        "independently repeated the D-to-S transition.",
    ),
    "1E18": (
        "Transmission Sport/Manual Shift Input",
        "confirmed",
        "Module TCM (7E1 request -> 7E9 response). Equation: raw enum: "
        "0x00070000=D, 0x00030000=S, 0x00010000=S-, 0x00020000=S+. "
        "Source: user-confirmed controlled field captures 2026-08-31 in "
        "input/ford/log_016 TCM1.csv and input/ford/log_017 TCM2.csv. In both "
        "captures the four-byte value changed from 00 07 00 00 in D to "
        "00 03 00 00 in S. TCM1, which the user confirmed was the S- test, "
        "recorded momentary 00 01 00 00 pulses before returning to S; TCM2, "
        "confirmed as the S+ test, recorded a momentary 00 02 00 00 pulse "
        "before returning to S.",
    ),
    "1E1B": (
        "Output Shaft Speed",
        "confirmed",
        "Module TCM (7E1 request -> 7E9 response). Equation: raw / 4 = rpm. "
        "Source: user field-verified 2026-08-17 against a live G-scan "
        "reading during input/ford/log_002-TCM.csv: raw 11730 / 4 = "
        "2932.50 rpm, exactly matching the photographed 2932.50 rpm.",
    ),
    "1505": (
        "Vehicle Speed (High Resolution)",
        "confirmed",
        "Observed from both PCM and TCM diagnostic responses. Equation: "
        "raw / 128 = km/h. Source: user field-verified 2026-08-17 against "
        "a live G-scan reading during input/ford/log_002-TCM.csv: raw "
        "15694 / 128 = 122.609375 km/h, matching the photographed "
        "122.61 km/h display.",
    ),
    "F40C": (
        "Engine RPM",
        "confirmed",
        "Observed from both PCM and TCM diagnostic responses. Equation: "
        "raw / 4 = rpm. Source: user field-verified 2026-08-17 against a "
        "live G-scan reading during input/ford/log_002-TCM.csv: raw 8192 / "
        "4 = 2048 rpm, exactly matching the photographed 2048.00 rpm.",
    ),
    "F40D": (
        "Vehicle Speed",
        "confirmed",
        "Observed from both PCM and TCM diagnostic responses. Equation: "
        "raw = km/h. Source: user field-verified 2026-08-17 against live "
        "G-scan readings: input/ford/log_001- PCM.csv contains repeated raw "
        "104 and 109 values matching photographed 104 km/h and 109 km/h; "
        "input/ford/log_002-TCM.csv contains raw 122 matching the "
        "photographed 122 km/h.",
    ),
    "F442": (
        "Control Module Supply Voltage",
        "confirmed",
        "Observed from both PCM and TCM diagnostic responses. Equation: "
        "raw / 1000 = V. Source: user field-verified 2026-08-17 against "
        "live G-scan readings. In input/ford/log_001- PCM.csv, raw 14360 "
        "and 14400 match photographed 14.36 V and 14.40 V; in "
        "input/ford/log_002-TCM.csv, raw 14034 gives 14.034 V, matching "
        "the photographed 14.03 V supply-voltage display.",
    ),
    "1E1F": (
        "Transmission Gear Engaged",
        "confirmed",
        "Module PCM (7E0 request -> 7E8 response). Formula: raw=engaged "
        "forward gear number; unit gear. Source: user field-confirmed that "
        "raw values 3, 4, and 5 track actual 3rd, 4th, and 5th gear changes "
        "in the captured automatic-transmission logs (2026-08-16). "
        "Independently cross-referenced against public Ford PID listings "
        "identifying DID 22 1E1F as Transmission Gear Engaged. Values 0 "
        "and 0x80 remain unmapped and must not be labelled P/R/N without "
        "controlled field evidence.",
    ),
    "03F6": (
        "Exhaust Gas Temp 12 (EGT12) [Post-DPF]",
        "confirmed",
        "Module PCM (7E0 request -> 7E8 response). 1-byte value. Equation: "
        "raw*5=degC. User field reading (2026-08-05, input/log_021.csv): "
        "high ~110 degC, exact match at raw 22 (22*5=110). Cross-checked "
        "across every log containing this DID for consistency: log_006 "
        "raw 3->15degC, log_021 raw 5-22->25-110degC, log_024 raw 23-> "
        "115degC, log_012 raw 56-57->280-285degC, log_013 raw 59-76-> "
        "295-380degC -- a single continuous, physically plausible "
        "cold-to-full-load exhaust temp progression across 5 independent "
        "capture sessions, all fitting raw*5=degC with no exceptions. "
        "Renamed from generic 'Exhaust Temp' to 'EGT12' 2026-08-06: user "
        "confirmed a live 'EGT12' scan-tool reading of 115-120 degC, "
        "exactly matching this DID's already-observed raw 23/24 "
        "(23*5=115, 24*5=120) from input/log_024.csv -- resolves the "
        "earlier open question (saeb.net research, 2026-08-05) of which "
        "specific EGT probe location this DID represents. "
        "POSITION CONFIRMED 2026-08-11 (Post-DPF) via cross-signal "
        "correlation in input/log_052.csv: EGT12 is consistently "
        "equal-to-or-cooler than EGT13/03F5 in every one of 14 sessions "
        "checked (never the reverse -- a reproducible exhaust-path "
        "temperature gradient, not noise). In log_052, a clear DPF active "
        "regen signature was isolated at ts~532819-549919ms: road speed "
        "(OBD PID 0D) held rock-steady 113-115 km/h and RPM (PID 0C) held "
        "steady ~2117-2146 (no acceleration), yet Engine Load (PID 04) "
        "jumped 34%->62% and Fuel Rate (F45E) tripled ~7->23 L/h then "
        "crashed to 1.65 L/h immediately after -- extra fuel burned with "
        "zero corresponding driving-demand change, the classic post-"
        "injection regen signature. EGT12 peaked at ts=546139ms (590 "
        "degC), landing almost exactly on the load/fuel spike's peak "
        "(ts=545338ms), while EGT13 had already peaked earlier "
        "(ts=523521ms, 620 degC) and was declining before the regen fuel "
        "event even started -- EGT12 tracks the regen heat release, "
        "EGT13 does not, placing EGT12 downstream of (after) the DPF. "
        "Corroborated (same steady-speed/steady-RPM + elevated "
        "load/fuel pattern) in input/log_046.csv (speed 110-111 km/h, RPM "
        "2066-2080, load 65.9-84.3%, fuel 15.6-21.1 L/h during its own "
        "EGT12 peak). input/log_051.csv's EGT12 peak was inconclusive "
        "(NOT contradictory) for this check -- that window has genuine "
        "speed/RPM swings (75-86 km/h, RPM 1523-2540) confounding the "
        "steady-cruise isolation technique. CROSS-CHECKED 2026-08-11: MAP/"
        "boost (PID 0B) also spikes hard during log_052's window (84-88 "
        "kPa baseline -> 195 kPa) with ACT (intercooler temp) dropping "
        "30->24 degC at the same time -- i.e. the engine was genuinely "
        "flowing more air/making more power, not just injecting extra "
        "fuel with zero work done. This raised (and has now been ruled "
        "out) an alternative explanation: a road-grade/headwind increase "
        "under cruise control could also produce constant speed/RPM with "
        "higher load/boost, unrelated to DPF regen. User confirmed "
        "2026-08-11 this stretch of driving was steady/flat (no hill), "
        "ruling out the road-grade alternative and reinforcing the regen "
        "interpretation. EGRC (commanded EGR, PID 2C) was also checked and "
        "found NOT to be regen-specific here -- it sits at 0% for a much "
        "broader ~7.7 minute stretch (ts 175624-638136ms) than just the "
        "spike window, so EGR-closed is this log's general highway-cruise "
        "baseline, not a regen signature on its own. NOTE: the underlying "
        "Post-DPF/Pre-DPF position call rests on the 14-session EGT13>= "
        "EGT12 cross-log consistency (structural, independent of any "
        "single event's cause); the log_052 regen narrative is corroborating "
        "context, now field-confirmed as steady driving rather than a "
        "hill/headwind confound. This positional finding is a "
        "data-correlation inference (multi-signal, cross-log, "
        "reproducible) plus this steady-driving field confirmation, not a "
        "live scan-tool reading of physical sensor location -- flagged as "
        "such per AGENTS.md, user-directed confirmation 2026-08-11.",
    ),
    "03F5": (
        "Exhaust Gas Temp 13 (EGT13) [Pre-DPF]",
        "confirmed",
        "Module PCM (7E0 request -> 7E8 response). 1-byte value. Equation: "
        "raw*5=degC (same formula/family as confirmed EGT12 03F6). "
        "User-confirmed 2026-08-06 as EGT13, captured alongside EGT12 in "
        "input/log_012.csv, log_013.csv and log_024.csv -- 03F5 tracks "
        "03F6 almost exactly in every one of those logs, consistently "
        "1-5 raw units higher (a few degrees hotter), matching adjacent "
        "EGT sensor positions on the same exhaust bank: log_012 03F5 "
        "58-62 vs 03F6 56-57, log_013 03F5 61-76 vs 03F6 59-76, log_024 "
        "03F5 24-25 vs 03F6 23. Also present alone (no 03F6) in "
        "input/log_035.csv, raw 23-25 -> 115-125degC. "
        "POSITION CONFIRMED 2026-08-11 (Pre-DPF) via the same cross-signal "
        "correlation documented on EGT12/03F6's entry above (see that "
        "entry for the full evidence chain: EGT13 consistently reads "
        "hotter than EGT12 in all 14 sessions checked, and EGT13's peak "
        "in input/log_052.csv occurred BEFORE the isolated steady-cruise "
        "regen fuel/load event and had already started declining once it "
        "began, whereas EGT12 tracked the regen heat release directly) -- "
        "user-directed confirmation 2026-08-11.",
    ),
    "051C": (
        "Air Charge Temp (Intercooler) [ACT]",
        "confirmed",
        "Source: saeb.net Ford Ranger PX2/Everest community PID list "
        "(module 7E0, mode 22). Equation: raw-40=degC. Observed raw "
        "0x39/0x3A (57/58) -> 17/18 degC, consistent with intercooler temp. "
        "Also field-verified 2026-08-05 against input/log_024.csv: raw "
        "0x48 (72) constant -> 32 degC, matching the user's live reading "
        "exactly.",
    ),
    "9938": (
        "Blower Motor Speed",
        "confirmed",
        "Module FCIM (7A7 request -> 7AF response). 1-byte value, "
        "raw=% directly (no scaling). User field-verified 2026-08-06 "
        "(input/log_034.csv): manually turning the rotary blower speed "
        "dial produced a smooth ramp from raw 0x16 (22) baseline up to "
        "raw 0x52 (82) and back, exactly matching the user's live "
        "reading of the blower cycling 22-82%. The smooth multi-step "
        "ramp (not an instant jump) is expected behaviour for a "
        "hand-turned rotary dial.",
    ),
    "9B03": (
        "Heater Temperature (Blend Door Position)",
        "confirmed",
        "Module FCIM (7A7 request -> 7AF response). 1-byte value, "
        "raw=% directly (no scaling). User field-verified 2026-08-06 "
        "(input/log_034.csv): manually turning the rotary heater temp "
        "dial produced a smooth sweep from raw 0x62 (98) baseline down "
        "to raw 4 and back up to raw 99, matching the user's live "
        "reading of the heater cycling 0-99%.",
    ),
}

# Standard SAE J1979 / ISO 15031 Mode 0x01 ("Show Current Data") PIDs.
# UNLIKE DID_NAME_HYPOTHESES above (Ford-specific UDS Mode 0x22 DIDs), these
# are internationally legislated, publicly standardised PIDs used by every
# OBD-II compliant vehicle -- confirmed by definition, not vehicle-specific
# sourcing, so long as the observed byte layout matches the standard (which
# it does for every PID below, checked against real input/*.csv captures).
# See AGENTS.md: still never invent a PID/formula not in the published
# standard.
OBD2_PID_NAMES: dict[str, tuple[str, str, str]] = {
    "04": (
        "Calculated Engine Load",
        "confirmed",
        "Standard SAE J1979 Mode 01 PID 0x04. Equation: raw*100/255=%. "
        "Observed raw 94-96 in input/log_011.csv -> ~36.9-37.6%, "
        "plausible idle/light-load engine load.",
    ),
    "05": (
        "Engine Coolant Temp",
        "confirmed",
        "Standard SAE J1979 Mode 01 PID 0x05. Equation: raw-40=degC. "
        "Observed constant raw 120 in input/log_010.csv and "
        "input/log_011.csv -> 80 degC, plausible warmed-up coolant temp.",
    ),
    "0C": (
        "Engine RPM",
        "confirmed",
        "Standard SAE J1979 Mode 01 PID 0x0C. Equation: raw/4=rpm (raw is "
        "the 2-byte ((A*256)+B) value). Observed raw 2784-2808 in "
        "input/log_010.csv and input/log_011.csv -> ~696-702 rpm, "
        "plausible diesel idle speed.",
    ),
    "0D": (
        "Vehicle Speed",
        "confirmed",
        "Standard SAE J1979 Mode 01 PID 0x0D. Equation: raw=km/h directly "
        "(no scaling). Observed constant raw 0 in input/log_010.csv and "
        "input/log_011.csv -> 0 km/h, consistent with a stationary vehicle "
        "during those captures.",
    ),
    "0B": (
        "Intake Manifold Absolute Pressure (MAP)",
        "confirmed",
        "Standard SAE J1979 Mode 01 PID 0x0B. Equation: raw=kPa directly "
        "(absolute, no scaling). Source: independently cross-confirmed "
        "against Greatscan 3.5's own working implementation "
        "(lib/Vehicle/src/ford_protocol.cpp, FordPids::INTAKE_MAP, "
        "2026-08-05). Closest standard PID to 'Boost Pressure' for a "
        "turbo-diesel (MAP is absolute pressure, not gauge boost above "
        "atmospheric -- treat as an approximation, not a literal boost "
        "gauge, until a real reading confirms the relationship). OBSERVED "
        "2026-08-10 in input/log_030.csv: idle baseline raw 0x66/0x67 "
        "(102/103 kPa), swinging up to raw 0xDD (221 kPa) during the "
        "capture -- 221-101.3=~120 kPa gauge boost (~17 psi), a real, "
        "physically plausible turbo boost signal with multiple "
        "acceleration pulses, not field-verified against a live reading.",
    ),
    "0F": (
        "Intake Air Temp",
        "confirmed",
        "Standard SAE J1979 Mode 01 PID 0x0F. Equation: raw-40=degC. "
        "Observed in input/log_030.csv and input/log_051.csv from both "
        "PCM and TCM: raw 48-67 -> 8-27 degC, a physically plausible "
        "intake-air temperature range.",
    ),
    "10": (
        "Mass Air Flow (MAF)",
        "confirmed",
        "Standard SAE J1979 Mode 01 PID 0x10. Equation: raw/100=g/s "
        "(raw is the 2-byte ((A*256)+B) value). Observed from PCM in "
        "input/log_030.csv and input/log_051.csv: raw 919-16424 -> "
        "9.19-164.24 g/s, a physically plausible idle-to-load range.",
    ),
    "11": (
        "Absolute Throttle Position",
        "confirmed",
        "Standard SAE J1979 Mode 01 PID 0x11. Equation: raw*100/255=%. "
        "Observed from PCM in input/log_030.csv and input/log_051.csv: "
        "raw 222-255 -> 87.1-100%. This is the standardized absolute "
        "throttle-position value, not a field-verified pedal reading.",
    ),
    "1F": (
        "Run Time Since Engine Start",
        "confirmed",
        "Standard SAE J1979 Mode 01 PID 0x1F. Equation: raw=seconds "
        "(raw is the 2-byte ((A*256)+B) value). Observed from PCM and "
        "TCM across input/log_011.csv, input/log_030.csv, and "
        "input/log_051.csv: 33-1918 seconds.",
    ),
    "21": (
        "Distance Travelled With MIL On",
        "confirmed",
        "Standard SAE J1979 Mode 01 PID 0x21. Equation: raw=km (raw is "
        "the 2-byte ((A*256)+B) value). Observed from PCM and TCM in "
        "input/log_030.csv and input/log_051.csv: raw 0 -> 0 km.",
    ),
    "2C": (
        "Commanded EGR (EGRC)",
        "confirmed",
        "Standard SAE J1979 Mode 01 PID 0x2C. Equation: raw*100/255=%. "
        "Source: independently cross-confirmed against Greatscan 3.5's "
        "own working implementation (lib/Vehicle/src/ford_protocol.cpp, "
        "FordPids::COMMANDED_EGR, 2026-08-05). OBSERVED 2026-08-10 in "
        "input/log_030.csv: raw 0x85 (133) -> 52.2%, not field-verified "
        "against a live reading.",
    ),
    "2D": (
        "EGR Error (EGRE)",
        "confirmed",
        "Standard SAE J1979 Mode 01 PID 0x2D. Equation: (raw-128)*100/128"
        "=%. Source: independently cross-confirmed against Greatscan "
        "3.5's own working implementation (lib/Vehicle/src/"
        "ford_protocol.cpp, FordPids::EGR_ERROR, 2026-08-05). OBSERVED "
        "2026-08-10 in input/log_030.csv: raw 0xBF (191) -> 49.2%, not "
        "field-verified against a live reading.",
    ),
    "31": (
        "Distance Since Diagnostic Trouble Codes Cleared",
        "confirmed",
        "Standard SAE J1979 Mode 01 PID 0x31. Equation: raw=km (raw is "
        "the 2-byte ((A*256)+B) value). Observed from PCM and TCM in "
        "input/log_030.csv and input/log_051.csv: 1965-2253 km.",
    ),
    "33": (
        "Barometric Pressure",
        "confirmed",
        "Standard SAE J1979 Mode 01 PID 0x33. Equation: raw=kPa "
        "directly. Observed from PCM and TCM in input/log_030.csv and "
        "input/log_051.csv: raw 99-101 -> 99-101 kPa, a physically "
        "plausible atmospheric-pressure range.",
    ),
    "2F": (
        "Fuel Tank Level (Fuel Left)",
        "confirmed",
        "Standard SAE J1979 Mode 01 PID 0x2F. Equation: raw*100/255=%. "
        "Source: independently cross-confirmed against Greatscan 3.5's "
        "own working implementation (lib/Vehicle/src/ford_protocol.cpp, "
        "FordPids::FUEL_LEVEL, 2026-08-05). OBSERVED 2026-08-10 in "
        "input/log_030.csv: raw 0xDC (220) -> 86.3%, not field-verified "
        "against a live reading.",
    ),
    "42": (
        "Control Module Voltage (Volts)",
        "confirmed",
        "Standard SAE J1979 Mode 01 PID 0x42. Equation: raw (2 bytes) / "
        "1000 = V. Source: independently cross-confirmed against "
        "Greatscan 3.5's own working implementation (lib/Vehicle/src/"
        "ford_protocol.cpp, FordPids::CONTROL_MODULE_VOLTAGE, "
        "2026-08-05). OBSERVED 2026-08-10 in input/log_030.csv: BOTH PCM "
        "(7E8, raw 0x3824=14372 -> 14.372V) and TCM (7E9, raw "
        "0x36D2=14034 -> 14.034V) independently answered this PID -- two "
        "modules reporting system voltage. Not field-verified against a "
        "live reading.",
    ),
    "46": (
        "Ambient Air Temp",
        "confirmed",
        "Standard SAE J1979 Mode 01 PID 0x46. Equation: raw-40=degC. "
        "Observed from PCM in input/log_030.csv and input/log_051.csv: "
        "raw 46-60 -> 6-20 degC, a physically plausible ambient-air "
        "temperature range.",
    ),
    "59": (
        "Fuel Rail Pressure (absolute)",
        "confirmed",
        "Standard SAE J1979 Mode 01 PID 0x59. Equation: raw (2 bytes) * "
        "10 = kPa. This is the ACTUAL/measured fuel rail pressure, "
        "distinct from the confirmed UDS DID 03DC 'Fuel Pressure "
        "Desired' (target value). Source: independently cross-confirmed "
        "against Greatscan 3.5's own working implementation "
        "(lib/Vehicle/src/ford_protocol.cpp, "
        "FordPids::FUEL_RAIL_PRESSURE_ABS, 2026-08-05). OBSERVED "
        "2026-08-10 in input/log_030.csv: raw 0x0D9A (3482) -> 34.82 MPa "
        "rising to raw 0x0E84 (3716) -> 37.16 MPa, not field-verified "
        "against a live reading.",
    ),
    "5E": (
        "Engine Fuel Rate",
        "confirmed",
        "Standard SAE J1979 Mode 01 PID 0x5E. Equation: raw (2 bytes) * "
        "0.05 = L/h. Source: independently cross-confirmed against "
        "Greatscan 3.5's own working implementation (lib/Vehicle/src/"
        "ford_protocol.cpp, FordPids::ENGINE_FUEL_RATE, 2026-08-05). "
        "OBSERVED 2026-08-10 in input/log_030.csv: raw 0x0010 (16) -> 0.8 "
        "L/h at idle, rising to raw 0x00D8 (216) -> 10.8 L/h under "
        "throttle, not field-verified against a live reading.",
    ),
}

# Module each OBD2_PID_NAMES entry was observed/expected responding from
# (PCM for all standard PIDs on this vehicle -- all Mode 01 requests seen
# so far, and GreatScan 3.5's own module list, address these to 7E0/7E8).
# Every key here must also be a key in OBD2_PID_NAMES.
OBD2_PID_MODULE_HINTS: dict[str, str] = {
    "04": "PCM",
    "05": "PCM",
    "0C": "PCM",
    "0D": "PCM",
    "0B": "PCM",
    "0F": "PCM",
    "10": "PCM",
    "11": "PCM",
    "1F": "PCM",
    "21": "PCM",
    "2C": "PCM",
    "2D": "PCM",
    "2F": "PCM",
    "31": "PCM",
    "33": "PCM",
    "42": "PCM",
    "46": "PCM",
    "59": "PCM",
    "5E": "PCM",
}

# Which module (key into CONFIRMED_MODULE_NAMES) each DID_NAME_HYPOTHESES
# entry was observed under. Every key here must also be a key in
# DID_NAME_HYPOTHESES. Used only to group the "known PIDs/DIDs" reference
# report by module -- see build_known_did_reference() below.
DID_MODULE_HINTS: dict[str, str] = {
    "03DC": "PCM",
    "F446": "PCM",
    "03F6": "PCM",
    "03F5": "PCM",
    "3302": "PSCM",
    "61A5": "IPC",
    "1E1A": "TCM",
    "1E1C": "TCM",
    "1E1D": "TCM",
    "1E12": "TCM",
    "1E23": "TCM",
    "1E18": "TCM",
    "1E1B": "TCM",
    "1505": "TCM",
    "F40C": "TCM",
    "F40D": "TCM",
    "F442": "TCM",
    "1E1F": "PCM",
    "0522": "PCM",
    "0579": "PCM",
    "404C": "IPC",
    "051C": "PCM",
    "F45E": "PCM",
    "402A": "BdyCM",
    "402B": "BdyCM",
    "4028": "BdyCM",
    "4029": "BdyCM",
    "9938": "FCIM",
    "9B03": "FCIM",
    "F405": "PCM",
    "F40F": "PCM",
    "DD05": "PCM",
}

# DIDs explicitly confirmed in more than one physical module.  The legacy
# DID_MODULE_HINTS table retains its primary module for compatibility, while
# this table lets the exported reference use the correct module+DID key.
DID_ADDITIONAL_MODULE_HINTS: dict[str, tuple[str, ...]] = {
    "1505": ("PCM",),
    "F40C": ("PCM",),
    "F40D": ("PCM",),
}

# Structured (formula, unit) pair for every currently-confirmed DID/PID
# above, extracted verbatim from that entry's notes text. This exists
# purely so downstream consumers (e.g. GreatScan 3.5's cross-repo porting
# of confirmed gauges -- see AGENTS.md "System overview") don't have to
# parse the prose `notes` field to find the raw-to-unit equation -- it is
# NOT a separate source of truth. Every key here must also be a
# `confidence="confirmed"` key in DID_NAME_HYPOTHESES or OBD2_PID_NAMES,
# and the formula/unit must match what that entry's notes already say.
DID_PID_FORMULA_UNITS: dict[str, tuple[str, str]] = {
    # DID_NAME_HYPOTHESES (Ford UDS Mode 0x22 DIDs)
    "03DC": ("raw / 100", "MPa"),
    "F446": ("raw - 40", "degC"),
    "F405": ("raw - 40", "degC"),
    "F40F": ("raw - 40", "degC"),
    "DD05": ("raw - 40", "degC"),
    "0522": ("raw - 40", "degC"),
    "0579": ("B", "%"),
    "404C": ("raw / 10", "km"),
    "F45E": ("((A*256)+B) / 20", "L/h"),
    "402A": ("(raw / 20) + 6", "V"),
    "402B": ("raw - 127", "A"),
    "4028": ("raw", "%"),
    "4029": ("raw - 40", "degC"),
    "3302": ("(raw / 10) - 780", "deg"),
    "61A5": ("(raw & 0x00800000) != 0", "state"),
    "03F6": ("raw * 5", "degC"),
    "03F5": ("raw * 5", "degC"),
    "051C": ("raw - 40", "degC"),
    "1E1A": ("raw", "raw count"),
    "1E1C": ("(raw * 5 / 72) - 17", "degC"),
    "1E1F": ("raw", "gear"),
    "1E1D": ("raw / 1000", "V"),
    "1E12": ("raw", "gear"),
    "1E23": (
        "raw enum: 0x46=P, 0x3C=R, 0x32=N, 0x2E=D, 0x0A=S",
        "state",
    ),
    "1E18": (
        "raw enum: 0x00070000=D, 0x00030000=S, 0x00010000=S-, "
        "0x00020000=S+",
        "state",
    ),
    "1E1B": ("raw / 4", "rpm"),
    "1505": ("raw / 128", "km/h"),
    "F40C": ("raw / 4", "rpm"),
    "F40D": ("raw", "km/h"),
    "F442": ("raw / 1000", "V"),
    "9938": ("raw", "%"),
    "9B03": ("raw", "%"),
    # OBD2_PID_NAMES (standard SAE J1979 Mode 0x01 PIDs)
    "04": ("raw * 100 / 255", "%"),
    "05": ("raw - 40", "degC"),
    "0C": ("raw / 4", "rpm"),
    "0D": ("raw", "km/h"),
    "0B": ("raw", "kPa"),
    "0F": ("raw - 40", "degC"),
    "10": ("raw / 100", "g/s"),
    "11": ("raw * 100 / 255", "%"),
    "1F": ("raw", "s"),
    "21": ("raw", "km"),
    "2C": ("raw * 100 / 255", "%"),
    "2D": ("(raw - 128) * 100 / 128", "%"),
    "2F": ("raw * 100 / 255", "%"),
    "31": ("raw", "km"),
    "33": ("raw", "kPa"),
    "42": ("raw / 1000", "V"),
    "46": ("raw - 40", "degC"),
    "59": ("raw * 10", "kPa"),
    "5E": ("raw * 0.05", "L/h"),
}


def build_known_did_reference() -> list[KnownDidEntry]:
    """Build a module-aware Ford PID/DID reference.

    Discovery-supported DIDs start as ``supported_unresolved``.  Curated
    names/formulas are then overlaid only for the module(s) in which they
    were confirmed.  The composite module+DID key prevents common Ford
    identification DIDs from colliding across ECUs.
    """
    by_key: dict[tuple[str, str, str], KnownDidEntry] = {}

    for profile in FORD_MODULE_PROFILES:
        for did in profile.discovered_dids:
            by_key[(profile.name, "DID", did)] = KnownDidEntry(
                module_name=profile.name,
                request_id=profile.request_id,
                response_id=profile.response_id,
                bus=profile.bus,
                did=did,
                possible_name=f"Unknown DID {did}",
                confidence="supported_unresolved",
                notes=(
                    "Positive UDS 0x62 response observed during module discovery; "
                    "meaning, byte layout, scaling and unit are not yet confirmed. "
                    f"Coverage: {profile.discovery_coverage}."
                ),
                code_type="DID",
                supported_status="discovered_supported",
                entry_session=profile.entry_session,
                exit_session=profile.exit_session,
            )

    curated_modules: list[tuple[str, str]] = list(DID_MODULE_HINTS.items())
    curated_modules.extend(
        (did, module_name)
        for did, module_names in DID_ADDITIONAL_MODULE_HINTS.items()
        for module_name in module_names
    )
    for did, module_name in curated_modules:
        possible_name, confidence, notes = DID_NAME_HYPOTHESES.get(
            did, ("(unnamed)", "unidentified", "")
        )
        profile = FORD_PROFILE_BY_NAME.get(module_name)
        request_id = profile.request_id if profile else next(
            (rid for rid, name in CONFIRMED_MODULE_NAMES.items() if name == module_name), "?"
        )
        formula, unit = DID_PID_FORMULA_UNITS.get(did, ("", ""))
        discovered = bool(profile and did in profile.discovered_dids)
        by_key[(module_name, "DID", did)] = KnownDidEntry(
            module_name=module_name,
            request_id=request_id,
            response_id=profile.response_id if profile else "",
            bus=profile.bus if profile else "",
            did=did,
            possible_name=possible_name,
            confidence=confidence,
            notes=notes,
            code_type="DID",
            formula=formula,
            unit=unit,
            supported_status=(
                "discovered_supported_confirmed" if discovered and confidence == "confirmed"
                else "discovered_supported" if discovered
                else "confirmed_gauge" if confidence == "confirmed"
                else "observed_supported_unresolved"
            ),
            entry_session=profile.entry_session if profile else "",
            exit_session=profile.exit_session if profile else "",
        )

    for pid, module_name in OBD2_PID_MODULE_HINTS.items():
        possible_name, confidence, notes = OBD2_PID_NAMES.get(
            pid, ("(unnamed)", "unidentified", "")
        )
        request_id = next(
            (rid for rid, name in CONFIRMED_MODULE_NAMES.items() if name == module_name),
            "?",
        )
        formula, unit = DID_PID_FORMULA_UNITS.get(pid, ("", ""))
        profile = FORD_PROFILE_BY_NAME.get(module_name)
        by_key[(module_name, "PID", pid)] = KnownDidEntry(
                module_name=module_name,
                request_id=request_id,
                response_id=profile.response_id if profile else "",
                bus=profile.bus if profile else "",
                did=pid,
                possible_name=possible_name,
                confidence=confidence,
                notes=notes,
                code_type="PID",
                formula=formula,
                unit=unit,
                supported_status="standard_supported",
                entry_session=profile.entry_session if profile else "",
                exit_session=profile.exit_session if profile else "",
        )
    entries = list(by_key.values())
    entries.sort(key=lambda e: (e.module_name, e.code_type, e.did))
    return entries


def _classify_observed_pattern(ordered_values: list[bytes]) -> str:
    """Classify how a DID's raw byte value moves, purely from the observed
    values themselves -- NOT a claim about what the DID means.

    Returns one of:
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
    ints = [int.from_bytes(v, "big") for v in ordered_values]
    distinct = sorted(set(ints))

    if len(distinct) == 2:
        hamming = bin(distinct[0] ^ distinct[1]).count("1")
        if hamming == 1:
            return "On/Off switch"
        return "Bitfield / multi-switch"

    # Discrete-state check: XOR every distinct value against the most
    # common ("baseline"/idle) value; if the combined set of bits that ever
    # toggle is small, this looks like a handful of flags/states rather
    # than a continuously varying analog reading.
    baseline = max(set(ints), key=ints.count)
    active_bits_mask = 0
    for v in distinct:
        active_bits_mask |= v ^ baseline
    if bin(active_bits_mask).count("1") <= 3 and len(distinct) <= 8:
        return "Bitfield / multi-switch"

    # Ramp/counter check: does the sequence trend consistently in one
    # direction over time (ignoring exact repeats between reads)?
    diffs = [b - a for a, b in zip(ints, ints[1:]) if b != a]
    if diffs:
        positive = sum(1 for d in diffs if d > 0)
        negative = sum(1 for d in diffs if d < 0)
        if positive == 0 or negative == 0:
            return "Ramp / counter"

    return "Sensor (varies)"


class TelemetryCandidateAnalyser:
    """Flags ReadDataByIdentifier (UDS service 0x22) DIDs that are
    candidates for live telemetry/gauge display.

    A DID is flagged only when it was read more than once via a
    single-frame positive response *and* its value changed across those
    reads -- this is observed behaviour in the capture, not an assumption
    about which DIDs carry live data. Multi-frame (first_frame/
    consecutive_frame) responses are excluded: they require ISO-TP flow
    control per read, making them slow/poor candidates for a polled gauge
    regardless of content.

    This does NOT identify what a DID means (units/scaling) on its own --
    only that it is dynamic and worth further correlation testing against
    known ground truth. Optional research hypotheses from DID_NAME_HYPOTHESES
    are attached (clearly labelled, never treated as confirmed) so a human
    can field-test them. See AGENTS.md: never guess packet meaning.
    """

    SERVICE_ID = "22"

    def __init__(self, name_hypotheses: dict[str, tuple[str, str, str]] | None = None) -> None:
        self._name_hypotheses = name_hypotheses if name_hypotheses is not None else DID_NAME_HYPOTHESES

    def discover(self, frames: list[Frame]) -> list[TelemetryCandidateEntry]:
        reads: dict[tuple[str, str], list[tuple[object, str]]] = {}

        for frame in frames:
            if frame.fields.get("uds_service_id") != self.SERVICE_ID:
                continue
            if frame.fields.get("uds_direction") != "positive_response":
                continue
            if frame.fields.get("iso_tp_type") != "single_frame":
                continue

            uds_data_hex = frame.fields.get("uds_data_hex")
            if not uds_data_hex:
                continue
            uds_bytes = bytes.fromhex(uds_data_hex.replace(" ", ""))
            if len(uds_bytes) < 3:
                continue  # 0x62 + 2 DID bytes minimum

            did = uds_bytes[1:3].hex().upper()
            value = uds_bytes[3:].hex(" ").upper()
            key = (frame.frame_id, did)
            reads.setdefault(key, []).append((frame.fields.get("timestamp_ms"), value))

        entries: list[TelemetryCandidateEntry] = []
        for (arb_id, did), values in reads.items():
            distinct = {v for _, v in values}
            if len(values) < 2 or len(distinct) < 2:
                continue  # read once, or never changed -- not a candidate

            timestamps = [ts for ts, _ in values if ts is not None]
            possible_name, confidence, notes = self._name_hypotheses.get(
                did, (None, "unidentified", "")
            )
            ordered = [
                bytes.fromhex(v.replace(" ", ""))
                for _, v in sorted(values, key=lambda tv: (tv[0] is None, tv[0]))
            ]
            entries.append(
                TelemetryCandidateEntry(
                    arbitration_id=arb_id,
                    did=did,
                    read_count=len(values),
                    distinct_value_count=len(distinct),
                    first_seen_ms=min(timestamps) if timestamps else None,
                    last_seen_ms=max(timestamps) if timestamps else None,
                    sample_values=[v for _, v in values[:5]],
                    possible_name=possible_name,
                    confidence=confidence,
                    notes=notes,
                    observed_pattern=_classify_observed_pattern(ordered),
                )
            )

        entries.sort(key=lambda e: (-e.read_count, e.arbitration_id, e.did))
        return entries


def build_analysis_result(
    frames: list[Frame], total_entries: int, errors: list[str] | None = None
) -> AnalysisResult:
    """Build an AnalysisResult (stats/sessions/module-discovery/summary) for
    an already-parsed list of frames.

    Shared by `analyse()` (whole-capture pipeline) and any caller that needs
    the same computed views over a subset of frames (e.g. exporting a single
    source log separately) without duplicating the aggregation logic.
    """

    stats_engine = StatisticsEngine()
    session_analyser = SessionAnalyser()
    module_discovery_analyser = ModuleDiscoveryAnalyser(CANDIDATE_MODULE_NAMES)
    telemetry_candidate_analyser = TelemetryCandidateAnalyser()

    result = AnalysisResult()
    result.frames = frames
    result.errors = list(errors) if errors else []
    result.canid_stats = stats_engine.compute(frames)
    result.sessions = session_analyser.build_sessions(frames)
    result.known_dids = build_known_did_reference()
    result.module_discovery = module_discovery_analyser.discover(
        frames, result.known_dids
    )
    result.telemetry_candidates = telemetry_candidate_analyser.discover(frames)

    result.summary["total_entries"] = total_entries
    result.summary["total_frames"] = len(frames)
    result.summary["valid_frames"] = sum(1 for f in frames if f.valid)
    result.summary["total_errors"] = len(result.errors)
    result.summary["unique_can_ids"] = len(result.canid_stats)
    result.summary["total_sessions"] = len(result.sessions)
    result.summary["protocols"] = detect_protocols(frames)

    return result


def analyse(entries: list[RawLogEntry]) -> AnalysisResult:
    """Run the full parse -> validate -> reassemble -> statistics pipeline."""

    parser = FrameParser()
    validator = FrameValidator()
    reassembler = IsoTpReassembler()

    frames: list[Frame] = []
    parse_errors: list[str] = []

    for entry in entries:
        try:
            frame = parser.parse(entry)
        except Exception as exc:  # noqa: BLE001 - record and continue
            parse_errors.append(f"{entry.source_file}:{entry.line_number}: {exc}")
            continue

        if frame is None:
            continue

        validator.validate(frame)
        frames.append(frame)

    # Multi-frame ISO-TP reassembly needs the full, ordered frame list (a
    # First Frame's Consecutive Frames arrive as later frames), so it runs
    # after per-frame structural validation and may add further errors
    # (orphan/incomplete/out-of-sequence) on top of those.
    reassembler.reassemble(frames)

    errors = list(parse_errors)
    for frame in frames:
        if not frame.valid:
            location = (
                f"{frame.source.source_file}:{frame.source.line_number}"
                if frame.source
                else "unknown"
            )
            errors.extend(f"{location}: {err}" for err in frame.validation_errors)

    return build_analysis_result(frames, len(entries), errors)

