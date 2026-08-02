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

from models import (
    AnalysisResult,
    CanIdStats,
    Frame,
    ModuleDiscoveryEntry,
    RawLogEntry,
    Session,
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


CANDIDATE_MODULE_NAMES: dict[str, str] = {
    "7DF": "Functional/broadcast diagnostic request (ISO 15765-4 standard)",
    **_build_module_name_lookup(CONFIRMED_MODULE_NAMES),
}


class FrameParser:
    """Turns a single raw CSV log entry into a Frame.

    Real CAN Sniffer 2000 capture format (verified against input/log_*.csv):
        ms,bus,id_hex,ext,rtr,dlc,data_hex

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

        if len(row) != 7:
            raise ValueError(f"expected 7 columns, got {len(row)}: {row!r}")

        ms_str, bus, id_hex, ext_str, rtr_str, dlc_str, data_hex = (
            col.strip() for col in row
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

    Consecutive Frames are placed by their ISO-TP sequence number rather
    than assumed to arrive in order — input/log_001.csv (lines 127-128)
    contains two Consecutive Frames logged with swapped sequence numbers at
    the same millisecond timestamp (a logger write-ordering quirk, not a
    bus fault), so reassembling strictly by arrival order corrupts the
    result. This mirrors what any correct ISO-TP receiver does: the
    sequence number exists precisely so reassembly is order-independent.

    Real-capture conditions handled explicitly rather than assumed away:
      - An orphan Consecutive Frame (no active First Frame for its
        (bus, arbitration_id) at that point) — input/log_006.csv line 255 —
        is flagged, not silently dropped or merged.
      - A duplicate or out-of-range sequence number is flagged.
      - A First Frame whose Consecutive Frames never fully arrive by the
        end of the frame list is flagged as incomplete.
    """

    def __init__(self) -> None:
        self._uds = UdsDecoder()

    def reassemble(self, frames: list[Frame]) -> None:
        active: dict[tuple[object, str], dict[str, object]] = {}

        for frame in frames:
            iso_tp_type = frame.fields.get("iso_tp_type")
            key = (frame.fields.get("bus"), frame.frame_id)

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
                if expected_count > 0 and len(fragments) >= expected_count:
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

        if seq not in expected_seqs:
            frame.validation_errors.append(
                f"unexpected ISO-TP sequence number: got {seq}, expected "
                f"one of {expected_seqs}"
            )
            frame.valid = False
            frame.fields["iso_tp_reassembly_status"] = "unexpected_sequence"
            return

        if seq in fragments:
            frame.validation_errors.append(
                f"duplicate ISO-TP consecutive frame sequence number: {seq}"
            )
            frame.valid = False
            frame.fields["iso_tp_reassembly_status"] = "duplicate_sequence"
            return

        fragments[seq] = frame.payload[1:]
        state["arrival_order"].append(seq)  # type: ignore[union-attr]

        in_order = len(state["arrival_order"]) <= 1 or seq == expected_seqs[  # type: ignore[index]
            len(state["arrival_order"]) - 1  # type: ignore[arg-type]
        ]
        frame.fields["iso_tp_reassembly_status"] = (
            "consumed" if in_order else "consumed_out_of_order"
        )

    def _finish(self, state: dict[str, object]) -> None:
        first_frame: Frame = state["frame"]  # type: ignore[assignment]
        total_len: int = state["total_len"]  # type: ignore[assignment]
        partial: bytes = state["partial"]  # type: ignore[assignment]
        expected_seqs: list[int] = state["expected_seqs"]  # type: ignore[assignment]
        fragments: dict[int, bytes] = state["fragments"]  # type: ignore[assignment]

        # Assembled strictly by sequence number, not arrival order.
        buffer = bytearray(partial)
        for seq in expected_seqs:
            buffer.extend(fragments[seq])

        full_uds = bytes(buffer[:total_len])
        uds_info = self._uds.decode(full_uds)
        first_frame.fields["uds_data_hex"] = full_uds.hex(" ").upper()
        first_frame.fields.update(uds_info)

        reordered = state["arrival_order"] != expected_seqs  # type: ignore[comparison-overlap]
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

    def discover(self, frames: list[Frame]) -> list[ModuleDiscoveryEntry]:
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

        return entries

    @staticmethod
    def _role_of(id_frames: list[Frame]) -> str:
        directions = [f.fields.get("uds_direction") for f in id_frames]
        if any(d == "request" for d in directions):
            return "request"
        if any(d in ("positive_response", "negative_response") for d in directions):
            return "response"
        return "unknown"

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
            1 for f in id_frames if f.fields.get("uds_direction") == "positive_response"
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

    result = AnalysisResult()
    result.frames = frames
    result.errors = list(errors) if errors else []
    result.canid_stats = stats_engine.compute(frames)
    result.sessions = session_analyser.build_sessions(frames)
    result.module_discovery = module_discovery_analyser.discover(frames)

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

