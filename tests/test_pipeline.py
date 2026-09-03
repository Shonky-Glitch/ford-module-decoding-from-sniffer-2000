"""Basic tests for the Decoding 2000 pipeline."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from frame_analyser import (  # noqa: E402
    DID_NAME_HYPOTHESES,
    DID_PID_FORMULA_UNITS,
    FrameParser,
        OBD2_PID_NAMES,
    FrameValidator,
    IsoTpDecoder,
    IsoTpReassembler,
    ModuleDiscoveryAnalyser,
    SessionAnalyser,
    StatisticsEngine,
    TelemetryCandidateAnalyser,
    UdsDecoder,
    analyse,
    build_known_did_reference,
)
from bmw_analyser import BmwFrameParser  # noqa: E402
from ford_profiles import FORD_MODULE_PROFILES, FORD_PROFILE_BY_NAME  # noqa: E402
from log_reader import (  # noqa: E402
    CSV_HEADER,
    CSV_HEADER_DISCOVERY,
    CSV_HEADER_PROTOCOL_DIRECTION,
    read_log_file,
)
from hyundai_signals import HYUNDAI_CAN_ID_NAMES, HYUNDAI_CONFIRMED_SIGNALS  # noqa: E402
from models import (  # noqa: E402
    KnownDidEntry,
    RawLogEntry,
)
from raw_can_analyser import RawCanFrameParser, analyse as analyse_raw_can  # noqa: E402


def test_analyse_empty_entries_returns_empty_result():
    result = analyse([])
    assert result.frames == []
    assert result.errors == []
    assert result.summary["total_entries"] == 0
    assert result.summary["total_frames"] == 0
    assert result.summary["unique_can_ids"] == 0
    assert result.summary["total_sessions"] == 0


def _entry(raw_text: str, line_number: int = 1) -> RawLogEntry:
    return RawLogEntry(line_number=line_number, raw_text=raw_text, source_file="log_005.csv")


def test_raw_can_parser_preserves_extended_protocol_metadata_without_decoding():
    entry = RawLogEntry(
        line_number=2,
        raw_text=(
            "46701,CAN1,4F0,0,0,8,-,-,FORD_UDS22,"
            "00-00-00-00-00-00-00-00"
        ),
        source_file="log_001.csv",
        column_layout="10col_protocol",
    )
    frame = RawCanFrameParser().parse(entry)

    assert frame is not None
    assert frame.frame_id == "4F0"
    assert frame.protocol == "FORD_UDS22"
    assert frame.payload == bytes(8)


def test_raw_can_analysis_does_not_assign_pid_or_module_meanings():
    entries = [
        RawLogEntry(1, "1,CAN1,100,0,0,8,00-00-00-00-00-00-00-00", "x.csv"),
        RawLogEntry(2, "2,CAN1,100,0,0,8,01-00-00-00-00-00-00-00", "x.csv"),
    ]
    result = analyse_raw_can(entries)

    assert result.summary["total_frames"] == 2
    assert result.telemetry_candidates[0].frame_id == "100"
    assert result.telemetry_candidates[0].byte_offset == 0
    assert result.telemetry_candidates[0].observed_pattern == "On/Off switch"


def test_hyundai_confirmed_signals_are_evidence_limited():
    signals = {(entry.frame_id, entry.signal_name) for entry in HYUNDAI_CONFIRMED_SIGNALS}

    assert len(signals) == 9
    assert ("316", "Engine Speed") in signals
    assert ("545", "Module Voltage") in signals
    assert ("43F", "Current Gear") not in signals
    assert ("5A2", "Unknown") not in signals
    assert all(entry.confidence == "confirmed" for entry in HYUNDAI_CONFIRMED_SIGNALS)


def test_hyundai_can_id_names_cover_the_observed_capture_ids():
    assert len(HYUNDAI_CAN_ID_NAMES) == 17
    assert HYUNDAI_CAN_ID_NAMES["316"][0] == "EMS1"
    assert HYUNDAI_CAN_ID_NAMES["316"][2] == "confirmed"
    assert HYUNDAI_CAN_ID_NAMES["43F"][0] == "TCU1"
    assert HYUNDAI_CAN_ID_NAMES["5A2"][2] == "unidentified"


def test_frame_parser_decodes_single_frame_uds_request():
    # Real row from input/log_005.csv: DiagnosticSessionControl request to 7E0.
    entry = _entry("100949,CAN1,7E0,0,0,8,02-10-03-00-00-00-00-00")
    frame = FrameParser().parse(entry)

    assert frame is not None
    assert frame.frame_id == "7E0"
    assert frame.fields["timestamp_ms"] == 100949
    assert frame.fields["bus"] == "CAN1"
    assert frame.fields["dlc"] == 8
    assert frame.fields["iso_tp_type"] == "single_frame"
    assert frame.fields["uds_service_id"] == "10"
    assert frame.fields["uds_service_name"] == "DiagnosticSessionControl"
    assert frame.fields["uds_direction"] == "request"


def test_frame_parser_decodes_positive_response():
    # Real row from input/log_005.csv: positive response to the above request.
    entry = _entry("100958,CAN1,7E8,0,0,8,06-50-03-00-32-01-F4-00")
    frame = FrameParser().parse(entry)

    assert frame is not None
    assert frame.frame_id == "7E8"
    assert frame.fields["uds_service_id"] == "10"
    assert frame.fields["uds_direction"] == "positive_response"


def test_iso_tp_decoder_single_frame():
    decoder = IsoTpDecoder()
    frame_type, length, uds_data = decoder.decode(bytes.fromhex("02100300000000"))
    assert frame_type == "single_frame"
    assert length == 2
    assert uds_data == bytes.fromhex("1003")


def _multi_frame_entries(uds_payload: bytes) -> list[RawLogEntry]:
    total_len = len(uds_payload)
    first_payload = bytes(
        [0x10 | ((total_len >> 8) & 0x0F), total_len & 0xFF]
    ) + uds_payload[:6]
    entries = [
        _entry(
            f"100000,CAN1,7E8,0,0,8,{first_payload.hex('-').upper()}",
            1,
        )
    ]
    for position, offset in enumerate(range(6, total_len, 7), start=1):
        fragment = uds_payload[offset : offset + 7]
        can_payload = bytes([0x20 | (position % 16)]) + fragment
        entries.append(
            _entry(
                f"{100000 + position},CAN1,7E8,0,0,{len(can_payload)},"
                f"{can_payload.hex('-').upper()}",
                position + 1,
            )
        )
    return entries


def test_iso_tp_reassembler_handles_sequence_number_wrap():
    uds_payload = bytes([0x62, 0xF1, 0x90]) + bytes(range(122))
    frames = [FrameParser().parse(entry) for entry in _multi_frame_entries(uds_payload)]

    IsoTpReassembler().reassemble(frames)

    assert frames[0].fields["iso_tp_reassembly_status"] == "complete"
    assert frames[0].fields["uds_data_hex"] == uds_payload.hex(" ").upper()
    assert all(frame.valid for frame in frames)


def test_iso_tp_reassembler_never_crosses_source_files():
    first = _entry("100000,CAN1,7E9,0,0,8,10-0D-62-F1-5F-08-06-01", 1)
    first.source_file = "capture_a.csv"
    consecutive = _entry("100001,CAN1,7E9,0,0,8,21-02-03-04-05-06-07-00", 1)
    consecutive.source_file = "capture_b.csv"
    frames = [FrameParser().parse(first), FrameParser().parse(consecutive)]

    IsoTpReassembler().reassemble(frames)

    assert frames[0].fields["iso_tp_reassembly_status"] == "incomplete"
    assert frames[1].fields["iso_tp_reassembly_status"] == "orphan"


def test_iso_tp_reassembler_preserves_adjacent_out_of_order_frames():
    uds_payload = bytes([0x62, 0xF1, 0x90]) + bytes(range(24))
    entries = _multi_frame_entries(uds_payload)
    entries[1], entries[2] = entries[2], entries[1]
    frames = [FrameParser().parse(entry) for entry in entries]

    IsoTpReassembler().reassemble(frames)

    assert frames[0].fields["iso_tp_reassembly_status"] == "complete_reordered"
    assert frames[0].fields["uds_data_hex"] == uds_payload.hex(" ").upper()


def test_uds_decoder_negative_response():
    decoder = UdsDecoder()
    info = decoder.decode(bytes.fromhex("7F1031"))
    assert info["uds_direction"] == "negative_response"
    assert info["uds_service_id"] == "10"
    assert info["uds_nrc"] == "31"


def test_frame_validator_flags_dlc_mismatch():
    entry = _entry("100949,CAN1,7E0,0,0,8,02-10-03-00-00-00-00-00")
    frame = FrameParser().parse(entry)
    assert frame is not None
    frame.fields["dlc"] = 5  # force a mismatch

    errors = FrameValidator().validate(frame)
    assert any("dlc mismatch" in err for err in errors)
    assert not frame.valid


def test_module_discovery_finds_paired_response():
    # Real request/response pair from input/log_005.csv (7E0 -> 7E8).
    frames = [
        FrameParser().parse(_entry("100949,CAN1,7E0,0,0,8,02-10-03-00-00-00-00-00", 1)),
        FrameParser().parse(_entry("100958,CAN1,7E8,0,0,8,06-50-03-00-32-01-F4-00", 2)),
    ]
    entries = ModuleDiscoveryAnalyser().discover(frames)

    request_entry = next(e for e in entries if e.arbitration_id == "7E0")
    assert request_entry.role == "request"
    assert request_entry.paired_id == "7E8"
    assert request_entry.module_present is True


def test_all_confirmed_ford_modules_have_machine_readable_profiles():
    expected_pairs = {
        "PCM": ("CAN1", "7E0", "7E8"),
        "TCM": ("CAN1", "7E1", "7E9"),
        "IPC": ("CAN2", "720", "728"),
        "BdyCM": ("CAN1", "726", "72E"),
        "GWM": ("CAN2", "716", "71E"),
        "IPMA": ("CAN2", "706", "70E"),
        "SCCM": ("CAN2", "724", "72C"),
        "ACM": ("CAN2", "727", "72F"),
        "PSCM": ("CAN2", "730", "738"),
        "RCM": ("CAN2", "737", "73F"),
        "RTM": ("CAN2", "751", "759"),
        "ABS": ("CAN2", "760", "768"),
        "TRM": ("CAN2", "791", "799"),
        "FCIM": ("CAN2", "7A7", "7AF"),
    }

    actual_pairs = {
        profile.name: (profile.bus, profile.request_id, profile.response_id)
        for profile in FORD_MODULE_PROFILES
    }

    assert actual_pairs == expected_pairs
    for name in expected_pairs.keys() - {"PCM", "TCM", "IPC", "BdyCM", "GWM"}:
        profile = FORD_PROFILE_BY_NAME[name]
        assert profile.entry_session == "none required"
        assert profile.exit_session == "none required"
        assert profile.discovered_dids


def test_module_discovery_lists_supported_dids_with_curated_metadata():
    frames = [
        FrameParser().parse(_entry("100000,CAN2,720,0,0,8,03-22-40-4C-00-00-00-00", 1)),
        FrameParser().parse(_entry("100010,CAN2,728,0,0,8,06-62-40-4C-1B-AF-99-00", 2)),
        FrameParser().parse(_entry("100020,CAN2,720,0,0,8,03-22-02-02-00-00-00-00", 3)),
        FrameParser().parse(_entry("100030,CAN2,728,0,0,8,04-62-02-02-00-00-00-00", 4)),
    ]
    known = [
        KnownDidEntry(
            module_name="IPC",
            request_id="720",
            did="404C",
            possible_name="Total Distance (Odometer)",
            confidence="confirmed",
            formula="raw / 10",
            unit="km",
        )
    ]

    request_entry = next(
        entry
        for entry in ModuleDiscoveryAnalyser({"720": "IPC"}).discover(frames, known)
        if entry.arbitration_id == "720"
    )

    assert [(code.code_type, code.code) for code in request_entry.supported_codes] == [
        ("DID", "0202"),
        ("DID", "404C"),
    ]
    assert request_entry.supported_codes[0].confidence == "unidentified"
    assert request_entry.supported_codes[1].possible_name == "Total Distance (Odometer)"
    assert request_entry.supported_codes[1].formula == "raw / 10"
    assert request_entry.supported_codes[1].unit == "km"


def test_functional_discovery_attaches_supported_did_to_each_responder():
    frames = [
        FrameParser().parse(_entry("100000,CAN2,7DF,0,0,8,03-22-40-4C-00-00-00-00", 1)),
        FrameParser().parse(_entry("100010,CAN2,728,0,0,8,06-62-40-4C-1B-AF-99-00", 2)),
    ]
    known = [
        KnownDidEntry(
            module_name="IPC",
            request_id="720",
            response_id="728",
            bus="CAN2",
            did="404C",
            possible_name="Total Distance (Odometer)",
            confidence="confirmed",
            formula="raw / 10",
            unit="km",
        )
    ]

    response_entry = next(
        entry
        for entry in ModuleDiscoveryAnalyser({"728": "IPC"}).discover(frames, known)
        if entry.arbitration_id == "728"
    )

    assert response_entry.role == "response"
    assert response_entry.paired_id == "7DF"
    assert response_entry.positive_response_count == 1
    assert [(code.code_type, code.code) for code in response_entry.supported_codes] == [
        ("DID", "404C")
    ]
    assert response_entry.supported_codes[0].possible_name == "Total Distance (Odometer)"
    assert response_entry.supported_codes[0].confidence == "confirmed"


def test_functional_discovery_keeps_did_from_incomplete_positive_first_frame():
    frames = [
        FrameParser().parse(_entry("100000,CAN2,7DF,0,0,8,03-22-F1-10-00-00-00-00", 1)),
        FrameParser().parse(_entry("100010,CAN2,70E,0,0,8,10-1B-62-F1-10-44-53-2D", 2)),
    ]
    IsoTpReassembler().reassemble(frames)

    response_entry = next(
        entry
        for entry in ModuleDiscoveryAnalyser({"70E": "IPMA"}).discover(frames)
        if entry.arbitration_id == "70E"
    )

    assert not frames[1].valid
    assert frames[1].fields["iso_tp_reassembly_status"] == "incomplete"
    assert response_entry.role == "response"
    assert response_entry.positive_response_count == 1
    assert [(code.code_type, code.code) for code in response_entry.supported_codes] == [
        ("DID", "F110")
    ]
    assert response_entry.supported_codes[0].confidence == "unidentified"


def test_telemetry_candidate_analyser_flags_changing_did_value():
    # Real DID (033C) from input/log_*.csv PCM sweep, values observed to
    # drift between 01-52 and 01-53 across repeated reads.
    frames = [
        FrameParser().parse(_entry("246092,CAN1,7E0,0,0,8,03-22-03-3C-00-00-00-00", 1)),
        FrameParser().parse(_entry("246095,CAN1,7E8,0,0,8,05-62-03-3C-01-52-00-00", 2)),
        FrameParser().parse(_entry("263974,CAN1,7E0,0,0,8,03-22-03-3C-00-00-00-00", 3)),
        FrameParser().parse(_entry("263977,CAN1,7E8,0,0,8,05-62-03-3C-01-53-00-00", 4)),
    ]
    entries = TelemetryCandidateAnalyser().discover(frames)

    assert len(entries) == 1
    entry = entries[0]
    assert entry.arbitration_id == "7E8"
    assert entry.did == "033C"
    assert entry.read_count == 2
    assert entry.distinct_value_count == 2
    assert entry.sample_values == ["01 52", "01 53"]


def test_telemetry_candidate_analyser_ignores_constant_value():
    frames = [
        FrameParser().parse(_entry("100000,CAN1,7E8,0,0,8,05-62-03-3C-01-52-00-00", 1)),
        FrameParser().parse(_entry("110000,CAN1,7E8,0,0,8,05-62-03-3C-01-52-00-00", 2)),
    ]
    entries = TelemetryCandidateAnalyser().discover(frames)
    assert entries == []


def test_telemetry_candidate_analyser_attaches_known_hypothesis():
    # Real DID (051C) confirmed via public Ford PX2/Everest community PID
    # database as Air Charge Temp (Intercooler) -- see DID_NAME_HYPOTHESES.
    frames = [
        FrameParser().parse(_entry("244995,CAN1,7E0,0,0,8,03-22-05-1C-00-00-00-00", 1)),
        FrameParser().parse(_entry("244998,CAN1,7E8,0,0,8,04-62-05-1C-39-00-00-00", 2)),
        FrameParser().parse(_entry("263510,CAN1,7E0,0,0,8,03-22-05-1C-00-00-00-00", 3)),
        FrameParser().parse(_entry("263513,CAN1,7E8,0,0,8,04-62-05-1C-3A-00-00-00", 4)),
    ]
    entries = TelemetryCandidateAnalyser().discover(frames)

    assert len(entries) == 1
    entry = entries[0]
    assert entry.did == "051C"
    assert entry.possible_name == "Air Charge Temp (Intercooler) [ACT]"
    assert entry.confidence == "confirmed"


def test_telemetry_candidate_analyser_unknown_did_has_no_hypothesis():
    frames = [
        FrameParser().parse(_entry("246092,CAN1,7E0,0,0,8,03-22-03-3C-00-00-00-00", 1)),
        FrameParser().parse(_entry("246095,CAN1,7E8,0,0,8,05-62-03-3C-01-52-00-00", 2)),
        FrameParser().parse(_entry("263974,CAN1,7E0,0,0,8,03-22-03-3C-00-00-00-00", 3)),
        FrameParser().parse(_entry("263977,CAN1,7E8,0,0,8,05-62-03-3C-01-99-00-00", 4)),
    ]
    entries = TelemetryCandidateAnalyser().discover(frames)

    assert len(entries) == 1
    assert entries[0].possible_name is None
    assert entries[0].confidence == "unidentified"


def test_known_reference_includes_new_confirmed_did_and_pids():
    entries = {(entry.code_type, entry.did): entry for entry in build_known_did_reference()}
    expected = {
        ("DID", "404C"): ("raw / 10", "km"),
        ("DID", "402B"): ("raw - 127", "A"),
        ("DID", "0579"): ("B", "%"),
        ("DID", "1E1A"): ("raw", "raw count"),
        ("DID", "1E1C"): ("(raw * 5 / 72) - 17", "degC"),
        ("DID", "1E1F"): ("raw", "gear"),
        ("DID", "1E1D"): ("raw / 1000", "V"),
        ("DID", "1E12"): ("raw", "gear"),
        ("DID", "1E23"): (
            "raw enum: 0x46=P, 0x3C=R, 0x32=N, 0x2E=D, 0x0A=S",
            "state",
        ),
        ("DID", "1E18"): (
            "raw enum: 0x00070000=D, 0x00030000=S, 0x00010000=S-, "
            "0x00020000=S+",
            "state",
        ),
        ("DID", "1E1B"): ("raw / 4", "rpm"),
        ("DID", "1505"): ("raw / 128", "km/h"),
        ("DID", "F40C"): ("raw / 4", "rpm"),
        ("DID", "F40D"): ("raw", "km/h"),
        ("DID", "F442"): ("raw / 1000", "V"),
        ("PID", "0F"): ("raw - 40", "degC"),
        ("PID", "10"): ("raw / 100", "g/s"),
        ("PID", "11"): ("raw * 100 / 255", "%"),
        ("PID", "1F"): ("raw", "s"),
        ("PID", "21"): ("raw", "km"),
        ("PID", "31"): ("raw", "km"),
        ("PID", "33"): ("raw", "kPa"),
        ("PID", "46"): ("raw - 40", "degC"),
    }

    for key, (formula, unit) in expected.items():
        assert entries[key].confidence == "confirmed"
        assert entries[key].formula == formula
        assert entries[key].unit == unit


def test_module_aware_profiles_merge_discovery_and_confirmed_gauges():
    entries = {
        (entry.module_name, entry.code_type, entry.did): entry
        for entry in build_known_did_reference()
    }

    # Shared identification DIDs remain separate module records.
    for module in ("PCM", "TCM", "IPC", "BdyCM", "GWM"):
        assert (module, "DID", "0202") in entries
        assert entries[(module, "DID", "0202")].request_id == (
            FORD_PROFILE_BY_NAME[module].request_id
        )

    # Confirmed gauges outside partial discovery coverage are retained.
    assert entries[("TCM", "DID", "1E1B")].formula == "raw / 4"
    assert entries[("TCM", "DID", "1E1A")].possible_name == (
        "Transmission Main Fluid Pressure"
    )
    assert entries[("TCM", "DID", "1E1A")].unit == "raw count"
    assert entries[("TCM", "DID", "1E1C")].formula == "(raw * 5 / 72) - 17"
    assert entries[("TCM", "DID", "1E23")].possible_name == (
        "Transmission Range Selector Position"
    )
    assert entries[("TCM", "DID", "1E18")].possible_name == (
        "Transmission Sport/Manual Shift Input"
    )
    assert entries[("IPC", "DID", "404C")].formula == "raw / 10"
    assert entries[("IPC", "DID", "61A5")].possible_name == (
        "Corner Lamp / Dash Illumination State"
    )
    assert entries[("IPC", "DID", "61A5")].confidence == "confirmed"
    assert entries[("IPC", "DID", "61A5")].formula == (
        "(raw & 0x00800000) != 0"
    )
    assert entries[("PSCM", "DID", "3302")].formula == "(raw / 10) - 780"
    assert entries[("PSCM", "DID", "3302")].confidence == "confirmed"
    assert entries[("BdyCM", "DID", "402A")].formula == "(raw / 20) + 6"
    assert entries[("PCM", "DID", "F40C")].formula == "raw / 4"

    assert entries[("GWM", "DID", "F1D4")].confidence == "supported_unresolved"


def test_every_confirmed_reference_has_exactly_one_formula():
    confirmed = {
        code for code, (_, confidence, _) in DID_NAME_HYPOTHESES.items()
        if confidence == "confirmed"
    }
    confirmed.update(
        code for code, (_, confidence, _) in OBD2_PID_NAMES.items()
        if confidence == "confirmed"
    )

    assert set(DID_PID_FORMULA_UNITS) == confirmed
    assert all(formula and unit for formula, unit in DID_PID_FORMULA_UNITS.values())


def test_read_log_file_skips_csv_header(tmp_path):
    path = tmp_path / "log_test.csv"
    path.write_text(
        CSV_HEADER + "\n100949,CAN1,7E0,0,0,8,02-10-03-00-00-00-00-00\n",
        encoding="utf-8",
    )
    entries = read_log_file(path)
    assert len(entries) == 1
    assert entries[0].raw_text.startswith("100949,")


def test_discovery_layout_header_and_frame_are_parsed_explicitly(tmp_path):
    path = tmp_path / "discovery.csv"
    path.write_text(
        CSV_HEADER_DISCOVERY
        + "\n33123,1,CAN2,TX,720,8,02 10 03 00 00 00 00 00\n",
        encoding="utf-8",
    )

    entries = read_log_file(path)
    assert len(entries) == 1
    assert entries[0].column_layout == "7col_discovery"

    frame = FrameParser().parse(entries[0])
    assert frame is not None
    assert frame.frame_id == "720"
    assert frame.fields["timestamp_ms"] == 33123
    assert frame.fields["scan"] == "1"
    assert frame.fields["direction"] == "TX"
    assert frame.fields["ext"] is False
    assert frame.fields["rtr"] is False
    assert frame.payload == bytes.fromhex("02 10 03 00 00 00 00 00")


def test_protocol_direction_layout_is_parsed_explicitly(tmp_path):
    path = tmp_path / "ford_protocol_direction.csv"
    path.write_text(
        CSV_HEADER_PROTOCOL_DIRECTION
        + "\n135817,CAN2,7DF,0,0,8,-,-,RAW_CAN,03-22-C1-04-00-00-00-00,TX\n",
        encoding="utf-8",
    )

    entries = read_log_file(path)
    assert len(entries) == 1
    assert entries[0].column_layout == "11col_protocol_direction"

    frame = FrameParser().parse(entries[0])
    assert frame is not None
    assert frame.frame_id == "7DF"
    assert frame.fields["protocol"] == "RAW_CAN"
    assert frame.fields["direction"] == "TX"
    assert frame.payload == bytes.fromhex("03 22 C1 04 00 00 00 00")

    generic_frame = BmwFrameParser().parse(entries[0])
    assert generic_frame is not None
    assert generic_frame.protocol == "RAW_CAN"
    assert generic_frame.payload == frame.payload

    raw_frame = RawCanFrameParser().parse(entries[0])
    assert raw_frame is not None
    assert raw_frame.protocol == "RAW_CAN"
    assert raw_frame.payload == frame.payload



def test_analyse_parses_simple_entry():
    entry = RawLogEntry(
        line_number=1,
        raw_text="100949,CAN1,7E0,0,0,8,02-10-03-00-00-00-00-00",
        source_file="test.csv",
    )
    result = analyse([entry])
    assert len(result.frames) == 1
    assert result.frames[0].frame_id == "7E0"
    assert result.frames[0].valid


def test_read_log_file_skips_blank_lines(tmp_path):
    log_path = tmp_path / "sample.log"
    log_path.write_text("line one\n\nline two\n", encoding="utf-8")

    entries = read_log_file(log_path)

    assert [e.raw_text for e in entries] == ["line one", "line two"]


def test_frame_parser_returns_none_for_blank_entry():
    entry = RawLogEntry(line_number=1, raw_text="   ", source_file="test.log")
    assert FrameParser().parse(entry) is None


def test_frame_validator_flags_missing_frame_id():
    entry = RawLogEntry(
        line_number=1,
        raw_text="100949,CAN1,7E0,0,0,8,02-10-03-00-00-00-00-00",
        source_file="test.csv",
    )
    frame = FrameParser().parse(entry)
    frame.frame_id = ""

    errors = FrameValidator().validate(frame)

    assert "missing frame_id" in errors
    assert not frame.valid


def test_statistics_engine_counts_frames_per_can_id():
    entries = [
        RawLogEntry(line_number=1, raw_text="100949,CAN1,7E0,0,0,8,02-10-03-00-00-00-00-00", source_file="test.csv"),
        RawLogEntry(line_number=2, raw_text="100958,CAN1,7E0,0,0,8,02-3E-00-00-00-00-00-00", source_file="test.csv"),
        RawLogEntry(line_number=3, raw_text="100984,CAN1,7E8,0,0,8,02-7E-00-00-00-00-00-00", source_file="test.csv"),
    ]
    frames = [FrameParser().parse(e) for e in entries]

    stats = StatisticsEngine().compute(frames)

    assert stats["7E0"].count == 2
    assert stats["7E8"].count == 1


def test_session_analyser_groups_by_source_file():
    entries = [
        RawLogEntry(line_number=1, raw_text="100949,CAN1,7E0,0,0,8,02-10-03-00-00-00-00-00", source_file="a.csv"),
        RawLogEntry(line_number=2, raw_text="100958,CAN1,7E8,0,0,8,06-50-03-00-32-01-F4-00", source_file="b.csv"),
    ]
    frames = [FrameParser().parse(e) for e in entries]

    sessions = SessionAnalyser().build_sessions(frames)

    assert len(sessions) == 2
    assert len(sessions[0].frames) == 1
    assert len(sessions[1].frames) == 1
