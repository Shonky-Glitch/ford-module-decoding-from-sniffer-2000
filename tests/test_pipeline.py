"""Basic tests for the Decoding 2000 pipeline."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from frame_analyser import (  # noqa: E402
    FrameParser,
    FrameValidator,
    IsoTpDecoder,
    ModuleDiscoveryAnalyser,
    SessionAnalyser,
    StatisticsEngine,
    TelemetryCandidateAnalyser,
    UdsDecoder,
    analyse,
)
from log_reader import CSV_HEADER, read_log_file  # noqa: E402
from models import RawLogEntry  # noqa: E402


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


def test_read_log_file_skips_csv_header(tmp_path):
    path = tmp_path / "log_test.csv"
    path.write_text(
        CSV_HEADER + "\n100949,CAN1,7E0,0,0,8,02-10-03-00-00-00-00-00\n",
        encoding="utf-8",
    )
    entries = read_log_file(path)
    assert len(entries) == 1
    assert entries[0].raw_text.startswith("100949,")



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
