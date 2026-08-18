from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from can_signal_analyser import CanSignalAnalyser, load_signal_database
from models import CanSignalDefinition, RawCanFrame


def _frame(timestamp_ms: int, value: int) -> RawCanFrame:
    return RawCanFrame("167", timestamp_ms, "CAN2", "RAW_CAN", 2, bytes([value, 0]))


def test_discovers_changed_byte_and_raw_transitions() -> None:
    result = CanSignalAnalyser().analyse([_frame(10, 0), _frame(20, 0), _frame(30, 4)])
    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.byte_offset == 0
    assert candidate.active_bit_mask == 0x04
    assert candidate.confidence == "unidentified"
    assert [(item.timestamp_ms, item.raw_value) for item in result.observations] == [
        (10, 0),
        (30, 4),
    ]


def test_applies_exact_curated_definition() -> None:
    definition = CanSignalDefinition(
        "CAN2", "167", "Example", 0, 8, "intel", "raw", "", "confirmed", "field test"
    )
    result = CanSignalAnalyser().analyse([_frame(10, 0), _frame(20, 1)], [definition])
    assert result.candidates[0].signal_name == "Example"
    assert result.candidates[0].confidence == "confirmed"


def test_loads_empty_database(tmp_path: Path) -> None:
    path = tmp_path / "signals.csv"
    path.write_text(
        "bus,frame_id,signal_name,start_bit,bit_length,byte_order,formula,unit,confidence,evidence\n",
        encoding="utf-8",
    )
    assert load_signal_database(path) == []
