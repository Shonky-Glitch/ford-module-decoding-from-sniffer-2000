"""Confirmed Hyundai broadcast-CAN signals backed by public DBC definitions."""

from models import KnownRawCanSignal

SOURCE = (
    "commaai/opendbc hyundai_i30_2014.dbc; cross-checked against Hyundai "
    "iLoad input/hyundai/log_001.csv on 2026-08-16"
)

# Message-level matches: 16 of the 17 IDs in the iLoad capture occur together
# in the public Hyundai i30 DBC. Descriptions summarize that DBC's signal set;
# they do not imply that every i30 bit layout applies unchanged to the iLoad.
HYUNDAI_CAN_ID_NAMES: dict[str, tuple[str, str, str]] = {
    "0A0": ("EngFrzFrm1", "Engine freeze-frame data", "confirmed"),
    "153": ("TCS1", "ABS, traction and stability-control status", "confirmed"),
    "18F": ("EMS_H2", "Engine-management and requested-gear status", "confirmed"),
    "1F1": ("TCS5", "Wheel-speed and ABS/TCS warning data", "confirmed"),
    "220": ("ESP2", "Acceleration, brake-pressure and yaw data", "confirmed"),
    "260": ("EMS6", "Engine torque and operating-state data", "confirmed"),
    "2A0": ("EMS5", "Intake-air and OBD counter data", "confirmed"),
    "316": ("EMS1", "Engine speed, torque and vehicle-speed data", "confirmed"),
    "329": ("EMS2", "Engine configuration, temperature and throttle data", "confirmed"),
    "370": ("TCU3", "Transmission target-gear and state data", "confirmed"),
    "43F": ("TCU1", "Primary transmission data", "confirmed"),
    "440": ("TCU2", "Secondary transmission data", "confirmed"),
    "4B1": ("WHL_PUL", "Wheel pulse-count and direction data", "confirmed"),
    "4F0": ("CLU1", "Instrument-cluster and vehicle-state data", "confirmed"),
    "545": ("EMS4", "Engine electrical and fuel-system data", "confirmed"),
    "690": ("CLU2", "Ignition, door, lighting and body-switch data", "confirmed"),
    "5A2": ("(unidentified)", "No reliable public definition found", "unidentified"),
}


def _signal(
    frame_id: str,
    message_name: str,
    signal_name: str,
    start_bit: int,
    bit_length: int,
    formula: str,
    unit: str,
    observed: str,
) -> KnownRawCanSignal:
    return KnownRawCanSignal(
        frame_id=frame_id,
        message_name=message_name,
        signal_name=signal_name,
        start_bit=start_bit,
        bit_length=bit_length,
        byte_order="little_endian",
        formula=formula,
        unit=unit,
        confidence="confirmed",
        notes=f"Source: {SOURCE}. Observed: {observed}.",
    )


HYUNDAI_CONFIRMED_SIGNALS: tuple[KnownRawCanSignal, ...] = (
    _signal("0A0", "EngFrzFrm1", "Calculated Engine Load", 0, 8,
            "raw * 0.392157", "%", "0-85.49% across 3,861 frames"),
    _signal("0A0", "EngFrzFrm1", "Engine Coolant Temperature", 8, 8,
            "raw - 40", "degC", "40-84 degC warm-up across 3,861 frames"),
    _signal("0A0", "EngFrzFrm1", "Engine Speed", 16, 16,
            "raw * 0.25", "rpm", "0-2124.75 rpm; agrees with CAN 316 within 3 rpm"),
    _signal("0A0", "EngFrzFrm1", "Throttle Position", 40, 8,
            "raw * 0.392157", "%", "0-64.31% across 3,861 frames"),
    _signal("316", "EMS1", "Engine Speed", 16, 16,
            "raw * 0.25", "rpm", "0-2121.75 rpm; agrees with CAN 0A0 within 3 rpm"),
    _signal("2A0", "EMS5", "Intake Air Temperature", 16, 8,
            "raw * 0.75 - 48", "degC", "0-41.25 degC across 896 frames"),
    _signal("329", "EMS2", "Throttle Position", 40, 8,
            "raw * 0.469484 - 15.0235", "%", "approximately 0-54.93% across 933 frames"),
    _signal("329", "EMS2", "Engine Displacement", 56, 8,
            "raw * 0.1", "L", "constant 2.5 L, matching the iLoad 2.5 diesel"),
    _signal("545", "EMS4", "Module Voltage", 24, 8,
            "raw * 0.101563", "V", "11.98-14.22 V across 1,570 frames"),
)
