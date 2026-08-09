"""Throwaway analysis script (not part of src/): for every UNIDENTIFIED
telemetry candidate DID, show which individual byte(s) of the payload
actually change value across the whole input/ corpus, and how (min/max,
distinct count, monotonic ramp vs bitfield toggle vs noisy).

Run: python _tmp_byte_movement.py
"""
from __future__ import annotations

import sys
from pathlib import Path
from collections import defaultdict

REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from log_reader import read_all_logs
from frame_analyser import analyse, DID_NAME_HYPOTHESES

INPUT_DIR = REPO_ROOT / "input"

entries = read_all_logs(INPUT_DIR, "*.csv")
result = analyse(entries)

# key: (frame_id, did) -> list of (timestamp_ms, value_bytes)
reads: dict[tuple[str, str], list[tuple[object, bytes]]] = defaultdict(list)

for frame in result.frames:
    if frame.fields.get("uds_service_id") != "22":
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
        continue
    did = uds_bytes[1:3].hex().upper()
    value = uds_bytes[3:]
    key = (frame.frame_id, did)
    reads[key].append((frame.fields.get("timestamp_ms"), value))

print(f"{'arb_id':6} {'DID':5} {'len':3} {'reads':6} byte-by-byte movement")
print("-" * 100)

for (arb_id, did), values in sorted(reads.items(), key=lambda kv: -len(kv[1])):
    distinct = {v for _, v in values}
    if len(values) < 2 or len(distinct) < 2:
        continue  # not a telemetry candidate at all
    if did in DID_NAME_HYPOTHESES and DID_NAME_HYPOTHESES[did][1] == "confirmed":
        continue  # already identified, skip

    vlen = len(next(iter(distinct)))
    if any(len(v) != vlen for v in distinct):
        vlen = max(len(v) for v in distinct)

    # per-byte-position stats
    byte_cols: list[set[int]] = [set() for _ in range(vlen)]
    for v in distinct:
        for i in range(vlen):
            if i < len(v):
                byte_cols[i].add(v[i])

    ordered_values = [v for _, v in sorted(values, key=lambda tv: (tv[0] is None, tv[0]))]
    col_desc = []
    for i in range(vlen):
        vals = byte_cols[i]
        if len(vals) <= 1:
            col_desc.append(f"B{i}=const({next(iter(vals)):02X})" if vals else f"B{i}=?")
            continue
        lo, hi = min(vals), max(vals)
        seq = [v[i] if i < len(v) else None for v in ordered_values]
        seq_clean = [s for s in seq if s is not None]
        is_monotonic_nondecreasing = all(a <= b for a, b in zip(seq_clean, seq_clean[1:]))
        is_monotonic_nonincreasing = all(a >= b for a, b in zip(seq_clean, seq_clean[1:]))
        shape = "ramp" if (is_monotonic_nondecreasing or is_monotonic_nonincreasing) else (
            "bitfield" if hi <= 1 or bin(hi).count("1") == 1 and lo == 0 else "varies"
        )
        col_desc.append(f"B{i}={lo:02X}-{hi:02X}({len(vals)}v,{shape})")

    print(f"{arb_id:6} {did:5} {vlen:3} {len(values):6} " + " ".join(col_desc))
