from pathlib import Path
import glob

input_dir = Path(r"c:\Users\hayle\OneDrive - HKK Equipment\Documents\PlatformIO\Projects\Decoding 2000\input")

mode01_pids = {}  # pid_hex -> set of source files
mode22_dids = {}  # did_hex -> set of source files

for path in sorted(input_dir.glob("*.csv")):
    with path.open(errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("ms,"):
                continue
            parts = line.split(",")
            data_hex = parts[-1]
            b = data_hex.split("-")
            if len(b) < 3:
                continue
            # Mode 01 request: PCI=02, SID=01, PID=b[2]
            if b[1] == "01" and len(b) >= 3:
                pid = b[2]
                mode01_pids.setdefault(pid, set()).add(path.name)
            # Mode 22 request: SID=22, DID=b[2]+b[3]
            if len(b) >= 4 and b[1] == "22":
                did = b[2] + b[3]
                mode22_dids.setdefault(did, set()).add(path.name)

print("=== Mode 01 (legacy OBD-II) PIDs requested across all logs ===")
for pid in sorted(mode01_pids):
    print(f"  PID {pid}: seen in {sorted(mode01_pids[pid])}")

print("\n=== Mode 22 (UDS ReadDataByIdentifier) DIDs requested across all logs ===")
for did in sorted(mode22_dids):
    print(f"  DID {did}: seen in {sorted(mode22_dids[did])}")
