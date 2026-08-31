# Decoding 2000

Passive broadcast CAN signals are kept separate from diagnostic PIDs/DIDs.
Curated definitions live in `reference/can_signals.csv`; pipeline runs write
unidentified changing-byte candidates and raw value transitions to
`output/ford/signals/`. A signal may only be marked `confirmed` when its bit
layout and meaning are supported by controlled field evidence or an independent
public reference.

Tools for reading, decoding, and exporting frame/log data from the Decoder 2000 project.

## Project layout

```
Decoding 2000/
├── AGENTS.md
├── README.md
├── requirements.txt
├── input/          # Raw log files to be decoded, one subfolder per OEM
│   ├── ford/         # Ford captures (log_*.csv)
│   ├── bmw/          # BMW captures
│   ├── toyota/       # Placeholder for future Toyota captures
│   └── hyundai/      # Placeholder for future Hyundai captures
├── output/         # Decoded / exported results, mirrored per OEM
│   ├── ford/         # Ford decoded output
│   │   ├── diagnostics/  # Per-log diagnostic exports (e.g. greatscan_3.5/)
│   │   ├── research/     # Isolated per-log decode runs (see --output-dir below)
│   │   └── telemetry/    # candidates.csv - dynamic DID/PID discovery
│   ├── bmw/          # BMW raw-traffic-only analysis output
│   ├── toyota/       # Placeholder for future Toyota output
│   └── hyundai/      # Placeholder for future Hyundai output
├── reference/      # Human-curated ECU/module reference notes
├── tests/          # Unit tests
└── src/
    ├── main.py            # Ford pipeline entry point / CLI
    ├── main_bmw.py        # BMW pipeline entry point / CLI
    ├── main_hyundai.py    # Hyundai raw-CAN pipeline entry point / CLI
    ├── log_reader.py      # Reads raw log files from input/
    ├── frame_analyser.py  # Parses and analyses Ford frames (ISO-TP/UDS)
    ├── bmw_analyser.py    # Parses and analyses BMW frames (raw traffic only)
    ├── raw_can_analyser.py # OEM-neutral broadcast-CAN analysis
    ├── exporters.py       # Writes Ford results to output/ford/
    ├── bmw_exporters.py   # Writes BMW results to output/bmw/
    ├── raw_can_exporters.py # OEM-neutral raw-CAN exports
    └── models.py          # Shared data models/types
```

## Getting started

1. Create a virtual environment and install dependencies:

   ```powershell
   python -m venv .venv
   .venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

2. Place raw Ford log files in [input/ford/](input/ford/) (BMW logs go in
   [input/bmw/](input/bmw/), analysed separately - see below).

3. Run the Ford decoder:

   ```powershell
   python src/main.py
   ```

4. Decoded output will be written to [output/ford/](output/ford/), including:
   - `decoded.csv` / `decoded.json` - every parsed frame
   - `can_id_summary.csv`, `module_discovery.csv`, `report.txt` - statistics/reports
   - `known_pids.csv` - static reference table of every known PID/DID
   - `ford_module_profiles.csv` - proven bus/address/session/wake profiles and
     discovery-supported DID allowlists for all 14 confirmed Ford modules
   - `telemetry/candidates.csv` - DIDs whose value changed across repeated reads (candidates for live telemetry), including an `observed_pattern` shape hint and `confidence` level (`confirmed` vs `unidentified`)

   `known_pids.csv` is module-aware: a DID shared by multiple ECUs receives a
   separate row per module. `supported_status` distinguishes DIDs proven by a
   discovery scan from confirmed gauges added from earlier controlled tests.

   To decode a single log (or subset) in isolation instead of merging all of `input/ford/`, use:

   ```powershell
   python src/main.py --pattern "log_013.csv" --output-dir "output/ford/research/log_013"
   ```

   BMW captures use a separate pipeline (raw traffic stats only - no ISO-TP/
   UDS decoding, since BMW's diagnostic protocol/addressing is not confirmed,
   see [reference/bmw_ecu_reference.md](reference/bmw_ecu_reference.md)):

   ```powershell
   python src/main_bmw.py
   ```

   which reads from `input/bmw/` and writes `can_id_summary.csv`,
   `byte_variability.csv`, and `report.txt` to `output/bmw/`.

   Hyundai captures currently use OEM-neutral raw broadcast-CAN analysis;
   no diagnostic protocol, module name, PID/DID meaning, or scaling is assumed:

   ```powershell
   python src/main_hyundai.py
   ```

   This reads `input/hyundai/` and writes decoded raw frames, CAN-ID timing,
   byte variability, `known_pids.csv` (confirmed broadcast CAN signals), a
   report, and unidentified telemetry candidates to `output/hyundai/`.

## Submitting your own confirmed PID/DID data

If you've already field-tested a DID/PID yourself — watched it live
against a scan tool, dash gauge, or multimeter, or turned a physical
control and watched the value track it — you don't need to re-run the
discovery workflow. Just hand it over, one line per DID:

```
DID <hex> = <name>, formula: <raw-to-unit equation>, evidence: <what you did/observed, with numbers>
```

Example:

```
DID F433 = Battery Current, formula: raw/100=A, evidence: multimeter read
8.4A at idle; raw was 0x0348 (840) at the same instant across 3 repeated
reads in input/log_030.csv.
```

Given that, the agent adds it to `DID_NAME_HYPOTHESES` in
`src/frame_analyser.py` as `confidence="confirmed"`, regenerates
`known_pids.csv`/`telemetry/candidates.csv`, and records it in repo
memory — no back-and-forth re-discovery needed. See
[AGENTS.md](AGENTS.md)'s "Telemetry candidate workflow" for the full
rules (including the slower from-scratch discovery path for DIDs nobody
has field data for yet).

## Tests

Run the test suite with:

```powershell
pytest tests/
```
