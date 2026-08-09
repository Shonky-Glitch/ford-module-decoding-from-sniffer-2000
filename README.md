# Decoding 2000

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
│   └── toyota/       # Placeholder for future Toyota captures
├── output/         # Decoded / exported results, mirrored per OEM
│   ├── ford/         # Ford decoded output
│   │   ├── diagnostics/  # Per-log diagnostic exports (e.g. greatscan_3.5/)
│   │   ├── research/     # Isolated per-log decode runs (see --output-dir below)
│   │   └── telemetry/    # candidates.csv - dynamic DID/PID discovery
│   ├── bmw/          # BMW raw-traffic-only analysis output
│   └── toyota/       # Placeholder for future Toyota output
├── reference/      # Human-curated ECU/module reference notes
├── tests/          # Unit tests
└── src/
    ├── main.py            # Ford pipeline entry point / CLI
    ├── main_bmw.py        # BMW pipeline entry point / CLI
    ├── log_reader.py      # Reads raw log files from input/
    ├── frame_analyser.py  # Parses and analyses Ford frames (ISO-TP/UDS)
    ├── bmw_analyser.py    # Parses and analyses BMW frames (raw traffic only)
    ├── exporters.py       # Writes Ford results to output/ford/
    ├── bmw_exporters.py   # Writes BMW results to output/bmw/
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
   - `telemetry/candidates.csv` - DIDs whose value changed across repeated reads (candidates for live telemetry), including an `observed_pattern` shape hint and `confidence` level (`confirmed` vs `unidentified`)

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

## Tests

Run the test suite with:

```powershell
pytest tests/
```
