# AGENTS.md

Decoding 2000 Engineering Guardrail — guidance for AI coding agents working in
this repository. Read this document completely before making any changes.

## Mission

Decoding 2000 is a standalone Windows laptop application.

Its purpose is to analyse CAN Sniffer 2000 SD card log files.

This project is NOT ESP32 firmware.
This project does NOT contain Arduino code.
This project does NOT communicate with hardware.

Its only responsibility is analysing recorded CAN traffic.

Use Python 3 only.

## Project scope

Responsibilities include:

- Reading CAN Sniffer 2000 log files
- Validating log integrity
- Parsing CAN frames
- Analysing CAN traffic
- Session reconstruction
- CAN ID statistics
- Exporting CSV
- Exporting JSON
- Producing engineering reports

Future responsibilities:

- ISO-TP decoding
- UDS decoding
- J1939 decoding
- GreatScan database generation

## Out of scope

Do NOT:

- Modify CAN Sniffer firmware
- Modify GreatScan firmware
- Generate Arduino code
- Add ESP32 libraries
- Change logging formats without approval
- Modify any other repository
- Merge projects together — maintain strict project separation

## Data flow

```
Input
  ↓
Log Reader
  ↓
Frame Parser
  ↓
Frame Validation
  ↓
Statistics Engine
  ↓
Protocol Detection
  ↓
Session Analysis
  ↓
Export Engine
  ↓
CSV / JSON / Reports
```

## Engineering rules

- Never guess the input file format.
- Always inspect a real capture first.
- If the file format changes: stop, report the differences, and wait for approval.
  Exception (precedent set 2026-08-05/09): once a new column layout has
  already been reviewed and approved once (e.g. the 7/9/10-column CSV
  header variants — see `log_reader.py`'s `CSV_HEADER`/
  `CSV_HEADER_EXTENDED`/`CSV_HEADER_EXTENDED_NO_MODE`), the parser may
  accept that same already-approved variant in future logs without
  re-asking — only a genuinely NEW/unseen layout requires stopping again.
- Never guess PID/DID meaning (units, scaling, name). A DID may only be
  marked "confirmed" after a live field reading or an independently
  sourced public reference (see "Telemetry candidate workflow" below).

## Telemetry candidate workflow

How new PIDs/DIDs get identified, in order:

1. Run the Ford pipeline (`python src/main.py`, optionally `--pattern`/
   `--output-dir` to isolate one log) to regenerate
   `output/ford/telemetry/candidates.csv` — every UDS `0x22` DID read at
   least twice with a changing value.
2. Anything with `confidence=unidentified` is a candidate worth
   investigating; `observed_pattern` gives a shape hint (On/Off switch,
   Bitfield/multi-switch, Ramp/counter, Sensor) but is NOT a meaning guess.
3. Cross-reference the raw bytes (`decoded.csv`/the source `input/ford/*.csv`)
   against either a live field reading you provide, or an independently
   sourced public reference (e.g. saeb.net, GreatScan 3.5 — read-only,
   cross-checked, never trusted blindly on its own).
4. Only once a formula/name is verified this way, add it to
   `DID_NAME_HYPOTHESES`/`DID_MODULE_HINTS` (or `OBD2_PID_NAMES`/
   `OBD2_PID_MODULE_HINTS`) in `frame_analyser.py` with `confidence=
   "confirmed"`, and record the evidence in repo memory
   (`/memories/repo/`).
5. Never skip straight to "confirmed" from pattern-matching alone.

## Repo memory

This project's cross-session findings (confirmed DIDs, open questions,
capture-specific notes, SD card import history) are tracked in the AI
agent's repo-scoped memory (`/memories/repo/can-bus-facts.md`), not just in
this file. Any agent picking up this project should read that memory
file in full before assuming a DID/PID/module id is unconfirmed or
unresearched — it is the authoritative running log, and this file only
covers stable rules/architecture.

## Future expansion

This project will eventually support:

- CAN Sniffer 2000
- GreatScan 3.5
- GreatScan 7.0
- BMW
- Ford
- Holden
- J1939
- UDS
- ISO-TP

The architecture must remain generic.

## AI behaviour

Approval is required BEFORE writing code when the change is architectural
or precedent-setting — i.e. any of:
- a new input file format/column layout not already covered by an
  approved precedent (see Engineering rules above),
- a new OEM/protocol decoder (BMW, Toyota, J1939, ISO-TP, UDS beyond what
  already exists),
- a new top-level module/file, or a change to the data-flow architecture.

For those cases:
1. Explain the folder structure.
2. Explain the parser architecture.
3. List required libraries.
4. Wait for approval.

Approval is NOT required to just proceed (implement, then briefly explain
what changed) when the user's own message is already a specific,
self-contained request scoped to existing files — e.g. "add a column",
"rerun all logs", "fix this bug", "add DID X as confirmed". The request
itself is the approval in that case; do not re-ask before doing what was
asked, but do report what was implemented afterwards. When in doubt about
which case applies, ask.

Never invent packet formats. Never guess PID/DID meaning. Never modify
other repositories. Never merge projects — maintain strict project
separation.

## Layout

```
Decoding 2000/
├── AGENTS.md
├── README.md
├── requirements.txt
├── input/            # Raw log files, one subfolder per OEM (test/sample data)
│   ├── ford/         # Ford captures (log_*.csv)
│   ├── bmw/          # BMW captures
│   └── toyota/       # Placeholder for future Toyota captures (empty for now)
├── output/           # Generated/decoded output (do not hand-edit), mirrored per OEM
│   ├── ford/         # Ford decoded output (ISO-TP/UDS pipeline)
│   │   ├── diagnostics/  # Per-log diagnostic exports (e.g. greatscan_3.5/)
│   │   ├── research/     # Isolated per-log decode runs (--output-dir)
│   │   └── telemetry/    # candidates.csv (dynamic DID/PID discovery)
│   ├── bmw/          # BMW raw-traffic-only analysis output (no ISO-TP/UDS)
│   └── toyota/       # Placeholder for future Toyota output (empty for now)
├── reference/        # Human-curated ECU/module reference notes (markdown)
├── tests/            # Unit tests (pytest)
└── src/
    ├── main.py            # Ford pipeline CLI entry point
    ├── main_bmw.py        # BMW pipeline CLI entry point
    ├── log_reader.py      # Reads raw log files from input/ (shared)
    ├── frame_analyser.py  # Parses and analyses Ford frames (ISO-TP/UDS)
    ├── bmw_analyser.py    # Parses and analyses BMW frames (raw traffic only,
    │                      # no ISO-TP/UDS/module-name assumptions)
    ├── exporters.py       # Writes Ford results to output/ford/
    ├── bmw_exporters.py   # Writes BMW results to output/bmw/
    └── models.py          # Shared data models/types
```

## Conventions

- Python 3.10+, use type hints on all new functions.
- Modular architecture: small, reusable classes. No global variables. No duplicated logic.
- Every parser must be unit testable.
- Keep `models.py` free of I/O; it should only define data structures.
- `log_reader.py` should only be responsible for reading raw input into memory;
  parsing/interpretation belongs in `frame_analyser.py`.
- `exporters.py` should not perform analysis, only format/write already-decoded data.
- New dependencies must be added to `requirements.txt`.
- Files under `input/` and `output/` are data, not source — do not commit large
  binary samples unless explicitly requested.

## Testing

- Tests live in `tests/` and use `pytest`.
- Run tests with `pytest tests/` from the repository root.
- Add/update tests when changing behaviour in `src/`.

## Before committing

- Run `pytest tests/` and ensure it passes.
- Keep changes scoped to the files/folders relevant to the task.
