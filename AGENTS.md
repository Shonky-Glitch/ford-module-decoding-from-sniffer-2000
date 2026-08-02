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

Before writing code:
1. Explain the folder structure.
2. Explain the parser architecture.
3. List required libraries.
4. Wait for approval.

Never invent packet formats. Never modify other repositories. Never merge
projects — maintain strict project separation.

## Layout

```
Decoding 2000/
├── AGENTS.md
├── README.md
├── requirements.txt
├── input/            # Raw log files (test/sample data goes here)
├── output/           # Generated/decoded output (do not hand-edit)
├── tests/            # Unit tests (pytest)
└── src/
    ├── main.py            # CLI entry point
    ├── log_reader.py      # Reads raw log files from input/
    ├── frame_analyser.py  # Parses and analyses frames
    ├── exporters.py       # Writes results to output/
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
