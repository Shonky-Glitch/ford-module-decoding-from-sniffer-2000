# Decoding 2000

Tools for reading, decoding, and exporting frame/log data from the Decoder 2000 project.

## Project layout

```
Decoding 2000/
├── AGENTS.md
├── README.md
├── requirements.txt
├── input/          # Raw log files to be decoded
├── output/          # Decoded / exported results
├── tests/           # Unit tests
└── src/
    ├── main.py            # Entry point / CLI
    ├── log_reader.py      # Reads raw log files from input/
    ├── frame_analyser.py  # Parses and analyses frames
    ├── exporters.py       # Writes results to output/
    └── models.py          # Shared data models/types
```

## Getting started

1. Create a virtual environment and install dependencies:

   ```powershell
   python -m venv .venv
   .venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

2. Place raw log files in [input/](input/).

3. Run the decoder:

   ```powershell
   python src/main.py
   ```

4. Decoded output will be written to [output/](output/).

## Tests

Run the test suite with:

```powershell
pytest tests/
```
