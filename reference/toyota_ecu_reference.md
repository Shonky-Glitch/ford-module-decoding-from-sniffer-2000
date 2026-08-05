# Toyota ECU / PID Reference Data

Reference notes for future Toyota log analysis (see AGENTS.md "Future
expansion" and `input/toyota/`, `output/toyota/`). This is research/reference
data only — not wired into any decoding code yet. Nothing here should be
treated as confirmed until cross-checked against a real `input/toyota/*.csv`
capture, per AGENTS.md ("never guess the input file format", "always inspect
a real capture first").

## Sources

- [SAE J1979 / Wikipedia "OBD-II PIDs"](https://en.wikipedia.org/wiki/OBD-II_PIDs) —
  the generic Mode 01 PID table below is a public standard, not
  Toyota-specific, and applies to any OBD-II compliant vehicle (confidence:
  high, it's a published standard).
- [commaai/opendbc](https://github.com/commaai/opendbc/blob/master/opendbc/car/toyota/values.py) —
  MIT-licensed, reverse-engineered Toyota/Lexus ECU addresses running in
  production `openpilot` builds. Same confidence caveat as the existing Ford
  reference: community-sourced/unofficial, not OEM-confirmed, and scoped to
  what openpilot's ADAS stack needs (not a full body-module list).

## Generic OBD-II Mode 01 PIDs (SAE J1979 — not Toyota-specific)

These apply to the standard functional request id `0x7DF` (broadcast) with
responses on `0x7E8`-`0x7EF` (physical ECU addr + `0x8`, same ISO 15765-4
convention already used for Ford in this repo). Byte formulas: A/B/C/D are
the 1st/2nd/3rd/4th data bytes after the PID echo.

| PID | Name | Bytes | Formula | Unit |
|---|---|---|---|---|
| `00` | PIDs supported [01-20] | 4 | bitmask | - |
| `04` | Calculated engine load | 1 | A/2.55 | % |
| `05` | Engine coolant temperature | 1 | A-40 | degC |
| `0B` | Intake manifold absolute pressure | 1 | A | kPa |
| `0C` | Engine RPM | 2 | (256A+B)/4 | rpm |
| `0D` | Vehicle speed | 1 | A | km/h |
| `0F` | Intake air temperature | 1 | A-40 | degC |
| `10` | MAF air flow rate | 2 | (256A+B)/100 | g/s |
| `11` | Throttle position | 1 | A/2.55 | % |
| `1C` | OBD standards this vehicle conforms to | 1 | enum | - |
| `1F` | Run time since engine start | 2 | 256A+B | s |
| `21` | Distance travelled with MIL on | 2 | 256A+B | km |
| `2F` | Fuel tank level input | 1 | A/2.55 | % |
| `33` | Absolute barometric pressure | 1 | A | kPa |
| `42` | Control module voltage | 2 | (256A+B)/1000 | V |
| `46` | Ambient air temperature | 1 | A-40 | degC |
| `5C` | Engine oil temperature | 1 | A-40 | degC |

This is a small, commonly-used subset, not the full J1979 table. Full table
is on the Wikipedia page above if more PIDs are needed later.

Note (from the same source): manufacturers define additional service/mode
numbers beyond the 10 standard ones for enhanced data — **service `0x21` is
specifically called out as Toyota's enhanced-PID mode** (vs. `0x22` for
Ford/GM). If a Toyota capture shows request/response traffic on service
`0x21` (rather than `0x22` DID-style like the Ford logs in this repo), that
is expected and should be handled as a distinct Toyota-specific service, not
folded into the existing Ford Mode-22 DID logic.

## Toyota/Lexus diagnostic addresses (opendbc, reverse-engineered)

Standard UDS/OBD convention (request → response = request + `0x8`) still
applies for the addresses below unless noted otherwise:

| Module | CAN address | Notes |
|---|---|---|
| Engine / PCM | `0x7E0` → `0x7E8` | Standard OBD addr, same as generic J1979 |
| Hybrid Control Assembly & Computer | `0x7E2` / `0x7D2` | Two possible addresses seen across platforms |
| SRS Airbag | `0x780` | |
| Transmission | `0x701` | Combined with engine on some platforms (e.g. TSS-P RAV4) |
| Transmission (alt.) | `0x7E1` | Some platforms have a tester-present response here too |
| HVAC | `0x7C4` | |
| Combination Meter (instrument cluster) | `0x7C0` | Documented but not queried by opendbc |
| HV Battery | `0x713`, `0x747` | Hybrid/EV models only |
| Motor Generator | `0x716`, `0x724` | Hybrid/EV models only |
| 2nd ABS / Brake / EPB | `0x730` | |
| Electronic Parking Brake | `0x750` (sub-id `0x2C`) | Multiplexed sub-address, not a plain UDS request id |
| Telematics | `0x750` (sub-id `0xC7`) | Multiplexed sub-address, not a plain UDS request id |
| Steering Angle Sensor | `0x7B3` | Uses legacy KWP2000-over-CAN, not straight UDS (see below) |
| EPS / EMPS | `0x7A0`, `0x7A1` | Uses legacy KWP2000-over-CAN, not straight UDS (see below) |

`fwdCamera`, `fwdRadar`, and `eps` addresses vary per Toyota platform
generation (TSS-P vs TSS2) in opendbc and were not pinned down to fixed
values in this pass — needs a real capture or a deeper opendbc dig if ADAS
modules show up in a log.

## Toyota-specific protocol quirk: legacy KWP2000 version query

Some older Toyota ECUs (per opendbc, at least `fwdCamera`, `fwdRadar`, `dsu`,
`abs`, `eps`, `srs`, `transmission`, `hvac`) respond to a **KWP2000-style**
"ReadECUIdentification" request rather than a plain UDS
`ReadDataByIdentifier` (Mode 22):

- Request: bytes `1A 88 01` (data identifier `0x1A88`, sub-id `01`)
- Response: bytes `5A 88 01` (positive KWP response echo)
- Toyota's own diagnostic tooling queries sub-ids sequentially: `1A8801`,
  then `1A8802`, `1A8803`, etc., after first requesting the supported list.

If a Toyota capture shows request bytes starting `1A 88 ...` this is that
KWP identification query, not a standard UDS DID read — don't try to decode
it with the existing Ford Mode-22 DID parser.

## Still missing (needs a real capture)

- Exact per-platform `fwdCamera` / `fwdRadar` / `eps` / `abs` addresses
  (opendbc varies these by TSS-P vs TSS2 generation).
- Any Toyota-specific Mode `0x21` enhanced-PID list (DID names/formulas) —
  none found in opendbc (it only cares about ADAS FW versions, not
  powertrain telemetry DIDs). Will need the same kind of controlled
  correlation approach used for the Ford DID candidates in
  `/memories/repo/can-bus-facts.md`.
- Confirmation of which addresses actually appear in a real
  `input/toyota/*.csv` capture — everything above is opendbc/Wikipedia
  reference only, not yet seen in this project's own data.
