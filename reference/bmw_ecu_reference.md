# BMW ECU / PID Reference Data

Reference notes for future BMW log analysis (see AGENTS.md "Future expansion"
and `input/bmw/`, `output/bmw/`). This is research/reference data only — not
wired into any decoding code yet. Nothing here should be treated as confirmed
until cross-checked against a real `input/bmw/*.csv` capture, per AGENTS.md
("never guess the input file format", "always inspect a real capture first").

## Sources and confidence — read this before using anything below

Unlike Ford ([reference/ford_ecu_reference.md](ford_ecu_reference.md)) and
Toyota ([reference/toyota_ecu_reference.md](toyota_ecu_reference.md)), **BMW
is not supported by commaai/opendbc at all** — there is no production,
reverse-engineered reference implementation to draw on, which was the main
confidence anchor for the other two files. What was found instead:

- [Wikipedia "OBD-II PIDs" / SAE J1979](https://en.wikipedia.org/wiki/OBD-II_PIDs) —
  same generic standard used for Toyota, applies to BMW too. High confidence
  (published standard, not manufacturer-specific).
- [endtuning.com "BMW Codes"](https://endtuning.com/bmwcodes.html) — a large,
  plain enthusiast reference of BMW **fault codes per ECU family** (DME, DDE,
  ABS/DSC, etc.), not diagnostic bus addresses. Useful only to confirm the ECU
  family names/acronyms below (cross-referenced against its own fault
  descriptions, e.g. "CAN Error - EGS Control Unit", "Message: CAS").
- `bimmer.studio` (a commercial/paywalled "BMW Intelligence Platform") claims
  example diagnostic addresses on its marketing landing page (e.g. "DME =
  0x12, DSC = 0x60"). **This is a single, unverified, commercial source** — it
  could not be cross-checked against a second independent authoritative
  source (unlike the Ford/Toyota opendbc data). Treat as low-confidence
  hearsay, not fact.
- `en.oldbmw.ru` and other diagnostic-equipment blogs — good background on
  BMW's tooling history (EDIABAS, INPA, DIS, GT1) but no consolidated
  address table was found there either.

**Conclusion: do not add any BMW-specific diagnostic address to code.** The
ECU family names below are solid; the actual hex addresses are not, and
should be read directly off a real `input/bmw/*.csv` capture instead of
assumed from this file.

## Generic OBD-II Mode 01 PIDs (SAE J1979 — same as any OBD-II vehicle)

BMWs sold for on-road use are OBD-II/EOBD compliant like any other
manufacturer, so the same generic PID table already documented in
[reference/toyota_ecu_reference.md](toyota_ecu_reference.md#generic-obd-ii-mode-01-pids-sae-j1979--not-toyota-specific)
applies unchanged (functional request `0x7DF`, responses `0x7E8`-`0x7EF`,
response = request + `0x8`). Not repeated here to avoid duplication/drift —
refer to that file for the PID table.

## BMW proprietary diagnostics — structurally different from Ford/Toyota

This is the important caveat for this project: BMW's factory diagnostics
(INPA, ISTA, Tool32, EDIABAS/`api32.dll`) generally do **not** use the plain
ISO 15765-4 `0x7E0`-`0x7EF` convention for anything beyond basic emissions
OBD-II. Proprietary diagnostics instead use:

- **DS2 / D-CAN / BMW-FAST** framing (older, pre-~2007 models), and/or
  **KWP2000/UDS-over-CAN with per-ECU "diagnostic addresses"** (newer models),
  documented in per-ECU `.PRG`/`.GRP`/SGBD definition files rather than a
  small fixed address table like Ford/Toyota's Mode 22/21 DID lists.
- Each ECU has its own diagnostic address baked into these definition files
  (open source projects like
  [uholeschak/ediabaslib](https://github.com/uholeschak/ediabaslib) interpret
  these files at runtime but don't publish a simple lookup table anywhere
  accessible without downloading/parsing the actual `.PRG` files, which
  wasn't done for this pass).

## BMW ECU family names/acronyms (confirmed by multiple sources, addresses NOT confirmed)

These acronyms are well-established across independent sources (opendbc has
no equivalent, but the names themselves are consistent between endtuning.com's
fault-code descriptions and general BMW enthusiast/service literature):

| Acronym | Full name | Function |
|---|---|---|
| DME | Digitale Motor Elektronik | Petrol engine control (ECU family names: M1.x, M3.x, MS4x, MSS5x, ME9, DME7.2, etc.) |
| DDE | Digitale Diesel Elektronik | Diesel engine control (DDE1 through DDE7) |
| EGS | Elektronische Getriebesteuerung | Automatic transmission control |
| ABS / ASC / DSC | Anti-lock Braking / Automatic Stability Control / Dynamic Stability Control | Brake/traction/stability control (same physical module family, renamed across generations) |
| IHKA | Integrierte Heizung/Klima Automatic | Climate control |
| CAS | Car Access System | Keyless entry / immobiliser / ignition switch replacement (newer models) |
| EWS | Elektronische Wegfahrsperre | Older immobiliser system (pre-CAS) |
| LM / FRM | Lichtmodul / Fussraummodul | Lighting / footwell module (body electronics) |
| KOMBI | Kombiinstrument | Instrument cluster |

No CAN arbitration ids are listed for these — see the confidence note above.

## Still missing (needs a real capture, or dedicated further research)

- Actual CAN diagnostic addresses (request/response ids) for every module
  above — not found from an independently-verifiable source in this pass.
- Whether a given BMW model/year in scope for this project uses D-CAN,
  BMW-FAST, or plain ISO 15765-4 UDS on its OBD connector — this determines
  whether the existing Ford-style ISO-TP reassembly logic in
  `src/frame_analyser.py` is even applicable, or whether BMW captures will
  need a distinct parser path.
- A verified BMW enhanced-PID/DID list (equivalent to the Ford Mode 22 DID
  work in `/memories/repo/can-bus-facts.md`) — none found; would need the same
  controlled-correlation approach once a real capture exists.
- Confirmation of which addresses/protocol actually appear in a real
  `input/bmw/*.csv` capture — everything above beyond the generic OBD-II
  table is unverified reference only.
