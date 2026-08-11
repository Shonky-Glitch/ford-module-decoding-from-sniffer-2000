# Ford AASRA/Service Info Session — DID Lookup Checklist

Working checklist for the paid Ford Service Information Access session
(motorcraftservice.com via AASRA). Goal: resolve the name/formula/unit for
DIDs already observed in real captures but not confirmed by any public
source (opendbc, saeb.net, GreatScan 3.5 — see the repo memory notes on
can-bus facts for full history). Nothing here should be added to
`DID_NAME_HYPOTHESES` in `src/frame_analyser.py` until confirmed against
this session's findings (or a field test) — per AGENTS.md, never guess.

**Context for every lookup below:** module = PCM, request `0x7E0` / response
`0x7E8`, protocol = UDS `ReadDataByIdentifier` (Mode/Service `0x22`).

## How to use this during the session

1. Log into motorcraftservice.com (via the AASRA Ford page) and find the
   PCM/powertrain diagnostic DID or "parameter identifier" reference/search
   tool (may be under Diagnostics, Wiring/PID reference, or a technical
   service bulletin search — exact location TBD, note it here once found for
   next time).
2. For each hex DID below, search it directly (with and without the `0x`
   prefix, and try both "DID" and "PID" terminology — Ford's own docs may
   use either).
3. Record: official name, byte length, scaling formula/unit, and which
   document/page it came from (for traceability).
4. Don't try to bulk-export or screenshot the whole database — targeted,
   one-at-a-time lookups only (see subscription terms).

## Priority 1 — unidentified DIDs from `input/log_013.csv` (dedicated PCM polling session, 90-91 reads each)

| DID | Byte size | Observed raw value(s) | Current guess (unconfirmed) | Found? | Official name / formula |
|---|---|---|---|---|---|
| `0324` | 2-byte | 73/91 distinct values — highly variable | none — no pattern match | ☐ | |
| `1E1F` | 1-byte? | near-constant `05`/`00` | possible status/flag bit (adjacent to confirmed ATF=`1E1C`) | ☐ | |
| `03C8` | 2-byte | steadily decreasing 871→851 over session | possible cooldown timer/counter | ☐ | |
| `03F5` | 1-byte | ~61-62 raw | NOTE: already confirmed elsewhere as **Exhaust Gas Temp 13 (EGT13)**, raw*5=degC — see `DID_NAME_HYPOTHESES` in `frame_analyser.py`. Row kept only for history; no lookup needed. | N/A | EGT13, raw*5=degC (confirmed) |
| `03F6` | 1-byte | ~59 raw | NOTE: already confirmed elsewhere as **Exhaust Gas Temp 12 (EGT12)**, raw*5=degC — see `DID_NAME_HYPOTHESES` in `frame_analyser.py`. Row kept only for history; no lookup needed. | N/A | EGT12, raw*5=degC (confirmed) |
| `F405` | 1-byte | `0x7C` (124) | sourced from saeb.net as **Coolant Temp**, raw-40=degC (~84°C) — needs official confirmation, not yet added to code | ☐ | |

## Priority 2 — older unidentified DIDs (from the main `input/` capture set)

| DID | Byte size | Observed raw value(s) | Current guess (unconfirmed) | Found? | Official name / formula |
|---|---|---|---|---|---|
| `033C` | 2-byte | `0x0152`/`0x0153` (±1 LSB) | possible fine-res analog sensor — NOTE: previously justified as "same family as confirmed Sump Oil Temp `03F3`", but `03F3` was never actually confirmed anywhere in this project (no such entry exists in `DID_NAME_HYPOTHESES`); that basis is invalid and the guess should be treated as having no supporting pattern | ☐ | |
| `035A` | 2-byte | `0x034A`-`0x034E` (842-846) | possible engine-load/pressure | ☐ | |
| `03BA` | 2-byte | `0x0287`-`0x0289` (647-649) | same 03xx family as above | ☐ | |
| `0914` | 2-byte | alternates ~`0x030B`/`0x0310` (779/784) in blocks | possible duty cycle/counter, paired with `0915` | ☐ | |
| `0915` | 2-byte | `0x018B`/`0x0185` (395/389) | possible pair to `0914` (dual-bank sensor or trim) | ☐ | |
| `9800` | 2-byte | near-constant `0x041E`/`0x0423` (1054/1059), rare ±5 drift | possible status/counter register | ☐ | |
| `F433` | 1-byte | ~61-62 raw | possible F4xx-family temp sensor | ☐ | |
| `F43C` | 2-byte | `0x0408`→`0x04E6` spike | possible high-res temp (EGT/oil?) | ☐ | |
| `F442` | 2-byte | ~12020-12040 | possible manifold/boost pressure | ☐ | |

## Priority 3 — module id confirmation (not DID lookups)

| Item | What's known | What to check |
|---|---|---|
| APIM (SYNC infotainment) = `0x7D0` | User-asserted, never seen in any capture, FORScan also couldn't reach it live | Check Ford's own module list/wiring diagrams for whether `0x7D0` is documented as APIM's request id, and whether APIM sits behind GWM on a separate bus (MS-CAN) not bridged to the tester session |

## After the session

Report back per DID: found/not found, official name, formula, source
page/document name. I'll cross-reference against the existing hypotheses in
`src/frame_analyser.py` and update `DID_NAME_HYPOTHESES` and
`/memories/repo/can-bus-facts.md` only for the ones you confirm — anything
not found stays flagged as unconfirmed, not deleted.
