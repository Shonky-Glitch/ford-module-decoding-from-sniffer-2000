# CAN-bus facts

## 2026-08-22 — Confirmed Ford PX3 discovery/access specification

- The vehicle operator supplied and confirmed the consolidated Ford PX3
  discovery/access specification. The complete communication formulas,
  timing rules, session requirements, and exact supported-DID allowlists are
  preserved in `reference/ford_px3_discovery_access_spec.md`.
- Confirmed supported-DID counts are: PCM 231, TCM 10, IPC 11, BdyCM 19,
  and GWM 18. These are supported/readable identifiers, not automatically
  decoded gauges.
- Confirmed access profiles: PCM `7E0 -> 7E8` on CAN1 with no session entry;
  TCM `7E1 -> 7E9` on CAN1 with no session entry; IPC `720 -> 728` on CAN2
  requiring extended session `10 03`; BdyCM `726 -> 72E` on CAN1 requiring
  its `7DF -> 22 C104` wake and default session `10 01`; GWM `716 -> 71E`
  on CAN2 requiring default session `10 01`. All use 11-bit CAN at 500 kbit/s.
- Preserve the supplied gauge-definition rule: discovery-only DIDs remain
  `supported_unresolved` with raw data and unknown formula/unit until
  controlled testing or independent evidence confirms interpretation.

## 2026-08-22 — TCM supported-DID discovery profile

- `input/ford/FORD_005  descovery.CSV` confirms the TCM physical
  request/response pair on CAN1 as `7E1 -> 7E9`. The TCM is already present
  in `CONFIRMED_MODULE_NAMES` under this address pair.
- Use this confirmed-supported DID allowlist for future TCM
  supported-DIDs-only discovery scans:

  ```text
  0202
  056F
  0591
  05B8
  F111
  F15F
  F163
  F166
  F188
  F18C
  ```

- These 10 identifiers are confirmed as readable/supported by this TCM;
  their engineering meanings, units, and scaling are not established by
  this discovery capture.
- The capture begins with successful TCM DID `0202` and PCM reference DID
  `0202` responses. It scans TCM DIDs `F100` through `F1FF`, then `0000`
  through `0E1F`, and transmits `10 81` at exit. It does not contain the
  beginning of the diagnostic-session exchange, so no session-entry or wake
  sequence is asserted from this file.
- Multi-frame positive responses are present for `F111`, `F15F`, `F188`,
  `F18C`, and `056F`; reassemble them by ISO-TP sequence number rather than
  treating continuation frames as separate responses.

## 2026-08-22 — Proven BdyCM discovery profile

- The vehicle operator confirmed this BdyCM access profile for permanent use:
  CAN1 at 500 kbit/s; wake with functional request `7DF -> 22 C104`;
  physical request/response pair `726 -> 72E`; enter the default diagnostic
  session with `10 01`; exit with `10 81`.
- The completed BdyCM discovery found these 19 supported DIDs: `0202`, `F10A`,
  `F10C`, `F110`, `F111`, `F113`, `F15F`, `F163`, `F166`, `F16B`, `F16C`,
  `F16D`, `F16E`, `F17C`, `F17D`, `F180`, `F188`, `F18C`, and `F190`.
- Ford Discovery build direction confirmed by the operator: retain a separate
  full-discovery option; add a supported-DIDs-only BdyCM scan to avoid repeated
  `7F 22 31` traffic; exclude IPMA from the combined long scan until its access
  sequence is established; retain PCM as the CAN1 reference; retain the CAN2
  address-discovery page for choosing the next module.

## 2026-08-22 — GWM supported-DID discovery profile

- `input/ford/FORD_004 CAN 2 GWM descovery.CSV` confirms the GWM physical
  request/response pair on CAN2 as `716 -> 71E`.
- Entering the default diagnostic session with `10 01` received the positive
  response `50 01`. DID `0202` also received a positive response. The capture
  transmitted `10 81` at exit but ended without recording a response.
- Use this confirmed-supported DID allowlist for future GWM supported-DIDs-only
  discovery scans:

  ```text
  0202
  F109
  F10A
  F110
  F111
  F113
  F15F
  F163
  F166
  F167
  F188
  F18C
  F1CD
  F1CE
  F1CF
  F1D2
  F1D3
  F1D4
  ```

- These 18 identifiers are confirmed as readable/supported by this GWM; their
  engineering meanings, units, and scaling are not confirmed by this capture.
- The discovery completed `F100` through `F1FF`, then scanned `0000` through
  `0A89` before exiting. It issued 2,955 DID requests, produced 19 positive
  response instances (DID `0202` was read twice), and produced 2,936
  `7F 22 31` responses. No functional `7DF -> 22 C104` wake was present.
- PCM DID `0202` on CAN1 (`7E0 -> 7E8`) was retained as the reference probe.
- Several multi-frame responses were recorded in CSV row order `21`, `23`,
  `22`; reassemble those responses by ISO-TP sequence number rather than by row
  order alone.

## 2026-08-18 — CAN2 ignition/start capture annotation

- The vehicle operator confirmed the controlled sequence in
  `input/ford/log_001_ign start.csv` as: KEY ON -> ACC ON -> IGN ON -> START,
  then a second START, followed by ACC and KEY OUT.
- Two start/run windows are visible at approximately 26.3-38.8 seconds and
  74.8-86.3 seconds relative to capture start.
- Raw broadcast ids `167`, `200`, and `204` visibly correlate with those
  windows, but their signal names, bit layouts, and scaling are not confirmed.
  They must remain unidentified until controlled per-state holds isolate the
  responsible byte/bit fields.
- Passive broadcast signals now use `reference/can_signals.csv`, separately
  from the diagnostic PID/DID reference.

## 2026-08-16 — FORScan discovery and Ford PX2 gateway access

- User confirmed that captures containing both `CAN1` and `CAN2` are from
  FORScan. Treat those captures as known-working FORScan sessions when
  researching module discovery and diagnostic access.
- APIM is not working on this vehicle and is excluded from the current gateway
  access investigation. Do not use the unanswered `7D0` probes as evidence for
  or against the general discovery procedure.
- Full-corpus analysis (57 Ford CSV logs) found no universal gateway-opening
  request and no SecurityAccess (`0x27`) sequence used for read-only module
  discovery.
- FORScan reaches modules by selecting the correct physical CAN channel and
  probing each module's request arbitration ID individually. The GWM is itself
  a normal UDS endpoint on CAN2 (`716` request -> `71E` response); opening a
  session with the GWM does not cause every other module to return its data.
- Exact successful GWM exchange in `input/ford/log_049.csv`:

  ```text
  CAN2 716 02-10-01-00-00-00-00-00
  CAN2 71E 06-50-01-00-32-01-F4-00
  CAN2 716 03-22-02-02-00-00-00-00
  CAN2 71E 04-62-02-02-00-00-00-00
  ```

- The first pair enters the default diagnostic session and receives a positive
  response. The second pair requests DID `0202` and receives the value for that
  specific DID. The physical meaning of DID `0202` is not confirmed here.
- FORScan discovery uses targeted requests such as `0x10` session control,
  `0x22` ReadDataByIdentifier, `0x19` ReadDTCInformation, and `0x3E`
  TesterPresent. A UDS ECU answers only the requested DID/service; it does not
  dump every supported PID/DID automatically.
- Standard OBD service `01` is a separate case: supported-PID requests such as
  PID `00`, `20`, and `40` return bitmaps for their respective standard PID
  ranges. This does not enumerate proprietary UDS DIDs.
- Confirmed working request/response pairs observed during FORScan operation:

  | Bus | Module | Request | Response |
  | --- | --- | --- | --- |
  | CAN1 | PCM | `7E0` | `7E8` |
  | CAN1 | TCM | `7E1` | `7E9` |
  | CAN1 | BdyCM | `726` | `72E` |
  | CAN2 | IPMA | `706` | `70E` |
  | CAN2 | GWM | `716` | `71E` |
  | CAN2 | IPC | `720` | `728` |
  | CAN2 | SCCM | `724` | `72C` |
  | CAN2 | ACM | `727` | `72F` |
  | CAN2 | PSCM | `730` | `738` |
  | CAN2 | RCM | `737` | `73F` |
  | CAN2 | RTM | `751` | `759` |
  | CAN2 | ABS | `760` | `768` |
  | CAN2 | TRM | `791` | `799` |
  | CAN2 | FCIM | `7A7` | `7AF` |
