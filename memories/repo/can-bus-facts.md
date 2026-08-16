# CAN-bus facts

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

