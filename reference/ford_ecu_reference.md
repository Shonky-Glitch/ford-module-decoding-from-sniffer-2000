# Ford ECU / UDS Reference Data

Reference notes for future UDS/ISO-TP decoding support (see AGENTS.md
"Future responsibilities"). This is research/reference data only — not
wired into any decoding code yet.

## Source

[commaai/opendbc](https://github.com/commaai/opendbc) — MIT-licensed, open
source, actively maintained. These physical CAN addresses are reverse
engineered and have been running in production `openpilot` builds on real
Ford vehicles for years, so confidence is reasonably high. Still,
FORScan itself is closed-source and was not directly available as a
source (site forum is currently down), so treat this as
community-sourced/unofficial rather than OEM-confirmed.

opendbc scopes its Ford ECU list to what its ADAS stack needs (steering,
braking, radar, camera, powertrain) — it does NOT cover the full FORScan
body-module list (instrument cluster, airbag/RCM, BCM, etc.) as
diagnostic UDS request/response addresses.

## Ford UDS module addresses (`opendbc/car/ford/tests/test_ford.py`)

| Module (Ecu enum) | Ford name | CAN request addr |
|---|---|---|
| `engine` | Powertrain Control Module (PCM) | `0x7E0` (standard OBD addr, same as generic SAE J1979) |
| `eps` | Power Steering Control Module (PSCM) | `0x730` |
| `abs` | Anti-Lock Brake System (ABS) | `0x760` |
| `fwdRadar` | Cruise Control Module (CCM) | `0x764` |
| `fwdCamera` | Image Processing Module A (IPMA) | `0x706` |
| `shiftByWire` | Gear Shift Module (GSM) | `0x732` |
| `debug` | Accessory Protocol Interface Module (APIM) | `0x7D0` |

Part-number prefixes used to identify each module's firmware:

- EPS: `14D003`
- ABS: `2D053`
- fwdRadar: `14D049`
- fwdCamera: `14F397` (Ford Q3 connector) / `14H102` (Ford Q4 connector)

## Ford HS-CAN broadcast message IDs (`opendbc/safety/modes/ford.h`)

Not diagnostic request/response addresses — normal bus traffic broadcast
by these modules:

| CAN ID | Message | Source module |
|---|---|---|
| `0x165` | EngBrakeData | PCM (driver brake pedal, cruise state) |
| `0x204` | EngVehicleSpThrottle | PCM (driver throttle input) |
| `0x202` | EngVehicleSpThrottle2 | PCM (second vehicle speed) |
| `0x213` | DesiredTorqBrk | ABS (standstill state) |
| `0x415` | BrakeSysFeatures | ABS (vehicle speed) |
| `0x91`  | Yaw_Data_FD1 | RCM (yaw rate) |

## Still missing (needs further research)

- Full body-module diagnostic addresses: RCM (airbag), IPC (instrument
  cluster), BCM (body control module), HVAC, etc. — opendbc doesn't
  cover these since they're outside its ADAS scope.
- Ford proprietary Mode 22 (`READ_DATA_BY_IDENTIFIER`) DID list beyond
  generic SAE J1979 Mode 01 PIDs.
