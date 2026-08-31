# Ford PX3 confirmed diagnostic discovery/access specification

Confirmed by the vehicle operator on 2026-08-22. These are proven read-only
communication profiles and supported-DID allowlists. A responding DID is not
automatically a decoded gauge; names, units, signedness, byte order, scaling,
and offsets require independent evidence or controlled live-data correlation.

All traffic is 11-bit CAN at 500 kbit/s using UDS service `0x22`.

## Common ReadDataByIdentifier exchange

```text
Request:               TX_ID  03 22 DID_HI DID_LO 00 00 00 00
Positive single-frame: RX_ID  LEN 62 DID_HI DID_LO DATA...
Positive first-frame:  RX_ID  1L LL 62 DID_HI DID_LO DATA...
Flow control:          TX_ID  30 00 00 00 00 00 00 00
Continuation:          RX_ID  21 DATA...
                       RX_ID  22 DATA...
Unsupported DID:       RX_ID  03 7F 22 31 00 00 00 00
```

Reassemble ISO-TP consecutive frames by sequence number until the First
Frame's declared length is satisfied. Allow up to 60 ms for the first response
and for each consecutive frame. Do not send another DID until the preceding
positive response, complete multi-frame response, negative response, or
timeout has been processed.

Recommended full-discovery order:

```text
F100-F1FF
0000-F0FF
F200-FEFF
```

## Completed dual-bus functional sweep (2026-08-29)

The vehicle operator completed a read-only `0000-FFFF` sweep using functional
request ID `7DF` on both buses. The sweep tested `F100-F1FF` first and then all
remaining DIDs. The source bundle was generated in the separate `x2-interface`
project at:

```text
captures/full_sweep_20260829_082902
```

The bundle manifest records `result=complete`, 65,536 DIDs tested, zero CAN
transmit failures, 135,002 CSV frame rows, and a duration of 3,490.15 seconds.
The CSV uses the already-approved discovery layout:
`x2_ms,scan,bus,direction,id,dlc,data`.

The controller's end-of-sweep summary reported 1,741 positive module/DID
results, 84 negative responses, and 14 responding modules:

| Module | Bus | Physical pair | Supported in sweep | Negative | Incomplete multi-frame payloads |
|---|---|---:|---:|---:|---:|
| PCM | CAN1 | `7E0 -> 7E8` | 417 | 0 | 2 |
| TCM | CAN1 | `7E1 -> 7E9` | 85 | 0 | 1 |
| BdyCM | CAN1 | `726 -> 72E` | 404 | 5 | 7 |
| IPMA | CAN2 | `706 -> 70E` | 39 | 0 | 3 |
| GWM | CAN2 | `716 -> 71E` | 75 | 0 | 5 |
| IPC | CAN2 | `720 -> 728` | 127 | 0 | 0 |
| SCCM | CAN2 | `724 -> 72C` | 36 | 0 | 1 |
| ACM | CAN2 | `727 -> 72F` | 113 | 17 | 14 |
| PSCM | CAN2 | `730 -> 738` | 43 | 48 | 0 |
| RCM | CAN2 | `737 -> 73F` | 126 | 12 | 7 |
| RTM | CAN2 | `751 -> 759` | 94 | 0 | 1 |
| ABS | CAN2 | `760 -> 768` | 38 | 2 | 4 |
| TRM | CAN2 | `791 -> 799` | 87 | 0 | 1 |
| FCIM | CAN2 | `7A7 -> 7AF` | 57 | 0 | 1 |

The regenerated Decoding 2000 module inventory contains 1,743 unique
module/DID pairs. That is two more than the controller's in-loop total because
PSCM and RTM each answered the pre-sweep `0202` reachability request but did
not repeat that answer when the main loop reached `0202`. Repeated preflight
and BdyCM wake responses are deduplicated in each module's supported-DID list.

The 47 incomplete multi-frame messages all contain a positive First Frame
prefix (`62 DID_HI DID_LO`), so the DID support result is proven even though
the full value payload was not captured. Do not infer a length, value, string,
formula, or gauge definition from one of those truncated messages. Re-read it
with a targeted physical request and only one active ECU when the complete
payload is required.

This functional sweep confirms the responder IDs and supported-DID results in
the captured session. It does not by itself prove that every DID is available
through a physical request without a session transition. The physical entry,
exit, and wake procedures below remain the authoritative access profiles
where separately proven. Targeted physical access for IPMA, SCCM, ACM, PSCM,
RCM, RTM, ABS, TRM, and FCIM still needs separate confirmation before those
modules are added to the machine-readable physical-access profiles.

### Follow-up module captures `FORD_009` through `FORD_017`

Nine approximately 60-second repeated-read captures were checked from
`input/ford/`:

| Module | Capture | Response | Unique DIDs | Full-sweep set match | Truncated pairs recovered |
|---|---|---:|---:|---:|---:|
| IPMA | `FORD_009_IPMA.CSV` | `70E` | 39 | exact | 3/3 |
| SCCM | `FORD_010_SCCM.CSV` | `72C` | 36 | exact | 1/1 |
| ACM | `FORD_011_ACM.CSV` | `72F` | 113 | exact | 8/14 |
| PSCM | `FORD_012_PSCM.CSV` | `738` | 44 | exact | 0/0 |
| RCM | `FORD_013_RCM.CSV` | `73F` | 126 | exact | 7/7 |
| RTM | `FORD_014_RTM.CSV` | `759` | 95 | exact | 1/1 |
| ABS | `FORD_015_ABS.CSV` | `768` | 38 | exact | 4/4 |
| TRM | `FORD_016_TRM.CSV` | `799` | 87 | exact | 1/1 |
| FCIM | `FORD_017_FCIM.CSV` | `7AF` | 57 | exact | 1/1 |

These are targeted by response filtering/repeated allowlist reads, but they
are still functional-request captures: every `0x22` request uses `7DF`.
The module's physical request ID appears only in `30 00 00` ISO-TP flow-control
frames. Across all nine files there are zero physical `0x22` requests, zero
`0x10` session-control requests, and zero `10 81` exits. Therefore these files
strengthen the supported-DID and payload evidence but do not complete the
physical-access confirmation requested above.

Six ACM payloads never completed despite 24-26 attempts each:

```text
800B C008 DE00 EE80 EE81 FD52
```

Their declared UDS lengths are 75, 244, 53, 147, 219, and 515 bytes
respectively. The capture contains missing ISO-TP Consecutive Frame sequence
numbers before the next request. Re-read these DIDs individually using the
physical `727 -> 72F` pair and a non-zero Flow Control separation time before
treating their payload length or content as captured.

### Direct physical redo `FORD_020` through `FORD_028`

The nine module checks were repeated with every `0x22` request sent to the
module's physical request ID. The resulting captures prove direct read access
for all nine modules:

| Module | Capture | Physical pair | Reachability DID | Supported DIDs |
|---|---|---:|---:|---:|
| IPMA | `FORD_020_IPMA.CSV` | `706 -> 70E` | `40BF` | 39 |
| SCCM | `FORD_021_SCCM.CSV` | `724 -> 72C` | `0202` | 36 |
| ACM | `FORD_022_ACM.CSV` | `727 -> 72F` | `0202` | 113 |
| PSCM | `FORD_023_PSCM.CSV` | `730 -> 738` | `0202` | 44 |
| RCM | `FORD_024_RCM.CSV` | `737 -> 73F` | `0202` | 126 |
| RTM | `FORD_025_RTM.CSV` | `751 -> 759` | `0202` | 95 |
| ABS | `FORD_026_ABS.CSV` | `760 -> 768` | `0202` | 38 |
| FCIM | `FORD_027_FCIM.CSV` | `7A7 -> 7AF` | `0202` | 57 |
| TRM | `FORD_028_TRM.CSV` | `791 -> 799` | `0202` | 87 |

Each physical DID inventory exactly matches the corresponding full functional
sweep inventory. These captures contain zero functional `0x22` requests and
zero `0x10` session-control requests; physical reads receive positive replies
without an explicit session transition. Record the entry and exit procedures
for these nine modules as `none required`. `FORD_019_RCM.CSV` contains only a
header and is an aborted/empty capture; it supplies no evidence and is ignored.

Every supported DID in the nine physical captures has at least one complete
positive response. Physical addressing also recovered complete payloads for
all six ACM DIDs that never completed in the earlier functional follow-up:

```text
800B C008 DE00 EE80 EE81 FD52
```

Some repeated reads still lost individual ISO-TP Consecutive Frames, so a
specific attempt may be incomplete, but no module/DID pair is left without a
complete captured example. These nine modules are now included in
`FORD_MODULE_PROFILES` in `src/ford_profiles.py`.

## PCM

```text
Bus: CAN1
Request/response: 7E0 -> 7E8
Entry session: none required
Reachability DID: 0202
Exit session: none required
Reachability request: 7E0  03 22 02 02 00 00 00 00
Expected prefix:      7E8  .. 62 02 02 ...
```

Confirmed supported DIDs (231):

```text
0202
0301 0302 0303 0304 0308 030A 030B 0311 031E
0322 0324 0325 032B 0333 033C 033D 033E 033F
0347 0357 035A 035D 0370 0371 0373 0374 038F
0394 0396 03A1 03A2 03B5 03B8 03B9 03BA 03BF
03C0 03C2 03C4 03C5 03C8 03DB 03DC 03E1 03EA
03EE 03F0 03F1 03F3 03F4 03F5 03F6 03F9 03FA
03FC 0401 040A 040B 040C 0416 0425 0426 0429
0440 0451 045E 0462 0463 0466 0467 0468 046A
046B 046C 046E 0478 047B 047C 047D 047E 0480
0481 0483 0485 0493 0495 049A 049B 049C 049E
04A0 04A1 04A2 04AA 04AB 04AC 04AD 04AE 04E4
04E5 04E6 04F1 04F5 04F6 04F7 0508 050B 050F
051C 0522 0527 052E 0530 0532 0534 0538 053F
0541 0542 0543 0547 0549 054A 054B 054C 054F
0550 0551 0552 0554 055B 055D 055E 055F 0561
0564 0566 0569 056A 056C 056E 0570 0571 0572
0573 0578 0579 057B 057E 0583 0590 0591 0596
0598 0599 059A 05B8 05BB 05BE 05C2 05C3 05C4
05C5 05C6 05D5 05E0 05E1 05E2 05E3 05E4 05E5
05E6 05E7 05E8 05EF 05FB 0604 0605 0606 0607
0608 0609 060A 060B 060C 060D 060E 060F 0610
0612 0613 0614 0615 0616 0617 0618 0619 061C
061F 0628 062C 0653 06AD 06AE 0700 0701 0702
0703 0704 0705 0707 0709 070D 070E
F108 F110 F111 F112 F113 F15F F162 F163 F166
F180 F188 F18C F190 F196 F1CD F1F3
```

## TCM

```text
Bus: CAN1
Request/response: 7E1 -> 7E9
Entry session: none required
Reachability DID: 0202
Reachability request: 7E1  03 22 02 02 00 00 00 00
Exit:                7E1  02 10 81 00 00 00 00 00
```

No positive response is expected for the suppressed `10 81` exit. Confirmed
supported DIDs (10):

```text
0202 056F 0591 05B8 F111 F15F F163 F166 F188 F18C
```

Multi-frame DIDs: `056F`, `F111`, `F15F`, `F188`, `F18C`. The 120-second
capture covered `F100-F1FF` and approximately `0000-0E1F`; this is an
allowlist, not proof that DIDs outside the scanned ranges are unsupported.

## IPC

```text
Bus: CAN2
Request/response: 720 -> 728
Required session: extended session 03
Reachability DID: 0202
Enter: 720  02 10 03 00 00 00 00 00
Reply: 728  06 50 03 00 32 01 F4 00
Exit:  720  02 10 81 00 00 00 00 00
```

Confirmed supported DIDs (11):

```text
0202 F110 F111 F113 F124 F15F F162 F163 F166 F188 F18C
```

Known raw identification values (identification data, normally not gauges):

```text
F110 = DSJB3T-10849-CF
F111 = JB3T-14F094-KB
F113 = JB3T-10849-PM
F124 = JB3T-14C088-AG
F188 = JB3T-14C026-FE
```

## BdyCM

```text
Bus: CAN1
Functional wake ID: 7DF
Request/response: 726 -> 72E
Required session: default session 01
Reachability DID: 0202
Wake:  7DF  03 22 C1 04 00 00 00 00
Enter: 726  02 10 01 00 00 00 00 00
Reply: 72E  .. 50 01 ...
Exit:  726  02 10 81 00 00 00 00 00
```

Send the wake request three times rapidly, wait approximately 1.45 seconds,
send it once more, then wait approximately 2.16 seconds before entering the
session. Confirmed supported DIDs (19):

```text
0202 F10A F10C F110 F111 F113 F15F F163 F166 F16B
F16C F16D F16E F17C F17D F180 F188 F18C F190
```

Functional DID `C104` is part of the access procedure and must not
automatically be treated as a live-gauge DID.

## GWM

```text
Bus: CAN2
Request/response: 716 -> 71E
Required session: default session 01
Reachability DID: 0202
Enter: 716  02 10 01 00 00 00 00 00
Reply: 71E  06 50 01 00 32 01 F4 00
Exit:  716  02 10 81 00 00 00 00 00
```

Confirmed supported DIDs (18):

```text
0202 F109 F10A F110 F111 F113 F15F F163 F166
F167 F188 F18C F1CD F1CE F1CF F1D2 F1D3 F1D4
```

## Gauge-definition rule

Until controlled testing confirms a signal, store a responding DID as:

```text
name: Unknown DID xxxx
module: module name
bus: CAN1 or CAN2
request_id: physical request ID
response_id: physical response ID
did: xxxx
service: 22
data_offset: after 62 DID_HI DID_LO
length: observed payload length
formula: unknown
unit: raw
status: supported_unresolved
```

Only assign a conversion after correlating raw data with a known physical
value. Formula metadata may include `value_type`, `byte_order`, `start_byte`,
`length_bytes`, optional `bit_mask`/`bit_shift`, confirmed `multiplier`,
`offset`, `unit`, optional limits, evidence, and confidence. The generic form
is:

```text
raw = bytes_to_integer(data[start:start+length], byte_order, signed)
engineering_value = raw * multiplier + offset
```

Never infer multiplier, offset, byte order, signedness, or units from a single
discovery response.
