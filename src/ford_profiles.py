"""Machine-readable Ford PX3 diagnostic access and supported-DID profiles.

These profiles record only behaviour proven by the vehicle captures.  A DID
listed here is supported, but remains unresolved until a separately curated
name/formula supplies evidence for its physical meaning.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FordModuleProfile:
    name: str
    bus: str
    request_id: str
    response_id: str
    entry_session: str
    reachability_did: str
    exit_session: str
    wake_sequence: str
    discovered_dids: tuple[str, ...]
    discovery_coverage: str


def _codes(value: str) -> tuple[str, ...]:
    return tuple(value.split())


FORD_MODULE_PROFILES: tuple[FordModuleProfile, ...] = (
    FordModuleProfile(
        name="PCM",
        bus="CAN1",
        request_id="7E0",
        response_id="7E8",
        entry_session="none required",
        reachability_did="0202",
        exit_session="none required",
        wake_sequence="none",
        discovered_dids=_codes("""
            0202 0301 0302 0303 0304 0308 030A 030B 0311 031E
            0322 0324 0325 032B 0333 033C 033D 033E 033F 0347
            0357 035A 035D 0370 0371 0373 0374 038F 0394 0396
            03A1 03A2 03B5 03B8 03B9 03BA 03BF 03C0 03C2 03C4
            03C5 03C8 03DB 03DC 03E1 03EA 03EE 03F0 03F1 03F3
            03F4 03F5 03F6 03F9 03FA 03FC 0401 040A 040B 040C
            0416 0425 0426 0429 0440 0451 045E 0462 0463 0466
            0467 0468 046A 046B 046C 046E 0478 047B 047C 047D
            047E 0480 0481 0483 0485 0493 0495 049A 049B 049C
            049E 04A0 04A1 04A2 04AA 04AB 04AC 04AD 04AE 04E4
            04E5 04E6 04F1 04F5 04F6 04F7 0508 050B 050F 051C
            0522 0527 052E 0530 0532 0534 0538 053F 0541 0542
            0543 0547 0549 054A 054B 054C 054F 0550 0551 0552
            0554 055B 055D 055E 055F 0561 0564 0566 0569 056A
            056C 056E 0570 0571 0572 0573 0578 0579 057B 057E
            0583 0590 0591 0596 0598 0599 059A 05B8 05BB 05BE
            05C2 05C3 05C4 05C5 05C6 05D5 05E0 05E1 05E2 05E3
            05E4 05E5 05E6 05E7 05E8 05EF 05FB 0604 0605 0606
            0607 0608 0609 060A 060B 060C 060D 060E 060F 0610
            0612 0613 0614 0615 0616 0617 0618 0619 061C 061F
            0628 062C 0653 06AD 06AE 0700 0701 0702 0703 0704
            0705 0707 0709 070D 070E F108 F110 F111 F112 F113
            F15F F162 F163 F166 F180 F188 F18C F190 F196 F1CD F1F3
        """),
        discovery_coverage="F100-F1FF then 0000 through approximately 070E",
    ),
    FordModuleProfile(
        name="TCM", bus="CAN1", request_id="7E1", response_id="7E9",
        entry_session="none required", reachability_did="0202",
        exit_session="10 81 (suppressed default)", wake_sequence="none",
        discovered_dids=_codes("0202 056F 0591 05B8 F111 F15F F163 F166 F188 F18C"),
        discovery_coverage="F100-F1FF then 0000 through approximately 0E1F",
    ),
    FordModuleProfile(
        name="IPC", bus="CAN2", request_id="720", response_id="728",
        entry_session="10 03 (extended)", reachability_did="0202",
        exit_session="10 81 (suppressed default)", wake_sequence="none",
        discovered_dids=_codes("0202 F110 F111 F113 F124 F15F F162 F163 F166 F188 F18C"),
        discovery_coverage="120-second partial discovery; not a full 16-bit sweep",
    ),
    FordModuleProfile(
        name="BdyCM", bus="CAN1", request_id="726", response_id="72E",
        entry_session="10 01 (default)", reachability_did="0202",
        exit_session="10 81 (suppressed default)",
        wake_sequence="7DF 22 C104 x3; wait 1.45 s; x1; wait 2.16 s",
        discovered_dids=_codes("""
            0202 F10A F10C F110 F111 F113 F15F F163 F166 F16B
            F16C F16D F16E F17C F17D F180 F188 F18C F190
        """),
        discovery_coverage="120-second partial discovery; not a full 16-bit sweep",
    ),
    FordModuleProfile(
        name="GWM", bus="CAN2", request_id="716", response_id="71E",
        entry_session="10 01 (default)", reachability_did="0202",
        exit_session="10 81 (suppressed default)", wake_sequence="none",
        discovered_dids=_codes("""
            0202 F109 F10A F110 F111 F113 F15F F163 F166
            F167 F188 F18C F1CD F1CE F1CF F1D2 F1D3 F1D4
        """),
        discovery_coverage="F100-F1FF then 0000 through approximately 0A89",
    ),
)

FORD_PROFILE_BY_NAME = {profile.name: profile for profile in FORD_MODULE_PROFILES}
FORD_PROFILE_BY_REQUEST_ID = {
    profile.request_id: profile for profile in FORD_MODULE_PROFILES
}

