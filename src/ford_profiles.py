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
    FordModuleProfile(
        name="IPMA", bus="CAN2", request_id="706", response_id="70E",
        entry_session="none required", reachability_did="40BF",
        exit_session="none required", wake_sequence="none",
        discovered_dids=_codes("""
            40BF 416D 41FA 41FB 4293 42A8 A222 D01C D100 D111 D117 D701
            D703 DD00 DD01 DD02 DD05 DD09 F110 F125 F1F0 F1F1 F1F4 F1F9
            FD00 FD01 FD02 FD03 FD04 FD05 FD06 FD07 FD08 FD0A FD10 FD11
            FD12 FD13 FD14
        """),
        discovery_coverage=(
            "Complete 0000-FFFF functional sweep; direct physical reads "
            "reconfirmed in FORD_020_IPMA.CSV"
        ),
    ),
    FordModuleProfile(
        name="SCCM", bus="CAN2", request_id="724", response_id="72C",
        entry_session="none required", reachability_did="0202",
        exit_session="none required", wake_sequence="none",
        discovered_dids=_codes("""
            0202 1E7D 3017 402A 4128 41FA 6025 61C0 7150 803B 803C 833C
            A002 A460 A462 D700 D701 DE00 DE01 DE02 DE03 DE04 DE05 DE06
            DE07 DE08 DE09 DE0A F111 F113 F129 F12A F12B F163 F166 F18C
        """),
        discovery_coverage=(
            "Complete 0000-FFFF functional sweep; direct physical reads "
            "reconfirmed in FORD_021_SCCM.CSV"
        ),
    ),
    FordModuleProfile(
        name="ACM", bus="CAN2", request_id="727", response_id="72F",
        entry_session="none required", reachability_did="0202",
        exit_session="none required", wake_sequence="none",
        discovered_dids=_codes("""
            0202 1505 411F 7140 7215 8003 800B 8012 801D 801E 8022 802F
            8032 8033 8035 8036 8037 803D 8041 8051 8053 8054 8133 8304
            8306 8307 8308 830A 830B 830D 8321 8322 833B 833C 9927 C006
            C007 C008 C150 D100 D111 D704 D705 DD00 DD01 DD09 DD0A DE00
            EE00 EE01 EE20 EE30 EE31 EE40 EE53 EE80 EE81 EE82 EE85 EE86
            EE87 EE88 EE89 EE8A EE8B EE8C EE8D EE8E EE8F EE90 EE91 EE92
            EE93 EE94 EE95 EE96 EE97 EE98 EEA0 F0E8 F0E9 F109 F10A F110
            F111 F113 F120 F122 F123 F124 F129 F12A F141 F142 F143 F17C
            F17E F180 F1D0 F1D1 F1D9 F40C F411 FD43 FD44 FD47 FD48 FD49
            FD50 FD52 FD53 FD54 FE60
        """),
        discovery_coverage=(
            "Complete 0000-FFFF functional sweep; direct physical reads "
            "reconfirmed in FORD_022_ACM.CSV"
        ),
    ),
    FordModuleProfile(
        name="PSCM", bus="CAN2", request_id="730", response_id="738",
        entry_session="none required", reachability_did="0202",
        exit_session="none required", wake_sequence="none",
        discovered_dids=_codes("""
            0202 2031 203D 3002 3003 3012 3301 3302 330C 3B4B D007 D111
            D117 D118 D700 D701 DD00 DD01 DE01 F10A F111 F124 F162 F163
            F166 F169 F180 F18A F18C F190 F40D FEE1 FEE2 FEE3 FEE4 FEE5
            FEE6 FEE7 FEE8 FEE9 FEEB FEED FEEE FEF0
        """),
        discovery_coverage=(
            "Complete 0000-FFFF functional sweep; direct physical reads "
            "reconfirmed in FORD_023_PSCM.CSV"
        ),
    ),
    FordModuleProfile(
        name="RCM", bus="CAN2", request_id="737", response_id="73F",
        entry_session="none required", reachability_did="0202",
        exit_session="none required", wake_sequence="none",
        discovered_dids=_codes("""
            0202 5817 5B03 5B04 5B05 5B06 5B07 5B08 5B09 5B0A 5B0B 5B0C
            5B0D 5B0E 5B0F 5B10 5B13 5B17 5B18 5B25 5B27 5B28 5B29 5B2B
            5B2C 5B2D 5B2E 5B2F 5B30 5B32 5B34 5B35 5B36 5B37 5B38 5B39
            5B3A 5B3B 5B3C 5B3D 5B3E 5B3F 5B40 5B41 5B42 5B43 5B44 5B4B
            5B4C 5B53 5B56 61A5 D017 D100 D112 D703 DD00 DD01 DD02 DD0A
            EE00 F110 F141 F142 F143 F144 F145 F146 F14B F14D F14E F14F
            F150 F188 F18C F190 FD03 FD14 FD33 FD35 FD37 FD38 FD39 FD3E
            FD3F FD40 FD41 FD42 FD43 FD44 FD45 FD46 FD47 FD48 FD49 FD50
            FD51 FD53 FD54 FD72 FD73 FD96 FD97 FD99 FD9A FD9D FDA0 FDAD
            FDB3 FDB4 FDB9 FDBA FDBB FDBD FDBE FDE0 FDE3 FDE5 FE1C FE1D
            FE1E FE22 FE23 FE25 FE26 FEA0
        """),
        discovery_coverage=(
            "Complete 0000-FFFF functional sweep; direct physical reads "
            "reconfirmed in FORD_024_RCM.CSV"
        ),
    ),
    FordModuleProfile(
        name="RTM", bus="CAN2", request_id="751", response_id="759",
        entry_session="none required", reachability_did="0202",
        exit_session="none required", wake_sequence="none",
        discovered_dids=_codes("""
            0202 2829 282A 282B 282C 282D 282E 41F9 41FC 424D C211 C243
            C244 C245 C246 C247 C252 C253 C254 C255 C256 C25B D100 D111
            D701 DE02 DE03 F15A F15F F163 F166 F180 F1F3 F1F4 F1F5 F1F7
            F1F8 F1F9 F1FA F1FB F1FC F1FD FD00 FD01 FD02 FD03 FD04 FD08
            FD0D FD10 FD11 FD17 FD18 FD19 FD1A FD1B FD1C FD1D FD1E FD1F
            FD20 FD21 FD22 FD23 FD24 FD25 FD26 FD27 FD28 FD29 FD2A FD2C
            FD2D FD2E FD2F FD30 FD31 FD32 FD33 FD34 FD35 FD36 FD37 FD38
            FD39 FD3A FD3B FD3C FD3D FD3F FD40 FD43 FD48 FD4A FD4B
        """),
        discovery_coverage=(
            "Complete 0000-FFFF functional sweep; direct physical reads "
            "reconfirmed in FORD_025_RTM.CSV"
        ),
    ),
    FordModuleProfile(
        name="ABS", bus="CAN2", request_id="760", response_id="768",
        entry_session="none required", reachability_did="0202",
        exit_session="none required", wake_sequence="none",
        discovered_dids=_codes("""
            0202 201D 2861 2862 2B00 2B06 2B07 2B08 2B09 2B0B 2B0C 2B0D
            2B11 2B12 2B22 2B2C 2B32 3302 4045 7217 D111 DE00 DE01 DE02
            F10A F110 F111 F113 F15F F162 F163 F166 F18C F194 F195 F40D
            FD00 FD02
        """),
        discovery_coverage=(
            "Complete 0000-FFFF functional sweep; direct physical reads "
            "reconfirmed in FORD_026_ABS.CSV"
        ),
    ),
    FordModuleProfile(
        name="TRM", bus="CAN2", request_id="791", response_id="799",
        entry_session="none required", reachability_did="0202",
        exit_session="none required", wake_sequence="none",
        discovered_dids=_codes("""
            0202 3B52 40C8 40DF 40E1 40F5 41D4 41F1 41F6 D111 D700 D701
            DE01 DE02 F110 F111 F113 F124 F15A F180 F188 F1F3 F1F4 F1F5
            F1F6 F1F8 F1F9 F1FB F1FC F1FD FD03 FD04 FD17 FD18 FD19 FD1A
            FD1B FD1C FD1D FD1E FD1F FD20 FD21 FD24 FD25 FD26 FD27 FD28
            FD29 FD2A FD2B FD2C FD30 FD31 FD32 FD33 FD34 FD35 FD36 FD37
            FD38 FD39 FD40 FD43 FD50 FD51 FD53 FD54 FD55 FD56 FD57 FD59
            FD67 FD70 FD71 FD72 FD73 FD74 FD75 FD77 FD80 FD81 FD82 FD83
            FD84 FD85 FD87
        """),
        discovery_coverage=(
            "Complete 0000-FFFF functional sweep; direct physical reads "
            "reconfirmed in FORD_028_TRM.CSV"
        ),
    ),
    FordModuleProfile(
        name="FCIM", bus="CAN2", request_id="7A7", response_id="7AF",
        entry_session="none required", reachability_did="0202",
        exit_session="none required", wake_sequence="none",
        discovered_dids=_codes("""
            0202 4056 4057 411F 711B 9801 9855 9869 9924 9927 9938 995A
            9972 99A2 99A3 9B00 9B01 9B03 9B04 9B05 D100 D111 D700 D701
            EE02 EE03 EE05 EE06 EE07 F159 F15A F15C F15E F15F F160 F161
            F162 F163 F166 F188 FD34 FD35 FD40 FD41 FD42 FD44 FD46 FD47
            FD4A FD4B FD55 FD61 FD62 FD70 FD71 FD79 FD7E
        """),
        discovery_coverage=(
            "Complete 0000-FFFF functional sweep; direct physical reads "
            "reconfirmed in FORD_027_FCIM.CSV"
        ),
    ),
)

FORD_PROFILE_BY_NAME = {profile.name: profile for profile in FORD_MODULE_PROFILES}
FORD_PROFILE_BY_REQUEST_ID = {
    profile.request_id: profile for profile in FORD_MODULE_PROFILES
}
