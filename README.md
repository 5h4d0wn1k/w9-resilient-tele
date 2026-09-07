# W9 — Attack-resilient dual-band telemetry (HC-12 failover) — w9-resilient-tele

Pure-Python simulation of a dual-band telemetry link with automatic 433 MHz HC-12 failover when the primary Wi-Fi / ESP-NOW link is attacked by deauth storm or jamming.

## Overview

This project simulates a telemetry system that monitors primary-link health, detects attack conditions (deauth storms, jamming), triggers failover to a secondary 433 MHz HC-12 radio link, and recovers when the primary link returns to normal. A comprehensive metrics report quantifies failover performance, packet loss, and false-failover events.

## Features

- Dual-link simulation: primary Wi-Fi / ESP-NOW + 433 MHz HC-12 failover
- Deauth-storm and jamming detection with configurable thresholds
- Automatic failover trigger and recovery logic
- Per-phase packet-loss tracking (normal, attack, post-attack)
- False-failover counting for tuning sensitivity
- Configurable packet-loss rates per link
- Fully offline — no hardware required
- Python ≥ 3.8, standard library only

## Installation

```bash
# No installation required
python3 firmware/resilient_tele.py
```

## Usage

```python
from firmware.resilient_tele import run_timeline, EventType

timeline = [{"event": "PACKET"}, {"event": "DEAUTH"}, ...]
report = run_timeline(timeline, deauth_threshold=3)
print(report["failover_count"], report["overall_loss_pct"])
```

## Example Output

```
==============================================================
 W9 — Attack-resilient dual-band telemetry (HC-12 failover)
==============================================================

  Timeline events      : 52
  Final link state     : primary
  Packets sent         : 43
  Packets received     : 39
  Packets lost         : 4
  Overall loss %       : 9.3
  Failover count       : 2
  False failover count : 1
  Attack-phase loss %  : 100.0
  Post-attack loss %   : 0.0

  Trace (first 12 events):
    PACKET               primary      → primary
    ...
    DEAUTH               primary      → primary
    DEAUTH               primary      → primary
    DEAUTH               primary      → failover   ← FAILOVER

==============================================================
 Result: PASS
==============================================================
```

## IMPORTANT: Read before use.

### Authorization Requirements

You must have explicit written authorisation before testing any telemetry or radio system. Unauthorised transmission on 433 MHz ISM band or interference with wireless communications is prohibited in most jurisdictions.

### Legal Framework

This tool is a simulation only and does not transmit radio signals. However, if the concepts herein are applied to real hardware, the Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030, and FCC regulations (47 CFR Part 15) govern unauthorised access and transmission. Violations may result in criminal prosecution, fines, and civil liability.

### Acceptable Use

Use this simulation for learning about resilient telemetry design, authorised security testing of your own radio systems, and academic research in wireless failover strategies. Never deploy simulated attack techniques against networks you do not own without explicit permission.

### Prohibited Use

Do not use the concepts or code from this project to jam, deauth, or otherwise interfere with wireless communications you do not own. Do not deploy HC-12 or similar ISM-band radios without proper licensing. Do not radiate on 433 MHz or any ISM/Part 15 channel outside a licensed, authorized, shield-attenuated lab. Any use that violates applicable law or regulatory requirements is strictly prohibited.

### Regulatory Framework
- **Federal Communications Act (47 U.S.C. § 333)**: Willful interference with authorized radio communications is prohibited.
- **47 CFR Part 15**: Radiating intentionally on 433 MHz / 2.4 GHz outside compliance limits is regulated; this repo is a pure simulation and emits nothing.
- **CFAA (18 U.S.C. § 1030)** and state computer-crime laws apply to interference with or interception of telemetry systems without authorization.

## Live Lab Test Plan

Offline (this repo, no radio):
1. `python3 firmware/resilient_tele.py` — run the 49-event embedded timeline through the
   HC-12 failover state machine + store-and-forward; expect PASS, exit 0.
2. `python3 firmware/resilient_tele.py --seed 7 --json reports/w9.json`
   — deterministic metrics (exit 0).
3. Custom timeline: `{"event":"packet","event":"packet","event":"deauth",...}` as JSON via
   `--timeline tl.json` (exit 0).
4. `python3 -m unittest discover -s tests` — byte-exact CRC16/framing tests pass (exit 0).

Authorized lab (only with written scope + shield + licensed ISM bench):
5. Wire two HC-12 modules on a licensed/authorized 433 MHz bench to two lab SBCs; run the
   same event timeline and verify the failover/open+retransmit behavior matches the simulation.
6. `green = permitted`: simulation only by default; any real 433 MHz radiation must be on an
   authorized channel with an attenuator and written lab scope.

## Metrics

- Frame model (byte-exact): magic "W9"(2) seq(u16) ts(u32) flags(u8) len(u8) payload CRC16
  (CCITT-FALSE 0x1021); parse_stream splits concatenated frames
- Link state machine: PRIMARY -> FAILOVER on deauth/jamming threshold, RECOVERING ->
  PRIMARY on clean-packet threshold; explicit FAILOVER_TRIGGER/RECOVERY events
- Store-and-forward: frames lost on primary/recovering are buffered and retransmitted
  (RETRANS + FAILOVER flags) on failover/recovery
- Metrics: packets sent/received/lost, overall + attack + post-attack loss %, failover counts,
  buffered, retransmitted, frames framed vs CRC-verified
- Deterministic: seeded RNG (default 42); same seed + timeline == same output
- Offline simulation only; no radio; reports/ gitignored

- Test suite: `python3 -m unittest discover -s tests`
- Reports: `reports/` (gitignored)

## License

MIT
