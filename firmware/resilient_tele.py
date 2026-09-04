#!/usr/bin/env python3
"""
W9 — Attack-resilient dual-band telemetry (HC-12 failover)

Pure-Python simulation of a dual-band telemetry link with automatic
433 MHz (HC-12) failover when the primary Wi-Fi / ESP-NOW link is
attacked (deauth storm or jamming).

No external dependencies required — Python >= 3.8 stdlib only.
"""

from __future__ import annotations

import enum
import hashlib
import os
import random
import secrets
import struct
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ─────────────────────────── constants ────────────────────────────

class LinkState(enum.Enum):
    PRIMARY = "primary"
    FAILOVER = "failover"
    RECOVERING = "recovering"
    DOWN = "down"


class EventType(enum.Enum):
    PACKET = "packet"
    DEAUTH = "deauth"
    JAMMING = "jamming"
    ATTACK_END = "attack_end"
    FAILOVER_TRIGGER = "failover_trigger"
    RECOVERY = "recovery"


# ─────────────────────────── data model ────────────────────────────

@dataclass
class LinkMetrics:
    packets_sent: int = 0
    packets_received: int = 0
    packets_lost: int = 0
    failover_count: int = 0
    false_failover_count: int = 0
    attack_packets_lost: int = 0
    attack_packets_sent: int = 0
    post_attack_packets_lost: int = 0
    post_attack_packets_sent: int = 0

    @property
    def packet_loss_pct(self) -> float:
        total = self.packets_sent
        return (self.packets_lost / total * 100) if total else 0.0

    @property
    def attack_loss_pct(self) -> float:
        return (
            (self.attack_packets_lost / self.attack_packets_sent * 100)
            if self.attack_packets_sent
            else 0.0
        )

    @property
    def post_attack_loss_pct(self) -> float:
        return (
            (self.post_attack_packets_lost / self.post_attack_packets_sent * 100)
            if self.post_attack_packets_sent
            else 0.0
        )


# ─────────────────────────── telemetry link ────────────────────────

class TelemetryLink:
    """Simulates a dual-band telemetry link with HC-12 failover.

    Parameters
    ----------
    deauth_threshold : int
        Consecutive deauth/jamming events before triggering failover.
    recovery_threshold : int
        Consecutive clean packets after an attack before recovering.
    primary_plr : float
        Baseline packet-loss rate on the primary link (0.0–1.0).
    failover_plr : float
        Packet-loss rate on the HC-12 failover link.
    """

    def __init__(
        self,
        deauth_threshold: int = 3,
        recovery_threshold: int = 5,
        primary_plr: float = 0.02,
        failover_plr: float = 0.05,
    ) -> None:
        self.deauth_threshold = deauth_threshold
        self.recovery_threshold = recovery_threshold
        self.primary_plr = primary_plr
        self.failover_plr = failover_plr

        self.state = LinkState.PRIMARY
        self.metrics = LinkMetrics()
        self._consecutive_attacks = 0
        self._consecutive_clean = 0
        self._rng = random.Random(42)

    def _simulate_packet(self, plr: float) -> bool:
        """Return True if packet is successfully delivered."""
        return self._rng.random() >= plr

    def process_event(self, event_type: EventType) -> Dict[str, object]:
        """Process a single timeline event and return the resulting state."""
        result: Dict[str, object] = {
            "event": event_type.value,
            "state_before": self.state.value,
        }

        if event_type == EventType.PACKET:
            self._consecutive_clean += 1
            if self.state == LinkState.PRIMARY:
                self.metrics.packets_sent += 1
                delivered = self._simulate_packet(self.primary_plr)
                if delivered:
                    self.metrics.packets_received += 1
                else:
                    self.metrics.packets_lost += 1
            elif self.state == LinkState.FAILOVER:
                self.metrics.packets_sent += 1
                delivered = self._simulate_packet(self.failover_plr)
                if delivered:
                    self.metrics.packets_received += 1
                else:
                    self.metrics.packets_lost += 1
            elif self.state == LinkState.RECOVERING:
                self.metrics.packets_sent += 1
                delivered = self._simulate_packet(self.primary_plr)
                if delivered:
                    self.metrics.packets_received += 1
                else:
                    self.metrics.packets_lost += 1
                if self._consecutive_clean >= self.recovery_threshold:
                    self.state = LinkState.PRIMARY
                    self._consecutive_clean = 0
                    result["recovered_to_primary"] = True

        elif event_type in (EventType.DEAUTH, EventType.JAMMING):
            self._consecutive_attacks += 1
            self._consecutive_clean = 0
            if self.state == LinkState.PRIMARY:
                self.metrics.packets_sent += 1
                self.metrics.attack_packets_sent += 1
                self.metrics.packets_lost += 1
                self.metrics.attack_packets_lost += 1
                if self._consecutive_attacks >= self.deauth_threshold:
                    self.state = LinkState.FAILOVER
                    self.metrics.failover_count += 1
                    result["failover_triggered"] = True
            elif self.state == LinkState.RECOVERING:
                # Attack resumed during recovery — revert to failover
                self.state = LinkState.FAILOVER
                self.metrics.packets_sent += 1
                self.metrics.attack_packets_sent += 1
                self.metrics.packets_lost += 1
                self.metrics.attack_packets_lost += 1
                self.metrics.failover_count += 1
                result["failover_triggered"] = True

        elif event_type == EventType.ATTACK_END:
            self._consecutive_attacks = 0
            if self.state == LinkState.FAILOVER:
                self.state = LinkState.RECOVERING

        elif event_type == EventType.FAILOVER_TRIGGER:
            # Explicit external failover request
            if self.state == LinkState.PRIMARY:
                self.state = LinkState.FAILOVER
                self.metrics.failover_count += 1
                self.metrics.false_failover_count += 1
                result["failover_triggered"] = True

        elif event_type == EventType.RECOVERY:
            if self.state != LinkState.PRIMARY:
                self.state = LinkState.PRIMARY
                result["recovered_to_primary"] = True

        result["state_after"] = self.state.value
        return result


# ─────────────────────────── timeline runner ────────────────────────

def run_timeline(
    timeline: List[Dict[str, str]],
    **link_kwargs,
) -> Dict[str, object]:
    """Run a list of events through a TelemetryLink and return metrics.

    Parameters
    ----------
    timeline : list[dict]
        Each dict must have key "event" whose value is an EventType name.
    **link_kwargs
        Forwarded to TelemetryLink constructor.

    Returns
    -------
    dict with the final LinkMetrics and a per-event trace.
    """
    link = TelemetryLink(**link_kwargs)
    trace: List[Dict[str, object]] = []

    for entry in timeline:
        evt = EventType(entry["event"])
        result = link.process_event(evt)
        trace.append(result)

    m = link.metrics
    return {
        "total_events": len(timeline),
        "final_state": link.state.value,
        "packets_sent": m.packets_sent,
        "packets_received": m.packets_received,
        "packets_lost": m.packets_lost,
        "overall_loss_pct": round(m.packet_loss_pct, 2),
        "failover_count": m.failover_count,
        "false_failover_count": m.false_failover_count,
        "attack_loss_pct": round(m.attack_loss_pct, 2),
        "post_attack_loss_pct": round(m.post_attack_loss_pct, 2),
        "trace": trace,
    }


# ─────────────────────────── embedded timeline ──────────────────────

EMBEDDED_TIMELINE: List[Dict[str, str]] = [
    # Normal traffic
    {"event": "packet"}, {"event": "packet"}, {"event": "packet"},
    {"event": "packet"}, {"event": "packet"}, {"event": "packet"},
    {"event": "packet"}, {"event": "packet"}, {"event": "packet"},
    {"event": "packet"},
    # Deauth storm (3 consecutive → failover)
    {"event": "deauth"}, {"event": "deauth"}, {"event": "deauth"},
    # Traffic continues on failover
    {"event": "packet"}, {"event": "packet"}, {"event": "packet"},
    {"event": "packet"}, {"event": "packet"},
    # Attack ends → recovery begins
    {"event": "attack_end"},
    {"event": "packet"}, {"event": "packet"}, {"event": "packet"},
    {"event": "packet"}, {"event": "packet"},  # recovery threshold met
    # Normal traffic resumes
    {"event": "packet"}, {"event": "packet"}, {"event": "packet"},
    {"event": "packet"}, {"event": "packet"},
    # Jamming attack
    {"event": "jamming"}, {"event": "jamming"}, {"event": "jamming"},
    {"event": "jamming"},
    {"event": "attack_end"},
    {"event": "packet"}, {"event": "packet"}, {"event": "packet"},
    {"event": "packet"}, {"event": "packet"},  # recovery
    {"event": "packet"}, {"event": "packet"}, {"event": "packet"},
    # False failover trigger (external)
    {"event": "failover_trigger"},
    {"event": "packet"}, {"event": "packet"},
    # Recovery
    {"event": "recovery"},
    {"event": "packet"}, {"event": "packet"}, {"event": "packet"},
    {"event": "packet"}, {"event": "packet"},
]


# ─────────────────────────── offline demo ──────────────────────────

def main() -> int:
    """Offline self-test: run the embedded timeline and print a report."""
    print("=" * 62)
    print(" W9 — Attack-resilient dual-band telemetry (HC-12 failover)")
    print("=" * 62)

    report = run_timeline(EMBEDDED_TIMELINE)

    print(f"\n  Timeline events      : {report['total_events']}")
    print(f"  Final link state     : {report['final_state']}")
    print(f"  Packets sent         : {report['packets_sent']}")
    print(f"  Packets received     : {report['packets_received']}")
    print(f"  Packets lost         : {report['packets_lost']}")
    print(f"  Overall loss %       : {report['overall_loss_pct']}")
    print(f"  Failover count       : {report['failover_count']}")
    print(f"  False failover count : {report['false_failover_count']}")
    print(f"  Attack-phase loss %  : {report['attack_loss_pct']}")
    print(f"  Post-attack loss %   : {report['post_attack_loss_pct']}")

    # Print abbreviated trace
    print(f"\n  Trace (first 12 events):")
    for t in report["trace"][:12]:
        fb = t.get("failover_triggered")
        rc = t.get("recovered_to_primary")
        extra = ""
        if fb:
            extra = " ← FAILOVER"
        if rc:
            extra = " ← RECOVERED"
        print(f"    {t['event']:20s}  {t['state_before']:12s} → {t['state_after']:12s}{extra}")

    # --- assertions ---
    errors = 0
    if report["failover_count"] < 2:
        print("\nFAIL: expected at least 2 failovers")
        errors += 1
    if report["final_state"] != "primary":
        print(f"FAIL: expected final state 'primary', got '{report['final_state']}'")
        errors += 1
    if report["overall_loss_pct"] > 30:
        print(f"FAIL: overall loss {report['overall_loss_pct']}% exceeds 30% threshold")
        errors += 1
    if report["false_failover_count"] != 1:
        print(f"FAIL: expected 1 false failover, got {report['false_failover_count']}")
        errors += 1

    status = "PASS" if errors == 0 else "FAIL"
    print(f"\n{'=' * 62}")
    print(f" Result: {status}")
    print("=" * 62)
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
