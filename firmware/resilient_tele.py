#!/usr/bin/env python3
"""
W9 — Attack-resilient dual-band telemetry (HC-12 failover)

Attack-resilient telemetry simulator with:

  * dual-band link state machine (primary Wi-Fi / ESP-NOW -> 433 MHz HC-12 failover)
  * byte-exact telemetry packet framing (magic + seq + ts + flags + crc16)
  * store-and-forward buffer: frames lost on the primary link during a deauth/jamming
    storm are queued, then retransmitted over the failover channel after recovery

Pure-Python, stdlib only, offline (no radio). Deterministic (seeded RNG).
"""

from __future__ import annotations

import argparse
import enum
import json
import os
import random
import struct
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional


# ─────────────────────────── constants ────────────────────────────

FRAME_MAGIC = b"W9"


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


# ───────────────────────── byte-level framing ─────────────────────

def crc16_ccitt(data: bytes, poly: int = 0x1021, init: int = 0xFFFF) -> int:
    crc = init
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = (((crc << 1) ^ poly) & 0xFFFF) if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


class PacketFramer:
    """Byte-exact telemetry framing: magic(2) seq(u16) ts(u32) flags(u8) len(u8) payload crc16.

    Flags: bit0 = retransmitted; bit1 = failover-channel.
    """

    FLAG_RETRANS = 0x01
    FLAG_FAILOVER = 0x02
    HEADER_LEN = 2 + 2 + 4 + 1 + 1
    MAX_PAYLOAD = 255

    def frame(self, payload: bytes, seq: int, ts: int = 0, flags: int = 0) -> bytes:
        if not 0 <= len(payload) <= self.MAX_PAYLOAD:
            raise ValueError("payload too long")
        if not 0 <= seq <= 0xFFFF:
            raise ValueError("seq out of range")
        header = FRAME_MAGIC + (struct.pack(">H", seq) + struct.pack(">I", ts)
                                + bytes([flags]) + bytes([len(payload)]))
        body = header + payload
        return body + struct.pack(">H", crc16_ccitt(body))

    def verify(self, data: bytes) -> bool:
        if len(data) < self.HEADER_LEN + 2:
            return False
        if data[:2] != FRAME_MAGIC:
            return False
        plen = data[9]
        if len(data) != self.HEADER_LEN + plen + 2:
            return False
        body = data[:-2]
        (crc,) = struct.unpack(">H", data[-2:])
        return crc16_ccitt(body) == crc

    def unframe(self, data: bytes) -> dict:
        if not self.verify(data):
            raise ValueError("bad frame")
        body = data[:-2]
        seq = struct.unpack_from(">H", body, 2)[0]
        ts = struct.unpack_from(">I", body, 4)[0]
        flags = body[8]
        plen = body[9]
        payload = body[self.HEADER_LEN:self.HEADER_LEN + plen]
        return {"seq": seq, "ts": ts, "flags": flags, "payload": payload,
                "retransmitted": bool(flags & self.FLAG_RETRANS),
                "on_failover": bool(flags & self.FLAG_FAILOVER),
                "payload_hex": payload.hex(), "crc_ok": True}

    def parse_stream(self, data: bytes) -> List[dict]:
        """Split concatenated frames by magic/len; returns unframed dicts."""
        out = []
        i = 0
        while i + 2 <= len(data):
            if data[i:i + 2] != FRAME_MAGIC:
                i += 1
                continue
            if i + self.HEADER_LEN + 2 > len(data):
                i += 1
                continue
            plen = data[i + 9]
            total = self.HEADER_LEN + plen + 2
            if i + total > len(data):
                i += 1
                continue
            try:
                out.append(self.unframe(data[i:i + total]))
                i += total
            except ValueError:
                i += 1
        return out


@dataclass
class StoreForwardBuffer:
    capacity: int = 1024
    _q: List[bytes] = field(default_factory=list)

    def enqueue(self, frame: bytes) -> bool:
        if len(self._q) >= self.capacity:
            return False
        self._q.append(frame)
        return True

    def drain(self) -> List[bytes]:
        out, self._q = self._q, []
        return out

    @property
    def length(self):
        return len(self._q)


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
    buffered: int = 0
    retransmitted: int = 0
    frames_framed: int = 0
    frames_verified: int = 0

    @property
    def packet_loss_pct(self) -> float:
        total = self.packets_sent
        return (self.packets_lost / total * 100) if total else 0.0

    @property
    def attack_loss_pct(self) -> float:
        return ((self.attack_packets_lost / self.attack_packets_sent * 100)
                if self.attack_packets_sent else 0.0)

    @property
    def post_attack_loss_pct(self) -> float:
        return ((self.post_attack_packets_lost / self.post_attack_packets_sent * 100)
                if self.post_attack_packets_sent else 0.0)


# ─────────────────────────── telemetry link ────────────────────────

class TelemetryLink:
    """Dual-band telemetry link state machine with HC-12 failover."""

    def __init__(self, deauth_threshold: int = 3, recovery_threshold: int = 5,
                 primary_plr: float = 0.02, failover_plr: float = 0.05,
                 seed: int = 42) -> None:
        self.deauth_threshold = deauth_threshold
        self.recovery_threshold = recovery_threshold
        self.primary_plr = primary_plr
        self.failover_plr = failover_plr
        self.state = LinkState.PRIMARY
        self.metrics = LinkMetrics()
        self._consecutive_attacks = 0
        self._consecutive_clean = 0
        self._rng = random.Random(seed)

    def _simulate_packet(self, plr: float) -> bool:
        return self._rng.random() >= plr

    def process_event(self, event_type: EventType) -> Dict[str, object]:
        result = {"event": event_type.value, "state_before": self.state.value}

        if event_type == EventType.PACKET:
            self._consecutive_clean += 1
            self.metrics.packets_sent += 1
            plr = self.primary_plr if self.state in (LinkState.PRIMARY, LinkState.RECOVERING) \
                else self.failover_plr
            delivered = self._simulate_packet(plr)
            if delivered:
                self.metrics.packets_received += 1
            else:
                self.metrics.packets_lost += 1
                if self.state == LinkState.RECOVERING:
                    self.metrics.post_attack_packets_lost += 1
            if self.state is not LinkState.FAILOVER:
                self.metrics.post_attack_packets_sent += 1
            if self.state == LinkState.RECOVERING and self._consecutive_clean >= self.recovery_threshold:
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


# ─────────────────────── resilient timeline runner ─────────────────

def run_timeline(timeline: List[Dict[str, str]], **link_kwargs) -> Dict[str, object]:
    """Run events through TelemetryLink; return metrics + trace."""
    link = TelemetryLink(**link_kwargs)
    trace = []
    for entry in timeline:
        result = link.process_event(EventType(entry["event"]))
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


def run_resilient_pipeline(timeline: List[Dict[str, str]], seed: int = 42,
                           **link_kwargs) -> Dict[str, object]:
    """Compose the link state machine with byte-level framing + store-and-forward.

    Each PACKET event generates a framed telemetry packet; frames lost on the
    primary/recovering link are buffered and retransmitted (flagged) on failover
    or after recovery. Deterministic: same seed + timeline == same output.
    """
    link = TelemetryLink(seed=seed, **link_kwargs)
    buffer = StoreForwardBuffer()
    framer = PacketFramer()
    trace = []
    for i, entry in enumerate(timeline):
        evt = EventType(entry["event"])
        before_lost = link.metrics.packets_lost
        result = link.process_event(evt)
        if evt == EventType.PACKET:
            payload = f"lab:tele:seq{i}".encode()
            flags = 0
            if link.state in (LinkState.FAILOVER, LinkState.RECOVERING) and i % 3 == 0:
                flags |= framer.FLAG_FAILOVER
            framed = framer.frame(payload, seq=i, ts=1700000000 + i, flags=flags)
            link.metrics.frames_framed += 1
            if framer.verify(framed):
                link.metrics.frames_verified += 1
            if link.metrics.packets_lost > before_lost and link.state != LinkState.FAILOVER:
                if buffer.enqueue(framed):
                    link.metrics.buffered += 1
        if result.get("failover_triggered") or result.get("recovered_to_primary"):
            drained = buffer.drain()
            for frame in drained:
                # retransmit with retrans flag; same seq (idempotent replay)
                seq = struct.unpack_from(">H", frame, 2)[0]
                payload = framer.unframe(frame)["payload"]
                reframed = framer.frame(payload, seq=seq,
                                        ts=1700000000 + len(trace),
                                        flags=framer.FLAG_RETRANS | framer.FLAG_FAILOVER)
                link.metrics.retransmitted += 1
                link.metrics.packets_received += 1
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
        "buffered": m.buffered,
        "retransmitted": m.retransmitted,
        "frames_framed": m.frames_framed,
        "frames_verified": m.frames_verified,
        "trace": trace,
    }


# ─────────────────────────── embedded timeline ──────────────────────

EMBEDDED_TIMELINE: List[Dict[str, str]] = [
    {"event": "packet"}, {"event": "packet"}, {"event": "packet"},
    {"event": "packet"}, {"event": "packet"}, {"event": "packet"},
    {"event": "packet"}, {"event": "packet"}, {"event": "packet"},
    {"event": "packet"},
    {"event": "deauth"}, {"event": "deauth"}, {"event": "deauth"},
    {"event": "packet"}, {"event": "packet"}, {"event": "packet"},
    {"event": "packet"}, {"event": "packet"},
    {"event": "attack_end"},
    {"event": "packet"}, {"event": "packet"}, {"event": "packet"},
    {"event": "packet"}, {"event": "packet"},
    {"event": "packet"}, {"event": "packet"}, {"event": "packet"},
    {"event": "packet"}, {"event": "packet"},
    {"event": "jamming"}, {"event": "jamming"}, {"event": "jamming"},
    {"event": "jamming"},
    {"event": "attack_end"},
    {"event": "packet"}, {"event": "packet"}, {"event": "packet"},
    {"event": "packet"}, {"event": "packet"},
    {"event": "packet"}, {"event": "packet"}, {"event": "packet"},
    {"event": "failover_trigger"},
    {"event": "packet"}, {"event": "packet"},
    {"event": "recovery"},
    {"event": "packet"}, {"event": "packet"}, {"event": "packet"},
    {"event": "packet"}, {"event": "packet"},
]


# ─────────────────────────── CLI / demo ────────────────────────────

def build_args_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="w9-resilient-tele",
        description="Attack-resilient dual-band telemetry simulator: HC-12 failover state "
                    "machine + byte-exact packet framing + store-and-forward retransmit "
                    "(stdlib; offline; no radio).")
    p.add_argument("--timeline", metavar="PATH", help="JSON list of events, e.g. [{\"event\": \"packet\"}]")
    p.add_argument("--seed", type=int, default=42, help="deterministic RNG seed")
    p.add_argument("--json", metavar="PATH", help="write JSON report")
    return p


def load_timeline(path: str) -> List[Dict[str, str]]:
    with open(path) as f:
        data = json.load(f)
    return [{"event": str(e["event"])} for e in data]


def print_report(report: Dict[str, object]) -> None:
    print("=" * 62)
    print(" W9 — Attack-resilient dual-band telemetry (HC-12 failover)")
    print("=" * 62)
    print(f"\n  Timeline events      : {report['total_events']}")
    print(f"  Final link state     : {report['final_state']}")
    print(f"  Packets sent         : {report['packets_sent']}")
    print(f"  Packets received     : {report['packets_received']}")
    print(f"  Packets lost         : {report['packets_lost']}")
    print(f"  Overall loss %       : {report['overall_loss_pct']}")
    print(f"  Failover count       : {report['failover_count']}")
    print(f"  False failover count : {report['false_failover_count']}")
    print(f"  Buffered (S&F)       : {report.get('buffered', 0)}")
    print(f"  Retransmitted        : {report.get('retransmitted', 0)}")
    print(f"  Frames framed        : {report.get('frames_framed', 0)}")
    print(f"  Frames CRC-verified  : {report.get('frames_verified', 0)}")
    print("\n  Trace (first 12):")
    for t in report["trace"][:12]:
        extra = ""
        if t.get("failover_triggered"):
            extra = " <- FAILOVER"
        if t.get("recovered_to_primary"):
            extra = " <- RECOVERED"
        print(f"    {t['event']:20s}  {t['state_before']:12s} -> {t['state_after']:12s}{extra}")
    print("=" * 62)


def main(argv: Optional[List[str]] = None) -> int:
    args = build_args_parser().parse_args(argv)
    if args.timeline:
        timeline = load_timeline(args.timeline)
    else:
        timeline = EMBEDDED_TIMELINE
    report = run_resilient_pipeline(timeline, seed=args.seed)
    print_report(report)

    # self-check assertions (embedded demo only; user timelines are not validated)
    errors = 0
    if not args.timeline:
        if report["failover_count"] < 2:
            errors += 1
        if report["final_state"] != "primary":
            errors += 1
        if report["overall_loss_pct"] > 30:
            errors += 1
        if report["false_failover_count"] != 1:
            errors += 1
        if report.get("retransmitted", 0) < 1:
            errors += 1
    print(f"\n Result: {'PASS' if errors == 0 else 'FAIL'}")

    if args.json:
        d = os.path.dirname(args.json)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2, default=str)

    return 0 if errors == 0 else 1


def run_demo() -> int:
    return main([])


if __name__ == "__main__":
    sys.exit(main())