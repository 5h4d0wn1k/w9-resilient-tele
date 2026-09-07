#!/usr/bin/env python3
"""Byte-exact unit tests for w9-resilient-tele."""

import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from firmware import resilient_tele as rt


class CrcTest(unittest.TestCase):
    def test_crc16_ccitt_check(self):
        self.assertEqual(rt.crc16_ccitt(b"123456789"), 0x29B1)


class FramerTest(unittest.TestCase):
    def setUp(self):
        self.framer = rt.PacketFramer()

    def test_roundtrip(self):
        data = self.framer.frame(b"lab:tele:fine", seq=7, ts=123, flags=0)
        self.assertTrue(self.framer.verify(data))
        parsed = self.framer.unframe(data)
        self.assertEqual(parsed["payload"], b"lab:tele:fine")
        self.assertEqual(parsed["seq"], 7)
        self.assertEqual(parsed["ts"], 123)
        self.assertFalse(parsed["retransmitted"])

    def test_flags(self):
        data = self.framer.frame(b"x", seq=0, flags=self.framer.FLAG_RETRANS | self.framer.FLAG_FAILOVER)
        parsed = self.framer.unframe(data)
        self.assertTrue(parsed["retransmitted"])
        self.assertTrue(parsed["on_failover"])

    def test_bad_magic(self):
        data = bytearray(self.framer.frame(b"payload", seq=1))
        data[0] ^= 0xFF
        self.assertFalse(self.framer.verify(bytes(data)))

    def test_tampered_crc(self):
        data = bytearray(self.framer.frame(b"payload", seq=1))
        data[10] ^= 0xFF  # flip payload byte
        self.assertFalse(self.framer.verify(bytes(data)))

    def test_stream_split(self):
        stream = (self.framer.frame(b"one", seq=0)
                  + b"junk" + self.framer.frame(b"two", seq=1))
        parsed = self.framer.parse_stream(stream)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[1]["payload"], b"two")


class BufferTest(unittest.TestCase):
    def test_enqueue_drain(self):
        buf = rt.StoreForwardBuffer(capacity=2)
        self.assertTrue(buf.enqueue(b"a"))
        self.assertTrue(buf.enqueue(b"b"))
        self.assertFalse(buf.enqueue(b"c"))
        self.assertEqual(buf.length, 2)
        self.assertEqual(buf.drain(), [b"a", b"b"])
        self.assertEqual(buf.length, 0)


class LinkStateMachineTest(unittest.TestCase):
    def test_failover_after_threshold(self):
        link = rt.TelemetryLink(deauth_threshold=3)
        for _ in range(2):
            link.process_event(rt.EventType.DEAUTH)
        self.assertEqual(link.state, rt.LinkState.PRIMARY)
        res = link.process_event(rt.EventType.DEAUTH)
        self.assertEqual(link.state, rt.LinkState.FAILOVER)
        self.assertTrue(res["failover_triggered"])

    def test_recovery(self):
        link = rt.TelemetryLink(recovery_threshold=3)
        for _ in range(3):
            link.process_event(rt.EventType.DEAUTH)
        link.process_event(rt.EventType.ATTACK_END)
        self.assertEqual(link.state, rt.LinkState.RECOVERING)
        for _ in range(3):
            link.process_event(rt.EventType.PACKET)
        self.assertEqual(link.state, rt.LinkState.PRIMARY)

    def test_deterministic(self):
        a = rt.run_timeline(rt.EMBEDDED_TIMELINE)
        b = rt.run_timeline(rt.EMBEDDED_TIMELINE)
        self.assertEqual(a["overall_loss_pct"], b["overall_loss_pct"])


class ResilientPipelineTest(unittest.TestCase):
    def test_sf_retransmits_occur(self):
        report = rt.run_resilient_pipeline(rt.EMBEDDED_TIMELINE)
        self.assertGreater(report["retransmitted"], 0)
        self.assertGreaterEqual(report["buffered"], report["retransmitted"])

    def test_frames_all_crc_verified(self):
        report = rt.run_resilient_pipeline(rt.EMBEDDED_TIMELINE)
        self.assertEqual(report["frames_framed"], report["frames_verified"])

    def test_deterministic_pipeline(self):
        a = rt.run_resilient_pipeline(rt.EMBEDDED_TIMELINE, seed=7)
        b = rt.run_resilient_pipeline(rt.EMBEDDED_TIMELINE, seed=7)
        self.assertEqual(a["packets_lost"], b["packets_lost"])
        self.assertEqual(a["retransmitted"], b["retransmitted"])


class CLITest(unittest.TestCase):
    def test_demo_exit_zero(self):
        self.assertEqual(rt.run_demo(), 0)

    def test_json_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "o.json")
            rc = rt.main(["--json", out])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(out))
            data = json.load(open(out))
            self.assertEqual(data["final_state"], "primary")

    def test_timeline_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            tl = os.path.join(tmp, "tl.json")
            with open(tl, "w") as f:
                json.dump([{"event": "packet"}, {"event": "packet"},
                           {"event": "deauth"}, {"event": "deauth"}, {"event": "deauth"}], f)
            rc = rt.main(["--timeline", tl])
            self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()