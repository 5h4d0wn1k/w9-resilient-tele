#!/usr/bin/env python3
"""802.11a/b/g/n management-frame byte-level engine (pure stdlib).

Hand-implemented builders/parsers for the 802.11 management frame address
formats (IEEE 802.11-2020) used across the W-series lab:

  * MAC address encode/decode
  * Frame Control field encode/decode
  * Management frame header (dur + DA/SA/BSSID + SeqCtl)
  * Tagged Information Elements (IE/TLV) encode/decode
  * Beacon, Probe Request, Probe Response, Deauth, Disassociation,
    Authentication builders & parsers
  * Frame Check Sequence (IEEE CRC-32) compute/verify
  * IEEE control / reason / status code tables
  * pcap (classic) frame reader/writer for synthetic offline fixtures

No external dependencies. Every builder round-trips with its parser so
byte-exact unit tests can lock down the wire format.
"""

from __future__ import annotations

import struct
import zlib

# ----------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------

# Frame Control bit layout
FC_VERSION = 0x0
FC_TYPE_MGMT = 0x0
FC_TYPE_CTRL = 0x1
FC_TYPE_DATA = 0x2

FC_SUBTYPE_ASSOC_REQ = 0x0
FC_SUBTYPE_ASSOC_RESP = 0x1
FC_SUBTYPE_PROBE_REQ = 0x4
FC_SUBTYPE_PROBE_RESP = 0x5
FC_SUBTYPE_AUTH = 0xB
FC_SUBTYPE_DEAUTH = 0xC
FC_SUBTYPE_ACTION = 0xD
FC_SUBTYPE_DISASSOC = 0xA
FC_SUBTYPE_BEACON = 0x8

FC_FLAG_TO_DS = 0x1 << 8
FC_FLAG_FROM_DS = 0x1 << 9
FC_FLAG_MORE_FRAG = 0x1 << 10
FC_FLAG_RETRY = 0x1 << 11
FC_FLAG_PWR_MGMT = 0x1 << 12
FC_FLAG_MORE_DATA = 0x1 << 13
FC_FLAG_PROTECTED = 0x1 << 14
FC_FLAG_ORDER = 0x1 << 15

SUBTYPE_NAMES = {
    FC_SUBTYPE_ASSOC_REQ: "assoc-req",
    FC_SUBTYPE_ASSOC_RESP: "assoc-resp",
    FC_SUBTYPE_PROBE_REQ: "probe-request",
    FC_SUBTYPE_PROBE_RESP: "probe-response",
    FC_SUBTYPE_AUTH: "auth",
    FC_SUBTYPE_DEAUTH: "deauth",
    FC_SUBTYPE_ACTION: "action",
    FC_SUBTYPE_DISASSOC: "disassoc",
    FC_SUBTYPE_BEACON: "beacon",
}

# IE element IDs (IEEE 802.11-2020 Table 9-77)
IE_SSID = 0
IE_SUPPORTED_RATES = 1
IE_DS_PARAMS = 3
IE_TIM = 5
IE_RSN = 48
IE_EXTENDED_RATES = 50
IE_HT_CAP = 45
IE_VENDOR = 221
IE_HT_INFO = 61
IE_EXT_CAP = 127

# Reason codes: IEEE 802.11-2020 Table 9-45
REASON_CODES = {
    1: "Unspecified reason",
    2: "Previous authentication no longer valid",
    3: "Deauthenticated because sending STA is leaving (or has left) IBSS or ESS",
    4: "Disassociated due to inactivity",
    5: "Disassociated because AP is unable to handle all currently associated STAs",
    6: "Class 2 frame received from nonauthenticated STA",
    7: "Class 3 frame received from nonassociated STA",
    8: "Disassociated because sending STA is leaving BSS",
    9: "STA requesting (re)association is not authenticated with responding STA",
    10: "Disassociated because the information in the Power Capability element is unacceptable",
    12: "Disassociated because the information in the Supported Channels element is unacceptable",
    14: "MIC failure",
    15: "4-way handshake timeout",
    16: "Group key handshake timeout",
    17: "Information element in 4-way handshake frame different from (re)association request",
    18: "Invalid group cipher",
    19: "Invalid pairwise cipher",
    20: "Invalid AKMP",
    21: "Unsupported RSNE version",
    22: "Invalid RSNE capabilities",
    23: "IEEE 802.1X authentication failed",
    24: "Cipher suite rejected because of security policy",
    34: "Disassociated due to low ACK",
    40: "Disassociated since STA is not responding to a request",
}

STATUS_CODES = {
    0: "Successful",
    1: "Unspecified failure",
    10: "Cannot support all requested capabilities in the Capability Information field",
    12: "Association denied due to reason outside the scope of this standard",
    13: "Responding STA does not support the specified authentication algorithm",
    14: "Received an Authentication frame with authentication transaction sequence number out of expected sequence",
    15: "Authentication rejected because of challenge failure",
    16: "Authentication rejected due to timeout waiting for next frame in sequence",
    17: "Association denied because AP is unable to handle additional associated STAs",
    18: "Association denied due to requesting STA not supporting all of the data rates in the BSSBasicRateSet parameter",
}

# Authentication algorithm values (IEEE 802.11-2020 Table 9-44)
AUTH_ALG_OPEN = 0
AUTH_ALG_SHARED = 1
AUTH_ALG_SAE = 3

AUTH_ALG_NAMES = {
    AUTH_ALG_OPEN: "open-system",
    AUTH_ALG_SHARED: "shared-key",
    AUTH_ALG_SAE: "SAE/OWE",
}

# ----------------------------------------------------------------------
# MAC address helpers
# ----------------------------------------------------------------------


def mac_bytes(mac: str) -> bytes:
    """Encode 'aa:bb:cc:dd:ee:ff' (or 12 hex chars) into 6 bytes."""
    if isinstance(mac, bytes):
        if len(mac) != 6:
            raise ValueError("MAC bytes must be 6 octets")
        return mac
    clean = mac.replace("-", ":").replace(".", ":").lower()
    parts = clean.split(":")
    if len(parts) == 1 and len(clean) == 12:
        parts = [clean[i:i + 2] for i in range(0, 12, 2)]
    if len(parts) != 6:
        raise ValueError(f"invalid MAC: {mac!r}")
    out = bytearray()
    for p in parts:
        if len(p) != 2:
            raise ValueError(f"invalid octet {p!r} in MAC {mac!r}")
        out.append(int(p, 16))
    return bytes(out)


def mac_str(b: bytes) -> str:
    if len(b) != 6:
        raise ValueError("MAC must be 6 octets")
    return ":".join(f"{x:02x}" for x in b)


BROADCAST = bytes([0xFF] * 6)
BROADCAST_STR = "ff:ff:ff:ff:ff:ff"

# Laboratory placeholders (allow-listed MACs / SSIDs for the offline lab).
LAB_MAC = "00:11:22:33:44:55"
LAB_MAC2 = "00:11:22:33:44:66"


def is_locally_administered(mac: bytes) -> bool:
    return bool(mac[0] & 0x02)


def is_broadcast(mac: bytes) -> bool:
    return mac == BROADCAST


def is_multicast(mac: bytes) -> bool:
    return bool(mac[0] & 0x01)


def is_lab_mac(mac: bytes) -> bool:
    """True if MAC starts with the laboratory OUI 00:11:22."""
    return mac[:3] == bytes([0x00, 0x11, 0x22])


# ----------------------------------------------------------------------
# Frame Control
# ----------------------------------------------------------------------


def encode_frame_control(subtype: int, version: int = 0, _type: int = FC_TYPE_MGMT,
                         flags: int = 0) -> bytes:
    fc = (version & 0x3) | ((_type & 0x3) << 2) | ((subtype & 0xF) << 4) | flags
    return struct.pack("<H", fc)


def decode_frame_control(fc_bytes: bytes) -> dict:
    if len(fc_bytes) != 2:
        raise ValueError("Frame Control must be exactly 2 octets")
    fc = struct.unpack("<H", fc_bytes)[0]
    return {
        "version": fc & 0x3,
        "type": (fc >> 2) & 0x3,
        "subtype": (fc >> 4) & 0xF,
        "to_ds": bool(fc & FC_FLAG_TO_DS),
        "from_ds": bool(fc & FC_FLAG_FROM_DS),
        "more_frag": bool(fc & FC_FLAG_MORE_FRAG),
        "retry": bool(fc & FC_FLAG_RETRY),
        "pwr_mgmt": bool(fc & FC_FLAG_PWR_MGMT),
        "more_data": bool(fc & FC_FLAG_MORE_DATA),
        "protected": bool(fc & FC_FLAG_PROTECTED),
        "order": bool(fc & FC_FLAG_ORDER),
        "raw": fc,
    }


def fc_type_str(fc: dict) -> str:
    t = fc["type"]
    if t == FC_TYPE_MGMT:
        return "management"
    if t == FC_TYPE_CTRL:
        return "control"
    if t == FC_TYPE_DATA:
        return "data"
    return f"reserved-{t}"


def fc_subtype_str(fc: dict) -> str:
    if fc["type"] != FC_TYPE_MGMT:
        return f"subtype-{fc['subtype']}"
    return SUBTYPE_NAMES.get(fc["subtype"], f"mgmt-{fc['subtype']}")


# ----------------------------------------------------------------------
# Sequence control
# ----------------------------------------------------------------------


def encode_seq_control(seq_num: int, frag_num: int = 0) -> bytes:
    seq = ((seq_num & 0xFFF) << 4) | (frag_num & 0xF)
    return struct.pack("<H", seq)


def decode_seq_control(seq_bytes: bytes) -> dict:
    seq = struct.unpack("<H", seq_bytes)[0]
    return {"frag_num": seq & 0xF, "seq_num": (seq >> 4) & 0xFFF}


# ----------------------------------------------------------------------
# Management header (Address3 format)
# ----------------------------------------------------------------------


def build_mgmt_header(subtype: int, da: str, sa: str, bssid: str | None = None,
                      seq_num: int = 0, frag_num: int = 0, flags: int = 0,
                      version: int = 0) -> bytes:
    """Build Frame Control + Duration + DA/SA/BSSID + SeqCtl for a mgmt frame."""
    da_b = mac_bytes(da)
    sa_b = mac_bytes(sa)
    bssid_b = mac_bytes(bssid if bssid is not None else da)
    fc = encode_frame_control(subtype, version=version, _type=FC_TYPE_MGMT, flags=flags)
    # Duration 0 for management frames in our offline simulation
    dur = struct.pack("<H", 0)
    seq = encode_seq_control(seq_num, frag_num)
    return fc + dur + da_b + sa_b + bssid_b + seq


def parse_mgmt_header(raw: bytes) -> tuple[dict, bytes]:
    """Parse a management-frame header, returning (fields, remainder)."""
    if len(raw) < 24:
        raise ValueError(f"management header too short ({len(raw)} bytes < 24)")
    fc = decode_frame_control(raw[0:2])
    if fc["type"] != FC_TYPE_MGMT:
        raise ValueError(f"not a management frame (type={fc['type']})")
    da = mac_str(raw[4:10])
    sa = mac_str(raw[10:16])
    bssid = mac_str(raw[16:22])
    seq = decode_seq_control(raw[22:24])
    return {
        "fc": fc,
        "duration": struct.unpack("<H", raw[2:4])[0],
        "da": da,
        "sa": sa,
        "bssid": bssid,
        "seq_num": seq["seq_num"],
        "frag_num": seq["frag_num"],
        "subtype": fc_subtype_str(fc),
        "subtype_val": fc["subtype"],
        "type": fc_type_str(fc),
        "is_broadcast": is_broadcast(raw[4:10]),
        "is_lab_mac_da": is_lab_mac(raw[4:10]),
        "is_lab_mac_sa": is_lab_mac(raw[10:16]),
        "is_lab_bssid": is_lab_mac(raw[16:22]),
        "locally_administered_sa": is_locally_administered(raw[10:16]),
    }, raw[24:]


# ----------------------------------------------------------------------
# Information Elements (TLV tags)
# ----------------------------------------------------------------------


def encode_ie(elem_id: int, payload: bytes) -> bytes:
    if len(payload) > 255:
        raise ValueError("IE payload exceeds 255 bytes")
    return bytes([elem_id & 0xFF, len(payload)]) + payload


def build_ssid_ie(ssid: str) -> bytes:
    return encode_ie(IE_SSID, ssid.encode("utf-8"))


def parse_ssid_ie(ie_bytes: bytes) -> str:
    eid, length = ie_bytes[0], ie_bytes[1]
    if eid != IE_SSID:
        raise ValueError(f"element {eid} is not an SSID")
    return ie_bytes[2:2 + length].decode("utf-8", errors="replace")


def build_rates_ie(rates_mbps: list[int]) -> bytes:
    return encode_ie(IE_SUPPORTED_RATES, bytes(rates_mbps))


def build_rsn_ie(pairwise: list[int] | None = None, group: int = 0x04,
                 akm: list[int] | None = None, capabilities: int = 0) -> bytes:
    """Build an RSNE (RSN information element, element ID 48).

    Minimal fixed skeleton: version=1, group cipher, pairwise count+suite(s),
    AKM count+suite(s), capabilities. Ciphers are the numeric cipher suite.
    """
    pairwise = pairwise or [0x04]
    akm = akm or [0x02]
    body = struct.pack("<H", 1)                      # version
    body += struct.pack("<H", group)                 # group cipher suite
    body += struct.pack("<H", len(pairwise))         # pairwise suite count
    for c in pairwise:
        body += b"\x00\x0f\xac" + bytes([c])         # vendor OUI 00:0F:AC
    body += struct.pack("<H", len(akm))              # AKM suite count
    for a in akm:
        body += b"\x00\x0f\xac" + bytes([a])         # vendor OUI 00:0F:AC
    body += struct.pack("<H", capabilities)          # RSN capabilities
    return encode_ie(IE_RSN, body)


def parse_ie_sequence(payload: bytes) -> list[dict]:
    """Parse a concatenated IE/TLV sequence into a list of {id,length,value}."""
    out = []
    i = 0
    while i < len(payload):
        if i + 2 > len(payload):
            break
        eid = payload[i]
        length = payload[i + 1]
        if i + 2 + length > len(payload):
            # truncated/malformed tag
            out.append({"id": eid, "length": length, "value": payload[i + 2:], "malformed": True})
            break
        out.append({"id": eid, "length": length, "value": payload[i + 2:i + 2 + length],
                    "malformed": False})
        i += 2 + length
    return out


def find_ssid(ies: list[dict]) -> str | None:
    for ie in ies:
        if ie["id"] == IE_SSID and not ie["malformed"]:
            return ie["value"].decode("utf-8", errors="replace") or "<hidden>"
    return None


# ----------------------------------------------------------------------
# Beacon
# ----------------------------------------------------------------------
# Body: timestamp(8) + beacon interval(2) + capability(2) + IEs


def build_beacon(bssid: str, ssid: str = "lab-test-net", timestamp: int = 0,
                 beacon_interval: int = 100, capability: int = 0x0431,
                 rates: list[int] | None = None, seq_num: int = 0, **ie_payloads) -> bytes:
    """Build a complete beacon management frame (pure bytes)."""
    rates = rates or [0x82, 0x84, 0x0b, 0x16]
    hdr = build_mgmt_header(FC_SUBTYPE_BEACON, BROADCAST_STR, bssid, bssid, seq_num=seq_num)
    body = struct.pack("<QH", timestamp & 0xFFFFFFFFFFFFFFFF, beacon_interval & 0xFFFF)
    body += struct.pack("<H", capability & 0xFFFF)
    body += build_ssid_ie(ssid)
    body += build_rates_ie(rates)
    if ie_payloads.get("ds_param") is not None:
        body += encode_ie(IE_DS_PARAMS, bytes([ie_payloads["ds_param"]]))
    if ie_payloads.get("vendor"):                      # covert-channel vendor IE
        body += encode_ie(IE_VENDOR, ie_payloads["vendor"])
    if ie_payloads.get("rsn"):
        body += ie_payloads["rsn"]
    if ie_payloads.get("extra_ies"):
        body += ie_payloads["extra_ies"]
    return hdr + body


def parse_beacon(raw: bytes) -> tuple[dict, list[dict]]:
    """Parse a beacon; returns (fields, list of parsed IEs)."""
    fields, rest = parse_mgmt_header(raw)
    if fields["subtype_val"] != FC_SUBTYPE_BEACON:
        raise ValueError(f"frame is not a beacon (subtype={fields['subtype']})")
    if len(rest) < 12:
        raise ValueError("beacon body too short")
    timestamp = struct.unpack("<Q", rest[0:8])[0]
    interval = struct.unpack("<H", rest[8:10])[0]
    capability = struct.unpack("<H", rest[10:12])[0]
    ies = parse_ie_sequence(rest[12:])
    fields["timestamp"] = timestamp
    fields["beacon_interval"] = interval
    fields["capability"] = capability
    fields["ssid"] = find_ssid(ies)
    fields["ie_count"] = len(ies)
    return fields, ies


# ----------------------------------------------------------------------
# Probe Request / Response
# ----------------------------------------------------------------------


def build_probe_request(ssid: str = "", sa: str = LAB_MAC, bssid: str = BROADCAST_STR,
                        seq_num: int = 0) -> bytes:
    hdr = build_mgmt_header(FC_SUBTYPE_PROBE_REQ, bssid, sa, bssid, seq_num=seq_num)
    body = build_ssid_ie(ssid)
    body += build_rates_ie([0x82, 0x84, 0x8b, 0x96])
    return hdr + body


def parse_probe_request(raw: bytes) -> tuple[dict, str]:
    fields, rest = parse_mgmt_header(raw)
    if fields["subtype_val"] != FC_SUBTYPE_PROBE_REQ:
        raise ValueError(f"frame is not a probe request (subtype={fields['subtype']})")
    ies = parse_ie_sequence(rest)
    fields["ssid"] = find_ssid(ies)
    fields["ie_count"] = len(ies)
    return fields, fields["ssid"]


def build_probe_response(bssid: str, ssid: str = "lab-test-net", timestamp: int = 0,
                         beacon_interval: int = 100, capability: int = 0x0431,
                         sa: str | None = None, seq_num: int = 0) -> bytes:
    sa = sa or bssid
    hdr = build_mgmt_header(FC_SUBTYPE_PROBE_RESP, LAB_MAC, sa, bssid, seq_num=seq_num)
    body = struct.pack("<QH", timestamp & 0xFFFFFFFFFFFFFFFF, beacon_interval & 0xFFFF)
    body += struct.pack("<H", capability & 0xFFFF)
    body += build_ssid_ie(ssid)
    body += build_rates_ie([0x82, 0x84, 0x0b, 0x16])
    return hdr + body


def parse_probe_response(raw: bytes) -> tuple[dict, str]:
    fields, rest = parse_mgmt_header(raw)
    if fields["subtype_val"] != FC_SUBTYPE_PROBE_RESP:
        raise ValueError(f"frame is not a probe response (subtype={fields['subtype']})")
    timestamp = struct.unpack("<Q", rest[0:8])[0]
    interval = struct.unpack("<H", rest[8:10])[0]
    capability = struct.unpack("<H", rest[10:12])[0]
    ies = parse_ie_sequence(rest[12:])
    fields["timestamp"] = timestamp
    fields["beacon_interval"] = interval
    fields["capability"] = capability
    fields["ssid"] = find_ssid(ies)
    fields["ie_count"] = len(ies)
    return fields, fields["ssid"]


# ----------------------------------------------------------------------
# Deauth / Disassociation
# ----------------------------------------------------------------------


def build_deauth(da: str, sa: str, bssid: str | None = None, reason: int = 7,
                 seq_num: int = 0, flags: int = 0) -> bytes:
    bssid = bssid or sa
    hdr = build_mgmt_header(FC_SUBTYPE_DEAUTH, da, sa, bssid, seq_num=seq_num, flags=flags)
    body = struct.pack("<H", reason & 0xFFFF)
    return hdr + body


def parse_deauth(raw: bytes) -> dict:
    fields, rest = parse_mgmt_header(raw)
    if fields["subtype_val"] != FC_SUBTYPE_DEAUTH:
        raise ValueError(f"frame is not deauth (subtype={fields['subtype']})")
    if len(rest) < 2:
        raise ValueError("deauth frame has no reason code")
    reason = struct.unpack("<H", rest[0:2])[0]
    fields["reason_code"] = reason
    fields["reason_text"] = REASON_CODES.get(reason, f"Unknown ({reason})")
    return fields


def build_disassoc(da: str, sa: str, bssid: str | None = None, reason: int = 8,
                   seq_num: int = 0) -> bytes:
    bssid = bssid or sa
    hdr = build_mgmt_header(FC_SUBTYPE_DISASSOC, da, sa, bssid, seq_num=seq_num)
    body = struct.pack("<H", reason & 0xFFFF)
    return hdr + body


def parse_disassoc(raw: bytes) -> dict:
    fields, rest = parse_mgmt_header(raw)
    if fields["subtype_val"] != FC_SUBTYPE_DISASSOC:
        raise ValueError(f"frame is not disassoc (subtype={fields['subtype']})")
    if len(rest) < 2:
        raise ValueError("disassoc frame has no reason code")
    fields["reason_code"] = struct.unpack("<H", rest[0:2])[0]
    fields["reason_text"] = REASON_CODES.get(fields["reason_code"],
                                             f"Unknown ({fields['reason_code']})")
    return fields


# ----------------------------------------------------------------------
# Authentication
# ----------------------------------------------------------------------


def build_auth(da: str, sa: str, bssid: str | None = None, auth_alg: int = AUTH_ALG_OPEN,
               transaction: int = 1, status: int = 0, seq_num: int = 0) -> bytes:
    bssid = bssid or sa
    hdr = build_mgmt_header(FC_SUBTYPE_AUTH, da, sa, bssid, seq_num=seq_num)
    body = struct.pack("<HHH", auth_alg & 0xFFFF, transaction & 0xFFFF, status & 0xFFFF)
    return hdr + body


def parse_auth(raw: bytes) -> dict:
    fields, rest = parse_mgmt_header(raw)
    if fields["subtype_val"] != FC_SUBTYPE_AUTH:
        raise ValueError(f"frame is not auth (subtype={fields['subtype']})")
    if len(rest) < 6:
        raise ValueError("auth frame too short")
    alg, transaction, status = struct.unpack("<HHH", rest[0:6])
    fields["auth_alg"] = alg
    fields["auth_alg_name"] = AUTH_ALG_NAMES.get(alg, f"alg-{alg}")
    fields["transaction"] = transaction
    fields["status_code"] = status
    fields["status_text"] = STATUS_CODES.get(status, f"Unknown ({status})")
    return fields


# ----------------------------------------------------------------------
# Frame Check Sequence (IEEE 802.3 / 802.11 CRC-32)
# ----------------------------------------------------------------------


def fcs(raw: bytes, with_fcs: bool = False) -> bytes:
    """Compute the 4-byte IEEE CRC-32 used as the 802.11 FCS.

    Drop the trailing FCS first if present (with_fcs=True) so it is not
    included in the CRC input.
    """
    data = raw[:-4] if with_fcs else raw
    crc = zlib.crc32(data) & 0xFFFFFFFF
    return struct.pack("<I", crc)


def verify_fcs(frame_with_fcs: bytes) -> bool:
    payload = frame_with_fcs[:-4]
    expected = frame_with_fcs[-4:]
    return fcs(payload) == expected


# ----------------------------------------------------------------------
# pcap (classic) reader/writer for synthetic offline fixtures
# ----------------------------------------------------------------------

_PCAP_LINKTYPE_IEEE802_11 = 105
_PCAP_MAGIC = 0xA1B2C3D4
_PCAP_MAGIC_SWAPPED = 0xD4C3B2A1


def write_pcap(path: str, frames: list[bytes], ts: float = 1700000000.0,
               linktype: int = _PCAP_LINKTYPE_IEEE802_11) -> None:
    """Write frames to a classic pcap file (little-endian)."""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", _PCAP_MAGIC, 2, 4, 0, 0, 0xFFFF, linktype))
        for frame in frames:
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000))
            f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            f.write(frame)


def read_pcap(path: str) -> list[dict]:
    """Read a classic pcap; returns list of {ts, sec, usec, data}."""
    frames = []
    with open(path, "rb") as f:
        head = f.read(24)
        if len(head) < 24:
            raise ValueError("truncated pcap header")
        magic, = struct.unpack("<I", head[0:4])
        swapped = magic != _PCAP_MAGIC
        fmt = "<" if not swapped else ">"
        if magic != _PCAP_MAGIC and magic != _PCAP_MAGIC_SWAPPED:
            raise ValueError(f"not a classic pcap (magic=0x{magic:08x})")
        _, _, _, _, _, _, linktype = struct.unpack(fmt + "IHHiIII", head)
        while True:
            rec_hdr = f.read(16)
            if len(rec_hdr) < 16:
                break
            sec, usec, incl, orig = struct.unpack(fmt + "IIII", rec_hdr)
            data = f.read(incl)
            if len(data) < incl:
                break
            frames.append({"sec": sec, "usec": usec,
                           "ts": sec + usec / 1_000_000,
                           "incl_len": incl, "orig_len": orig,
                           "linktype": linktype, "data": data})
    return frames


def make_beacon_fixture(path: str, bssid: str = LAB_MAC, ssid: str = "lab-test-net",
                        count: int = 5, interval: float = 0.1) -> int:
    """Write a small deterministic beacon pcap fixture and return frame count."""
    frames = []
    for i in range(count):
        fr = build_beacon(bssid, ssid=ssid, timestamp=1000 + i, seq_num=i + 1)
        frames.append(fr)
    write_pcap(path, frames, ts=1700000000.0)
    return len(frames)
