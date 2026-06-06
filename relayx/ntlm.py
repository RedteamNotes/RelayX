from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import time
from dataclasses import dataclass, field


NTLM_SIGNATURE = b"NTLMSSP\x00"

NEGOTIATE_UNICODE = 0x00000001
REQUEST_TARGET = 0x00000004
NEGOTIATE_NTLM = 0x00000200
NEGOTIATE_ALWAYS_SIGN = 0x00008000
NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000
NEGOTIATE_TARGET_INFO = 0x00800000
NEGOTIATE_128 = 0x20000000
NEGOTIATE_56 = 0x80000000

DEFAULT_TYPE1_FLAGS = (
    NEGOTIATE_UNICODE
    | REQUEST_TARGET
    | NEGOTIATE_NTLM
    | NEGOTIATE_ALWAYS_SIGN
    | NEGOTIATE_EXTENDED_SESSIONSECURITY
    | NEGOTIATE_TARGET_INFO
    | NEGOTIATE_128
    | NEGOTIATE_56
)

AV_IDS = {
    0: "EOL",
    1: "NbComputerName",
    2: "NbDomainName",
    3: "DnsComputerName",
    4: "DnsDomainName",
    5: "DnsTreeName",
    6: "Flags",
    7: "Timestamp",
    8: "SingleHost",
    9: "TargetName",
    10: "ChannelBindings",
}

TEXT_AV_IDS = {1, 2, 3, 4, 5, 9}


@dataclass(slots=True)
class NTLMType2:
    flags: int
    challenge: str
    target_name: str = ""
    target_info: dict[str, str | int] = field(default_factory=dict)
    target_info_raw: dict[str, str] = field(default_factory=dict)
    target_info_hex: str = ""


def make_type1(domain: str = "", workstation: str = "RELAYX") -> bytes:
    domain_bytes = domain.encode("ascii", "ignore")
    workstation_bytes = workstation.encode("ascii", "ignore")
    offset = 32
    domain_offset = offset
    workstation_offset = domain_offset + len(domain_bytes)
    flags = DEFAULT_TYPE1_FLAGS
    msg = bytearray()
    msg.extend(NTLM_SIGNATURE)
    msg.extend(struct.pack("<I", 1))
    msg.extend(struct.pack("<I", flags))
    msg.extend(_sec_buf(len(domain_bytes), domain_offset))
    msg.extend(_sec_buf(len(workstation_bytes), workstation_offset))
    msg.extend(domain_bytes)
    msg.extend(workstation_bytes)
    return bytes(msg)


def make_type1_b64(domain: str = "", workstation: str = "RELAYX") -> str:
    return base64.b64encode(make_type1(domain=domain, workstation=workstation)).decode("ascii")


def parse_type2(data: bytes) -> NTLMType2:
    if len(data) < 48:
        raise ValueError("NTLM Type2 message too short")
    if data[:8] != NTLM_SIGNATURE:
        raise ValueError("missing NTLMSSP signature")
    msg_type = struct.unpack_from("<I", data, 8)[0]
    if msg_type != 2:
        raise ValueError(f"expected NTLM Type2, got Type{msg_type}")
    target_name = _read_sec_buf_text(data, 12)
    flags = struct.unpack_from("<I", data, 20)[0]
    challenge = data[24:32].hex()
    target_info: dict[str, str | int] = {}
    target_info_raw: dict[str, str] = {}
    if len(data) >= 48:
        av_bytes = _read_sec_buf(data, 40)
        target_info, target_info_raw = parse_av_pairs(av_bytes)
    return NTLMType2(
        flags=flags,
        challenge=challenge,
        target_name=target_name,
        target_info=target_info,
        target_info_raw=target_info_raw,
        target_info_hex=av_bytes.hex(),
    )


def parse_type2_b64(token: str) -> NTLMType2:
    return parse_type2(base64.b64decode(token))


def parse_av_pairs(data: bytes) -> tuple[dict[str, str | int], dict[str, str]]:
    values: dict[str, str | int] = {}
    raw: dict[str, str] = {}
    offset = 0
    while offset + 4 <= len(data):
        avid, length = struct.unpack_from("<HH", data, offset)
        offset += 4
        if avid == 0:
            break
        value = data[offset : offset + length]
        offset += length
        name = AV_IDS.get(avid, f"AvId{avid}")
        raw[name] = value.hex()
        if avid in TEXT_AV_IDS:
            values[name] = value.decode("utf-16le", "replace")
        elif avid == 6 and len(value) == 4:
            values[name] = struct.unpack("<I", value)[0]
        else:
            values[name] = value.hex()
    return values, raw


def extract_ntlm_challenge(auth_headers: list[str]) -> str | None:
    for header in auth_headers:
        parts = header.strip().split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "ntlm":
            return parts[1].strip()
    return None


def make_type3(
    type2: NTLMType2,
    *,
    username: str = "redpen",
    password: str | None = None,
    domain: str = "RELAYX",
    workstation: str = "RELAYX",
    cbt_hash: bytes | None = None,
) -> bytes:
    """Build a synthetic NTLMv2 Authenticate message for validation probes.

    RelayX uses this only when the operator explicitly enables auth-validation.
    It is intended for server-side enforcement observation with a random
    placeholder password, not for submitting real credentials.
    """

    password = password if password is not None else base64.b16encode(os.urandom(16)).decode("ascii")
    server_challenge = bytes.fromhex(type2.challenge)
    target_info = bytes.fromhex(type2.target_info_hex) if type2.target_info_hex else b"\x00\x00\x00\x00"
    if cbt_hash:
        target_info = set_av_pair(target_info, 10, cbt_hash)
    target_info = ensure_eol(target_info)
    client_challenge = os.urandom(8)
    timestamp = _filetime_now()
    blob = b"".join(
        [
            b"\x01\x01\x00\x00",
            b"\x00\x00\x00\x00",
            struct.pack("<Q", timestamp),
            client_challenge,
            b"\x00\x00\x00\x00",
            target_info,
        ]
    )
    response_key = ntowfv2(username, password, domain)
    nt_proof = hmac.new(response_key, server_challenge + blob, hashlib.md5).digest()
    nt_response = nt_proof + blob
    lm_response = hmac.new(response_key, server_challenge + client_challenge, hashlib.md5).digest() + client_challenge

    domain_bytes = domain.encode("utf-16le")
    username_bytes = username.encode("utf-16le")
    workstation_bytes = workstation.encode("utf-16le")
    session_key = b""

    offset = 64
    fields = [lm_response, nt_response, domain_bytes, username_bytes, workstation_bytes, session_key]
    offsets = []
    payload = bytearray()
    for field in fields:
        offsets.append((len(field), offset))
        payload.extend(field)
        offset += len(field)

    msg = bytearray()
    msg.extend(NTLM_SIGNATURE)
    msg.extend(struct.pack("<I", 3))
    for length, field_offset in offsets:
        msg.extend(_sec_buf(length, field_offset))
    msg.extend(struct.pack("<I", type2.flags))
    msg.extend(payload)
    return bytes(msg)


def make_type3_b64(type2: NTLMType2, **kwargs) -> str:
    return base64.b64encode(make_type3(type2, **kwargs)).decode("ascii")


def ntowfv2(username: str, password: str, domain: str) -> bytes:
    nt_hash = md4(password.encode("utf-16le"))
    identity = (username.upper() + domain).encode("utf-16le")
    return hmac.new(nt_hash, identity, hashlib.md5).digest()


def channel_bindings_hash_from_cert_sha256(cert_sha256_hex: str) -> bytes:
    cert_hash = bytes.fromhex(cert_sha256_hex)
    application_data = b"tls-server-end-point:" + cert_hash
    unhashed = b"\x00" * 16 + struct.pack("<I", len(application_data)) + application_data
    return hashlib.md5(unhashed).digest()


def parse_av_pair_list(data: bytes) -> list[tuple[int, bytes]]:
    pairs: list[tuple[int, bytes]] = []
    offset = 0
    while offset + 4 <= len(data):
        avid, length = struct.unpack_from("<HH", data, offset)
        offset += 4
        if avid == 0:
            pairs.append((0, b""))
            break
        value = data[offset : offset + length]
        offset += length
        pairs.append((avid, value))
    return pairs


def serialize_av_pairs(pairs: list[tuple[int, bytes]]) -> bytes:
    out = bytearray()
    has_eol = False
    for avid, value in pairs:
        if avid == 0:
            has_eol = True
            out.extend(struct.pack("<HH", 0, 0))
            break
        out.extend(struct.pack("<HH", avid, len(value)))
        out.extend(value)
    if not has_eol:
        out.extend(struct.pack("<HH", 0, 0))
    return bytes(out)


def set_av_pair(data: bytes, avid: int, value: bytes) -> bytes:
    pairs = [(key, val) for key, val in parse_av_pair_list(data) if key not in {avid, 0}]
    pairs.append((avid, value))
    pairs.append((0, b""))
    return serialize_av_pairs(pairs)


def ensure_eol(data: bytes) -> bytes:
    pairs = parse_av_pair_list(data)
    if pairs and pairs[-1][0] == 0:
        return data
    return data + b"\x00\x00\x00\x00"


def tls_cert_sha256(cert_der: bytes | None) -> str:
    if not cert_der:
        return ""
    return hashlib.sha256(cert_der).hexdigest()


def md4(data: bytes) -> bytes:
    return _MD4(data).digest()


def _sec_buf(length: int, offset: int) -> bytes:
    return struct.pack("<HHI", length, length, offset)


def _read_sec_buf(data: bytes, offset: int) -> bytes:
    if offset + 8 > len(data):
        return b""
    length, _max_length, value_offset = struct.unpack_from("<HHI", data, offset)
    if length == 0:
        return b""
    if value_offset + length > len(data):
        return b""
    return data[value_offset : value_offset + length]


def _read_sec_buf_text(data: bytes, offset: int) -> str:
    raw = _read_sec_buf(data, offset)
    if not raw:
        return ""
    try:
        return raw.decode("utf-16le")
    except UnicodeDecodeError:
        return raw.decode("ascii", "replace")


def _filetime_now() -> int:
    return int((time.time() + 11644473600) * 10_000_000)


class _MD4:
    def __init__(self, data: bytes = b""):
        self._count = 0
        self._buf = b""
        self._state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
        if data:
            self.update(data)

    def update(self, data: bytes) -> None:
        self._count += len(data)
        data = self._buf + data
        blocks = len(data) // 64
        for index in range(blocks):
            self._compress(data[index * 64 : (index + 1) * 64])
        self._buf = data[blocks * 64 :]

    def digest(self) -> bytes:
        clone = _MD4()
        clone._count = self._count
        clone._buf = self._buf
        clone._state = self._state.copy()
        bit_len = clone._count * 8
        clone.update(b"\x80")
        while len(clone._buf) != 56:
            clone.update(b"\x00")
        clone.update(struct.pack("<Q", bit_len))
        return struct.pack("<4I", *clone._state)

    def _compress(self, block: bytes) -> None:
        x = list(struct.unpack("<16I", block))
        a, b, c, d = self._state

        def f(xv, yv, zv):
            return ((xv & yv) | (~xv & zv)) & 0xFFFFFFFF

        def g(xv, yv, zv):
            return ((xv & yv) | (xv & zv) | (yv & zv)) & 0xFFFFFFFF

        def h(xv, yv, zv):
            return (xv ^ yv ^ zv) & 0xFFFFFFFF

        def rol(value, bits):
            value &= 0xFFFFFFFF
            return ((value << bits) | (value >> (32 - bits))) & 0xFFFFFFFF

        def round1(av, bv, cv, dv, k, s):
            return rol((av + f(bv, cv, dv) + x[k]) & 0xFFFFFFFF, s)

        def round2(av, bv, cv, dv, k, s):
            return rol((av + g(bv, cv, dv) + x[k] + 0x5A827999) & 0xFFFFFFFF, s)

        def round3(av, bv, cv, dv, k, s):
            return rol((av + h(bv, cv, dv) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)

        a = round1(a, b, c, d, 0, 3)
        d = round1(d, a, b, c, 1, 7)
        c = round1(c, d, a, b, 2, 11)
        b = round1(b, c, d, a, 3, 19)
        a = round1(a, b, c, d, 4, 3)
        d = round1(d, a, b, c, 5, 7)
        c = round1(c, d, a, b, 6, 11)
        b = round1(b, c, d, a, 7, 19)
        a = round1(a, b, c, d, 8, 3)
        d = round1(d, a, b, c, 9, 7)
        c = round1(c, d, a, b, 10, 11)
        b = round1(b, c, d, a, 11, 19)
        a = round1(a, b, c, d, 12, 3)
        d = round1(d, a, b, c, 13, 7)
        c = round1(c, d, a, b, 14, 11)
        b = round1(b, c, d, a, 15, 19)

        a = round2(a, b, c, d, 0, 3)
        d = round2(d, a, b, c, 4, 5)
        c = round2(c, d, a, b, 8, 9)
        b = round2(b, c, d, a, 12, 13)
        a = round2(a, b, c, d, 1, 3)
        d = round2(d, a, b, c, 5, 5)
        c = round2(c, d, a, b, 9, 9)
        b = round2(b, c, d, a, 13, 13)
        a = round2(a, b, c, d, 2, 3)
        d = round2(d, a, b, c, 6, 5)
        c = round2(c, d, a, b, 10, 9)
        b = round2(b, c, d, a, 14, 13)
        a = round2(a, b, c, d, 3, 3)
        d = round2(d, a, b, c, 7, 5)
        c = round2(c, d, a, b, 11, 9)
        b = round2(b, c, d, a, 15, 13)

        a = round3(a, b, c, d, 0, 3)
        d = round3(d, a, b, c, 8, 9)
        c = round3(c, d, a, b, 4, 11)
        b = round3(b, c, d, a, 12, 15)
        a = round3(a, b, c, d, 2, 3)
        d = round3(d, a, b, c, 10, 9)
        c = round3(c, d, a, b, 6, 11)
        b = round3(b, c, d, a, 14, 15)
        a = round3(a, b, c, d, 1, 3)
        d = round3(d, a, b, c, 9, 9)
        c = round3(c, d, a, b, 5, 11)
        b = round3(b, c, d, a, 13, 15)
        a = round3(a, b, c, d, 3, 3)
        d = round3(d, a, b, c, 11, 9)
        c = round3(c, d, a, b, 7, 11)
        b = round3(b, c, d, a, 15, 15)

        self._state[0] = (self._state[0] + a) & 0xFFFFFFFF
        self._state[1] = (self._state[1] + b) & 0xFFFFFFFF
        self._state[2] = (self._state[2] + c) & 0xFFFFFFFF
        self._state[3] = (self._state[3] + d) & 0xFFFFFFFF
