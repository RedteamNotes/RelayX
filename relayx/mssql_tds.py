from __future__ import annotations

import os
import socket
import struct
import ssl
from dataclasses import dataclass, field

from .ntlm import (
    channel_bindings_hash_from_cert_sha256,
    make_type1,
    make_type3,
    parse_type2,
)
from .ntlm import tls_cert_sha256 as cert_sha256

TDS_PRELOGIN = 0x12
TDS_LOGIN7 = 0x10
TDS_TABULAR = 0x04
TDS_STATUS_EOM = 0x01
TDS_TOKEN_SSPI = 0xED
TDS_TOKEN_ERROR = 0xAA
TDS_TOKEN_INFO = 0xAB
TDS_TOKEN_LOGINACK = 0xAD
TDS_TOKEN_ENVCHANGE = 0xE3
TDS_TOKEN_DONE = 0xFD
TDS_TOKEN_DONEPROC = 0xFE
TDS_TOKEN_DONEINPROC = 0xFF

PRELOGIN_VERSION = 0x00
PRELOGIN_ENCRYPTION = 0x01
PRELOGIN_TERMINATOR = 0xFF

ENCRYPTION_VALUES = {
    0: "ENCRYPT_OFF",
    1: "ENCRYPT_ON",
    2: "ENCRYPT_NOT_SUP",
    3: "ENCRYPT_REQ",
}
ENCRYPT_OFF = 0
ENCRYPT_ON = 1
ENCRYPT_NOT_SUP = 2
ENCRYPT_REQ = 3


@dataclass(slots=True)
class TDSTLSInfo:
    version: str
    cipher: tuple | None
    certificate_sha256: str


@dataclass(slots=True)
class MSSQLSSPIChallenge:
    prelogin: dict
    type2: dict | None = None
    tls: dict | None = None
    auth_validation: dict | None = None
    errors: list[str] = field(default_factory=list)
    infos: list[str] = field(default_factory=list)
    loginack: bool = False
    raw_tokens: list[dict] = field(default_factory=list)
    skipped_reason: str = ""


def prelogin(host: str, port: int = 1433, timeout: float = 3.0, encryption: int = ENCRYPT_OFF) -> dict:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        return _send_prelogin(sock, encryption=encryption)


def ntlm_sspi_challenge(
    host: str,
    port: int = 1433,
    timeout: float = 3.0,
    server_name: str | None = None,
    prefer_tls: bool = True,
    auth_validation: bool = False,
) -> MSSQLSSPIChallenge:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        requested_encryption = ENCRYPT_ON if prefer_tls else ENCRYPT_OFF
        prelogin_result = _send_prelogin(sock, encryption=requested_encryption)
        encryption = prelogin_result.get("encryption")
        if encryption in {ENCRYPT_NOT_SUP} and prefer_tls:
            return MSSQLSSPIChallenge(
                prelogin=prelogin_result,
                skipped_reason=(
                    "server reported ENCRYPT_NOT_SUP; TLS CBT evidence is unavailable"
                ),
            )
        channel = None
        tls_info = None
        if encryption in {ENCRYPT_ON, ENCRYPT_REQ}:
            channel = TDSTLSChannel(sock, server_hostname=server_name or host, timeout=timeout)
            tls_info = channel.handshake()
        login_packet = build_login7(
            host_name="RELAYX",
            app_name="RelayX",
            server_name=server_name or host,
            client_interface="RelayX",
            sspi=make_type1(),
        )
        packet = _tds_packet(TDS_LOGIN7, login_packet)
        if channel:
            channel.write(packet)
            body = _read_tds_response_tls(channel)
        else:
            sock.sendall(packet)
            body = _read_tds_response(sock)
        tokens = parse_token_stream(body)
        parsed_tokens = _summarize_tokens(tokens)
        parsed_type2 = parsed_tokens["parsed_type2"]
        type2 = parsed_tokens["type2"]
        auth_result = None
        if auth_validation and parsed_type2:
            cbt_hash = None
            tls_json = _tls_info_for_json(tls_info)
            if tls_json and tls_json.get("certificate_sha256"):
                cbt_hash = channel_bindings_hash_from_cert_sha256(tls_json["certificate_sha256"])
            type3 = make_type3(parsed_type2, cbt_hash=cbt_hash)
            validation_packet = _tds_packet(0x11, type3)
            try:
                if channel:
                    channel.write(validation_packet)
                    validation_body = _read_tds_response_tls(channel)
                else:
                    sock.sendall(validation_packet)
                    validation_body = _read_tds_response(sock)
                validation_tokens = parse_token_stream(validation_body)
                validation_summary = _summarize_tokens(validation_tokens)
                auth_result = {
                    "sent": True,
                    "synthetic_credentials": True,
                    "cbt_mode": "tls-server-end-point" if cbt_hash else "not_available",
                    "cbt_hash": cbt_hash.hex() if cbt_hash else "",
                    "errors": validation_summary["errors"],
                    "infos": validation_summary["infos"],
                    "loginack": validation_summary["loginack"],
                    "raw_tokens": _tokens_for_json(validation_tokens),
                    "interpretation": (
                        "SQL Server response to synthetic NTLM Authenticate captured. "
                        "This is enforcement evidence, not proof of valid credentials."
                    ),
                }
            except OSError as exc:
                auth_result = {
                    "sent": True,
                    "synthetic_credentials": True,
                    "cbt_mode": "tls-server-end-point" if cbt_hash else "not_available",
                    "cbt_hash": cbt_hash.hex() if cbt_hash else "",
                    "error": str(exc),
                }
    return MSSQLSSPIChallenge(
        prelogin=prelogin_result,
        type2=type2,
        tls=_tls_info_for_json(tls_info),
        auth_validation=auth_result,
        errors=parsed_tokens["errors"],
        infos=parsed_tokens["infos"],
        loginack=parsed_tokens["loginack"],
        raw_tokens=_tokens_for_json(tokens),
    )


class TDSTLSChannel:
    """TLS over TDS prelogin packets for SQL Server encryption negotiation."""

    def __init__(self, sock: socket.socket, server_hostname: str, timeout: float = 3.0):
        self.sock = sock
        self.server_hostname = server_hostname
        self.sock.settimeout(timeout)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        self._incoming = ssl.MemoryBIO()
        self._outgoing = ssl.MemoryBIO()
        self._tls = context.wrap_bio(
            self._incoming,
            self._outgoing,
            server_side=False,
            server_hostname=server_hostname,
        )

    def handshake(self) -> TDSTLSInfo:
        while True:
            try:
                self._tls.do_handshake()
                self._drain_handshake_output()
                break
            except ssl.SSLWantWriteError:
                self._drain_handshake_output()
            except ssl.SSLWantReadError:
                self._drain_handshake_output()
                self._incoming.write(_read_tds_tls_handshake_payload(self.sock))
        return TDSTLSInfo(
            version=self._tls.version() or "",
            cipher=self._tls.cipher(),
            certificate_sha256=cert_sha256(self._tls.getpeercert(binary_form=True)),
        )

    def write(self, data: bytes) -> None:
        view = memoryview(data)
        while view:
            sent = self._tls.write(view[:16384])
            view = view[sent:]
            self._drain_raw_output()
        self._drain_raw_output()

    def read(self, size: int = 8192) -> bytes:
        while True:
            try:
                return self._tls.read(size)
            except ssl.SSLWantWriteError:
                self._drain_raw_output()
            except ssl.SSLWantReadError:
                self._drain_raw_output()
                chunk = self.sock.recv(8192)
                if not chunk:
                    raise OSError("TLS socket closed while reading TDS response")
                self._incoming.write(chunk)

    def _drain_handshake_output(self) -> None:
        while True:
            data = self._outgoing.read()
            if not data:
                break
            for offset in range(0, len(data), 16384):
                self.sock.sendall(_tds_packet(TDS_PRELOGIN, data[offset : offset + 16384]))

    def _drain_raw_output(self) -> None:
        while True:
            data = self._outgoing.read()
            if not data:
                break
            self.sock.sendall(data)


def build_login7(
    *,
    host_name: str,
    app_name: str,
    server_name: str,
    client_interface: str,
    sspi: bytes,
    database: str = "",
) -> bytes:
    fields: list[tuple[str, bytes, int]] = [
        ("host", _ucs2(host_name), len(host_name)),
        ("username", b"", 0),
        ("password", b"", 0),
        ("app", _ucs2(app_name), len(app_name)),
        ("server", _ucs2(server_name), len(server_name)),
        ("unused", b"", 0),
        ("client_interface", _ucs2(client_interface), len(client_interface)),
        ("language", b"", 0),
        ("database", _ucs2(database), len(database)),
        ("sspi", sspi, len(sspi)),
        ("attach_db", b"", 0),
        ("change_password", b"", 0),
    ]
    data_start = 94
    cursor = data_start
    offset_lengths: dict[str, tuple[int, int]] = {}
    data = bytearray()
    for name, value, logical_length in fields:
        if value:
            offset_lengths[name] = (cursor, logical_length)
            data.extend(value)
            cursor += len(value)
        else:
            offset_lengths[name] = (data_start, 0)

    total_length = data_start + len(data)
    packet = bytearray()
    packet.extend(struct.pack("<I", total_length))
    packet.extend(struct.pack("<I", 0x74000004))  # TDS 7.4, wire bytes 04 00 00 74.
    packet.extend(struct.pack("<I", 4096))
    packet.extend(struct.pack("<I", 0))
    packet.extend(struct.pack("<I", os.getpid() & 0xFFFFFFFF))
    packet.extend(struct.pack("<I", 0))
    packet.extend(bytes([0x00, 0x82, 0x00, 0x00]))  # Integrated security + ODBC bit.
    packet.extend(struct.pack("<i", 0))
    packet.extend(struct.pack("<I", 0x00000409))

    for name in [
        "host",
        "username",
        "password",
        "app",
        "server",
        "unused",
        "client_interface",
        "language",
        "database",
    ]:
        packet.extend(struct.pack("<HH", *offset_lengths[name]))
    packet.extend(os.urandom(6))
    packet.extend(struct.pack("<HH", *offset_lengths["sspi"]))
    packet.extend(struct.pack("<HH", *offset_lengths["attach_db"]))
    packet.extend(struct.pack("<HH", *offset_lengths["change_password"]))
    packet.extend(struct.pack("<I", 0))
    packet.extend(data)

    if len(packet) != total_length:
        raise ValueError("LOGIN7 length calculation failed")
    return bytes(packet)


def parse_token_stream(body: bytes) -> list[dict]:
    tokens: list[dict] = []
    offset = 0
    while offset < len(body):
        token = body[offset]
        offset += 1
        if token == TDS_TOKEN_SSPI:
            length, offset = _read_ushort(body, offset)
            data = body[offset : offset + length]
            offset += length
            tokens.append({"type": "SSPI", "data": data, "length": length})
        elif token in {TDS_TOKEN_ERROR, TDS_TOKEN_INFO}:
            length, offset = _read_ushort(body, offset)
            payload = body[offset : offset + length]
            offset += length
            tokens.append(_parse_error_or_info(token, payload))
        elif token == TDS_TOKEN_LOGINACK:
            length, offset = _read_ushort(body, offset)
            data = body[offset : offset + length]
            offset += length
            tokens.append({"type": "LOGINACK", "length": length, "data": data})
        elif token == TDS_TOKEN_ENVCHANGE:
            length, offset = _read_ushort(body, offset)
            data = body[offset : offset + length]
            offset += length
            tokens.append({"type": "ENVCHANGE", "length": length, "data": data})
        elif token in {TDS_TOKEN_DONE, TDS_TOKEN_DONEPROC, TDS_TOKEN_DONEINPROC}:
            data = body[offset : offset + 12]
            offset += min(12, len(data))
            tokens.append({"type": "DONE", "data": data})
        else:
            tokens.append({"type": f"UNKNOWN_0x{token:02x}", "offset": offset - 1})
            break
    return tokens


def _summarize_tokens(tokens: list[dict]) -> dict:
    parsed_type2 = None
    type2 = None
    errors: list[str] = []
    infos: list[str] = []
    loginack = False
    for token in tokens:
        if token["type"] == "SSPI" and token.get("data", b"").startswith(b"NTLMSSP\x00"):
            parsed_type2 = parse_type2(token["data"])
            type2 = {
                "flags": parsed_type2.flags,
                "challenge": parsed_type2.challenge,
                "target_name": parsed_type2.target_name,
                "target_info": parsed_type2.target_info,
                "target_info_raw": parsed_type2.target_info_raw,
                "target_info_hex": parsed_type2.target_info_hex,
            }
        elif token["type"] == "ERROR":
            errors.append(str(token.get("message", "")))
        elif token["type"] == "INFO":
            infos.append(str(token.get("message", "")))
        elif token["type"] == "LOGINACK":
            loginack = True
    return {
        "parsed_type2": parsed_type2,
        "type2": type2,
        "errors": errors,
        "infos": infos,
        "loginack": loginack,
    }


def _send_prelogin(sock: socket.socket, encryption: int = ENCRYPT_OFF) -> dict:
    requested_encryption = encryption
    payload = _build_prelogin_payload(encryption=encryption)
    packet = _tds_packet(TDS_PRELOGIN, payload)
    sock.sendall(packet)
    header = _recv_exact(sock, 8)
    packet_type, status, length, spid, packet_id, window = struct.unpack(">BBHHBB", header)
    body = _recv_exact(sock, length - 8)
    if packet_type != TDS_PRELOGIN:
        raise OSError(f"unexpected TDS packet type 0x{packet_type:02x}")
    options = _parse_prelogin_options(body)
    encryption_raw = options.get(PRELOGIN_ENCRYPTION, b"")
    encryption = encryption_raw[0] if encryption_raw else None
    return {
        "packet_type": packet_type,
        "status": status,
        "spid": spid,
        "packet_id": packet_id,
        "window": window,
        "requested_encryption": requested_encryption,
        "requested_encryption_name": ENCRYPTION_VALUES.get(requested_encryption, "unknown"),
        "encryption": encryption,
        "encryption_name": ENCRYPTION_VALUES.get(encryption, "unknown"),
        "options": {str(key): value.hex() for key, value in options.items()},
    }


def _build_prelogin_payload(encryption: int = ENCRYPT_OFF) -> bytes:
    version_value = b"\x00\x00\x00\x00\x00\x00"
    encryption_value = bytes([encryption])
    header_len = 5 + 5 + 1
    version_offset = header_len
    encryption_offset = version_offset + len(version_value)
    option_table = b"".join(
        [
            bytes([PRELOGIN_VERSION]) + struct.pack(">HH", version_offset, len(version_value)),
            bytes([PRELOGIN_ENCRYPTION]) + struct.pack(">HH", encryption_offset, len(encryption_value)),
            bytes([PRELOGIN_TERMINATOR]),
        ]
    )
    return option_table + version_value + encryption_value


def _tds_packet(packet_type: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    return struct.pack(">BBHHBB", packet_type, TDS_STATUS_EOM, length, 0, 1, 0) + payload


def _read_tds_response(sock: socket.socket) -> bytes:
    chunks = bytearray()
    while True:
        header = _recv_exact(sock, 8)
        packet_type, status, length, _spid, _packet_id, _window = struct.unpack(">BBHHBB", header)
        body = _recv_exact(sock, length - 8)
        if packet_type not in {TDS_TABULAR, 0x11}:
            raise OSError(f"unexpected TDS response packet type 0x{packet_type:02x}")
        chunks.extend(body)
        if status & TDS_STATUS_EOM:
            break
    return bytes(chunks)


def _read_tds_response_tls(channel: TDSTLSChannel) -> bytes:
    encrypted_buffer = bytearray()
    body_chunks = bytearray()
    while True:
        while len(encrypted_buffer) < 8:
            encrypted_buffer.extend(channel.read(8192))
        packet_type, status, length, _spid, _packet_id, _window = struct.unpack(
            ">BBHHBB", encrypted_buffer[:8]
        )
        while len(encrypted_buffer) < length:
            encrypted_buffer.extend(channel.read(8192))
        packet = bytes(encrypted_buffer[:length])
        del encrypted_buffer[:length]
        if packet_type not in {TDS_TABULAR, 0x11}:
            raise OSError(f"unexpected decrypted TDS response packet type 0x{packet_type:02x}")
        body_chunks.extend(packet[8:])
        if status & TDS_STATUS_EOM:
            break
    return bytes(body_chunks)


def _read_tds_tls_handshake_payload(sock: socket.socket) -> bytes:
    header = _recv_exact(sock, 8)
    packet_type, _status, length, _spid, _packet_id, _window = struct.unpack(">BBHHBB", header)
    if packet_type != TDS_PRELOGIN:
        raise OSError(f"unexpected TDS TLS handshake packet type 0x{packet_type:02x}")
    return _recv_exact(sock, length - 8)


def _parse_prelogin_options(body: bytes) -> dict[int, bytes]:
    options: dict[int, bytes] = {}
    offset = 0
    descriptors: list[tuple[int, int, int]] = []
    while offset < len(body):
        token = body[offset]
        offset += 1
        if token == PRELOGIN_TERMINATOR:
            break
        if offset + 4 > len(body):
            break
        value_offset, length = struct.unpack(">HH", body[offset : offset + 4])
        offset += 4
        descriptors.append((token, value_offset, length))
    for token, value_offset, length in descriptors:
        if value_offset + length <= len(body):
            options[token] = body[value_offset : value_offset + length]
    return options


def _read_ushort(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 2 > len(data):
        raise OSError("truncated token length")
    return struct.unpack_from("<H", data, offset)[0], offset + 2


def _parse_error_or_info(token: int, payload: bytes) -> dict:
    kind = "ERROR" if token == TDS_TOKEN_ERROR else "INFO"
    try:
        offset = 0
        number = struct.unpack_from("<I", payload, offset)[0]
        offset += 4
        state = payload[offset]
        offset += 1
        severity = payload[offset]
        offset += 1
        msg_len = struct.unpack_from("<H", payload, offset)[0]
        offset += 2
        message = payload[offset : offset + msg_len * 2].decode("utf-16le", "replace")
    except (IndexError, struct.error, UnicodeDecodeError):
        return {"type": kind, "message": "", "raw": payload}
    return {
        "type": kind,
        "number": number,
        "state": state,
        "severity": severity,
        "message": message,
        "raw": payload,
    }


def _tokens_for_json(tokens: list[dict]) -> list[dict]:
    serializable: list[dict] = []
    for token in tokens:
        clean = {}
        for key, value in token.items():
            if isinstance(value, bytes):
                clean[key] = value.hex()
            else:
                clean[key] = value
        serializable.append(clean)
    return serializable


def _tls_info_for_json(info: TDSTLSInfo | None) -> dict | None:
    if not info:
        return None
    return {
        "version": info.version,
        "cipher": list(info.cipher) if info.cipher else None,
        "certificate_sha256": info.certificate_sha256,
        "cbt_type": "tls-server-end-point",
        "cbt_hash": info.certificate_sha256,
    }


def _ucs2(value: str) -> bytes:
    return value.encode("utf-16le")


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        part = sock.recv(size - len(chunks))
        if not part:
            raise OSError("connection closed while reading TDS response")
        chunks.extend(part)
    return bytes(chunks)
