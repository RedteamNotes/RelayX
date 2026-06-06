from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field

from .ntlm import (
    channel_bindings_hash_from_cert_sha256,
    make_type1,
    make_type3,
    parse_type2,
    tls_cert_sha256,
)


class BERError(ValueError):
    pass


@dataclass(slots=True)
class LDAPRootDSE:
    attributes: dict[str, list[str]] = field(default_factory=dict)


@dataclass(slots=True)
class LDAPNTLMChallenge:
    result_code: int
    diagnostic_message: str
    type2: dict | None = None
    raw_server_sasl_creds: str = ""
    auth_validation: dict | None = None


def ldap_socket(host: str, port: int, timeout: float) -> tuple[socket.socket, bytes | None]:
    raw = socket.create_connection((host, port), timeout=timeout)
    raw.settimeout(timeout)
    if port == 636:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        tls_sock = context.wrap_socket(raw, server_hostname=host)
        return tls_sock, tls_sock.getpeercert(binary_form=True)
    return raw, None


def query_root_dse(host: str, port: int, timeout: float = 3.0) -> tuple[LDAPRootDSE, bytes | None]:
    attrs = [
        "supportedSASLMechanisms",
        "supportedCapabilities",
        "ldapServiceName",
        "dnsHostName",
        "defaultNamingContext",
        "rootDomainNamingContext",
        "domainFunctionality",
        "forestFunctionality",
        "domainControllerFunctionality",
        "isGlobalCatalogReady",
    ]
    sock, cert_der = ldap_socket(host, port, timeout)
    with sock:
        sock.sendall(_ldap_message(1, _search_root_dse(attrs)))
        data = _recv_ldap_messages(sock)
    return LDAPRootDSE(_parse_search_entries(data)), cert_der


def request_ntlm_challenge(
    host: str,
    port: int,
    timeout: float = 3.0,
    auth_validation: bool = False,
) -> tuple[LDAPNTLMChallenge, bytes | None]:
    sock, cert_der = ldap_socket(host, port, timeout)
    with sock:
        sock.sendall(_ldap_message(2, _sasl_ntlm_bind_request(make_type1())))
        data = _recv_ldap_messages(sock)
        challenge = _parse_bind_response(data)
        if auth_validation and challenge.type2 and challenge.raw_server_sasl_creds:
            cbt_hash = None
            cbt_mode = "not_available"
            if cert_der:
                cbt_hash = channel_bindings_hash_from_cert_sha256(tls_cert_sha256(cert_der))
                cbt_mode = "tls-server-end-point"
            parsed_type2 = parse_type2(bytes.fromhex(challenge.raw_server_sasl_creds))
            type3 = make_type3(parsed_type2, cbt_hash=cbt_hash)
            try:
                sock.sendall(_ldap_message(3, _sasl_ntlm_bind_request(type3)))
                validation_data = _recv_ldap_messages(sock)
                validation_response = _parse_bind_response(validation_data)
                challenge.auth_validation = {
                    "sent": True,
                    "synthetic_credentials": True,
                    "cbt_mode": cbt_mode,
                    "cbt_hash": cbt_hash.hex() if cbt_hash else "",
                    "result_code": validation_response.result_code,
                    "diagnostic_message": validation_response.diagnostic_message,
                    "raw_server_sasl_creds": validation_response.raw_server_sasl_creds,
                    "interpretation": (
                        "LDAP response to synthetic NTLM Authenticate captured. "
                        "This is enforcement evidence, not proof of valid credentials."
                    ),
                }
            except (OSError, BERError) as exc:
                challenge.auth_validation = {
                    "sent": True,
                    "synthetic_credentials": True,
                    "cbt_mode": cbt_mode,
                    "cbt_hash": cbt_hash.hex() if cbt_hash else "",
                    "error": str(exc),
                }
    return challenge, cert_der


def _ldap_message(message_id: int, protocol_op: bytes) -> bytes:
    return _seq(_integer(message_id) + protocol_op)


def _search_root_dse(attrs: list[str]) -> bytes:
    attr_seq = _seq(b"".join(_octet(attr.encode("utf-8")) for attr in attrs))
    present_filter = _tlv(0x87, b"objectClass")
    payload = b"".join(
        [
            _octet(b""),  # baseObject
            _enum(0),  # baseObject scope
            _enum(0),  # neverDerefAliases
            _integer(0),  # sizeLimit
            _integer(0),  # timeLimit
            _bool(False),  # typesOnly
            present_filter,
            attr_seq,
        ]
    )
    return _tlv(0x63, payload)


def _sasl_ntlm_bind_request(type1: bytes) -> bytes:
    sasl = _tlv(0xA3, _seq(_octet(b"NTLM") + _octet(type1)))
    payload = _integer(3) + _octet(b"") + sasl
    return _tlv(0x60, payload)


def _parse_search_entries(data: bytes) -> dict[str, list[str]]:
    attributes: dict[str, list[str]] = {}
    offset = 0
    while offset < len(data):
        tag, content, offset = _read_tlv(data, offset)
        if tag != 0x30:
            continue
        msg_offset = 0
        _mid_tag, _mid_content, msg_offset = _read_tlv(content, msg_offset)
        if msg_offset >= len(content):
            continue
        op_tag, op_content, _ = _read_tlv(content, msg_offset)
        if op_tag != 0x64:
            continue
        entry_offset = 0
        _obj_tag, _obj_content, entry_offset = _read_tlv(op_content, entry_offset)
        attr_tag, attr_content, _ = _read_tlv(op_content, entry_offset)
        if attr_tag != 0x30:
            continue
        attr_offset = 0
        while attr_offset < len(attr_content):
            seq_tag, seq_content, attr_offset = _read_tlv(attr_content, attr_offset)
            if seq_tag != 0x30:
                continue
            seq_offset = 0
            type_tag, type_content, seq_offset = _read_tlv(seq_content, seq_offset)
            vals_tag, vals_content, _ = _read_tlv(seq_content, seq_offset)
            if type_tag != 0x04 or vals_tag != 0x31:
                continue
            name = type_content.decode("utf-8", "replace")
            vals: list[str] = []
            val_offset = 0
            while val_offset < len(vals_content):
                val_tag, val_content, val_offset = _read_tlv(vals_content, val_offset)
                if val_tag == 0x04:
                    vals.append(val_content.decode("utf-8", "replace"))
            attributes[name] = vals
    return attributes


def _parse_bind_response(data: bytes) -> LDAPNTLMChallenge:
    offset = 0
    while offset < len(data):
        tag, content, offset = _read_tlv(data, offset)
        if tag != 0x30:
            continue
        msg_offset = 0
        _mid_tag, _mid_content, msg_offset = _read_tlv(content, msg_offset)
        if msg_offset >= len(content):
            continue
        op_tag, op_content, _ = _read_tlv(content, msg_offset)
        if op_tag != 0x61:
            continue
        res_offset = 0
        code_tag, code_content, res_offset = _read_tlv(op_content, res_offset)
        result_code = _decode_int(code_content) if code_tag == 0x0A else -1
        _dn_tag, _dn_content, res_offset = _read_tlv(op_content, res_offset)
        diag_tag, diag_content, res_offset = _read_tlv(op_content, res_offset)
        diagnostic = diag_content.decode("utf-8", "replace") if diag_tag == 0x04 else ""
        server_creds = b""
        while res_offset < len(op_content):
            extra_tag, extra_content, res_offset = _read_tlv(op_content, res_offset)
            if extra_tag == 0x87:
                server_creds = extra_content
        type2 = None
        if server_creds.startswith(b"NTLMSSP\x00"):
            parsed = parse_type2(server_creds)
            type2 = {
                "flags": parsed.flags,
                "challenge": parsed.challenge,
                "target_name": parsed.target_name,
                "target_info": parsed.target_info,
                "target_info_raw": parsed.target_info_raw,
                "target_info_hex": parsed.target_info_hex,
            }
        return LDAPNTLMChallenge(
            result_code=result_code,
            diagnostic_message=diagnostic,
            type2=type2,
            raw_server_sasl_creds=server_creds.hex(),
        )
    raise BERError("LDAP bind response not found")


def _recv_ldap_messages(sock: socket.socket) -> bytes:
    chunks = bytearray()
    while True:
        try:
            part = sock.recv(8192)
        except TimeoutError:
            break
        except socket.timeout:
            break
        if not part:
            break
        chunks.extend(part)
        if _contains_done_or_bind_response(bytes(chunks)):
            break
    return bytes(chunks)


def _contains_done_or_bind_response(data: bytes) -> bool:
    offset = 0
    try:
        while offset < len(data):
            tag, content, offset = _read_tlv(data, offset)
            if tag != 0x30:
                continue
            msg_offset = 0
            _mid_tag, _mid_content, msg_offset = _read_tlv(content, msg_offset)
            if msg_offset >= len(content):
                continue
            op_tag, _op_content, _ = _read_tlv(content, msg_offset)
            if op_tag in {0x61, 0x65}:
                return True
    except BERError:
        return False
    return False


def _seq(content: bytes) -> bytes:
    return _tlv(0x30, content)


def _integer(value: int) -> bytes:
    if value == 0:
        encoded = b"\x00"
    else:
        encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if encoded[0] & 0x80:
            encoded = b"\x00" + encoded
    return _tlv(0x02, encoded)


def _enum(value: int) -> bytes:
    return _tlv(0x0A, bytes([value]))


def _bool(value: bool) -> bytes:
    return _tlv(0x01, b"\xff" if value else b"\x00")


def _octet(value: bytes) -> bytes:
    return _tlv(0x04, value)


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _encode_len(len(content)) + content


def _encode_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    if offset + 2 > len(data):
        raise BERError("truncated BER TLV")
    tag = data[offset]
    offset += 1
    length_byte = data[offset]
    offset += 1
    if length_byte & 0x80:
        len_len = length_byte & 0x7F
        if len_len == 0 or offset + len_len > len(data):
            raise BERError("invalid BER length")
        length = int.from_bytes(data[offset : offset + len_len], "big")
        offset += len_len
    else:
        length = length_byte
    end = offset + length
    if end > len(data):
        raise BERError("BER value exceeds buffer")
    return tag, data[offset:end], end


def _decode_int(content: bytes) -> int:
    if not content:
        return 0
    return int.from_bytes(content, "big", signed=bool(content[0] & 0x80))
