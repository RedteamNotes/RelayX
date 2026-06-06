import base64
import socket
import struct
import threading
import unittest

from relayx.ldap_proto import request_ntlm_challenge


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _len(len(content)) + content


def _len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _seq(content: bytes) -> bytes:
    return _tlv(0x30, content)


def _integer(value: int) -> bytes:
    return _tlv(0x02, bytes([value]))


def _enum(value: int) -> bytes:
    return _tlv(0x0A, bytes([value]))


def _octet(value: bytes) -> bytes:
    return _tlv(0x04, value)


def _ldap_message(message_id: int, op: bytes) -> bytes:
    return _seq(_integer(message_id) + op)


def _bind_response(message_id: int, result_code: int, diagnostic: str = "", server_creds: bytes = b"") -> bytes:
    content = _enum(result_code) + _octet(b"") + _octet(diagnostic.encode("utf-8"))
    if server_creds:
        content += _tlv(0x87, server_creds)
    return _ldap_message(message_id, _tlv(0x61, content))


def _fake_type2() -> bytes:
    target = "LDAPLAB".encode("utf-16le")
    av = b"".join(
        [
            struct.pack("<HH", 2, len(target)),
            target,
            struct.pack("<HH", 0, 0),
        ]
    )
    header_len = 48
    target_offset = header_len
    av_offset = target_offset + len(target)
    return b"".join(
        [
            b"NTLMSSP\x00",
            struct.pack("<I", 2),
            struct.pack("<HHI", len(target), len(target), target_offset),
            struct.pack("<I", 0x00880201),
            b"LDAPCHAL",
            b"\x00" * 8,
            struct.pack("<HHI", len(av), len(av), av_offset),
            target,
            av,
        ]
    )


class _FakeLDAPServer:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.type1_seen = False
        self.type3_seen = False

    def start(self):
        self.thread.start()

    def stop(self):
        try:
            self.sock.close()
        finally:
            self.thread.join(timeout=2)

    def _serve(self):
        conn, _addr = self.sock.accept()
        with conn:
            first = conn.recv(8192)
            self.type1_seen = b"NTLMSSP\x00\x01\x00\x00\x00" in first
            conn.sendall(_bind_response(2, 14, server_creds=_fake_type2()))
            second = conn.recv(8192)
            self.type3_seen = b"NTLMSSP\x00\x03\x00\x00\x00" in second
            conn.sendall(_bind_response(3, 49, "invalid credentials"))


class LDAPProtoTests(unittest.TestCase):
    def test_ldap_ntlm_auth_validation_flow(self):
        server = _FakeLDAPServer()
        server.start()
        try:
            challenge, _cert = request_ntlm_challenge(
                "127.0.0.1",
                server.port,
                timeout=2.0,
                auth_validation=True,
            )
        finally:
            server.stop()
        self.assertTrue(server.type1_seen)
        self.assertTrue(server.type3_seen)
        self.assertIsNotNone(challenge.type2)
        self.assertEqual(challenge.type2["target_name"], "LDAPLAB")
        self.assertIsNotNone(challenge.auth_validation)
        self.assertEqual(challenge.auth_validation["result_code"], 49)


if __name__ == "__main__":
    unittest.main()

