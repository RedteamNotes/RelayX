import unittest
import struct
import socket
import threading

from relayx.mssql_tds import (
    PRELOGIN_ENCRYPTION,
    _build_prelogin_payload,
    _tds_packet,
    _parse_prelogin_options,
    build_login7,
    ntlm_sspi_challenge,
    parse_token_stream,
    TDS_PRELOGIN,
    TDS_TABULAR,
)


class MSSQLTDSTests(unittest.TestCase):
    def test_prelogin_payload_parses(self):
        payload = _build_prelogin_payload()
        options = _parse_prelogin_options(payload)
        self.assertIn(0, options)
        self.assertIn(1, options)
        self.assertEqual(options[1], b"\x00")

    def test_prelogin_payload_can_request_tls(self):
        payload = _build_prelogin_payload(encryption=1)
        options = _parse_prelogin_options(payload)
        self.assertEqual(options[PRELOGIN_ENCRYPTION], b"\x01")

    def test_login7_length_and_sspi_offset(self):
        login = build_login7(
            host_name="RELAYX",
            app_name="RelayX",
            server_name="sql01",
            client_interface="RelayX",
            sspi=b"NTLMSSP\x00demo",
        )
        self.assertEqual(struct.unpack_from("<I", login, 0)[0], len(login))
        sspi_offset, sspi_len = struct.unpack_from("<HH", login, 36 + 36 + 6)
        self.assertEqual(sspi_len, len(b"NTLMSSP\x00demo"))
        self.assertEqual(login[sspi_offset : sspi_offset + sspi_len], b"NTLMSSP\x00demo")

    def test_parse_sspi_token(self):
        token_data = b"NTLMSSP\x00type2"
        body = b"\xED" + struct.pack("<H", len(token_data)) + token_data
        tokens = parse_token_stream(body)
        self.assertEqual(tokens[0]["type"], "SSPI")
        self.assertEqual(tokens[0]["data"], token_data)

    def test_ntlm_sspi_challenge_network_flow(self):
        type2 = _fake_type2()
        server = _FakeTDSServer(type2)
        server.start()
        try:
            result = ntlm_sspi_challenge("127.0.0.1", port=server.port, timeout=2.0)
        finally:
            server.stop()
        self.assertIsNotNone(result.type2)
        self.assertEqual(result.type2["target_name"], "SQLLAB")
        self.assertTrue(server.login7_seen)
        self.assertEqual(server.client_requested_encryption, 1)

    def test_ntlm_sspi_auth_validation_network_flow(self):
        type2 = _fake_type2()
        server = _FakeTDSServer(type2)
        server.start()
        try:
            result = ntlm_sspi_challenge(
                "127.0.0.1",
                port=server.port,
                timeout=2.0,
                auth_validation=True,
            )
        finally:
            server.stop()
        self.assertIsNotNone(result.auth_validation)
        self.assertTrue(result.auth_validation["sent"])
        self.assertTrue(server.type3_seen)


class _FakeTDSServer:
    def __init__(self, type2: bytes):
        self.type2 = type2
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.login7_seen = False
        self.type3_seen = False
        self.client_requested_encryption = None

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
            prelogin_header = _recv_exact(conn, 8)
            prelogin_len = struct.unpack(">H", prelogin_header[2:4])[0]
            prelogin_body = _recv_exact(conn, prelogin_len - 8)
            options = _parse_prelogin_options(prelogin_body)
            encryption = options.get(PRELOGIN_ENCRYPTION, b"")
            self.client_requested_encryption = encryption[0] if encryption else None
            conn.sendall(_tds_packet(TDS_PRELOGIN, _build_prelogin_payload()))
            header = _recv_exact(conn, 8)
            packet_type = header[0]
            length = struct.unpack(">H", header[2:4])[0]
            login_body = _recv_exact(conn, length - 8)
            self.login7_seen = packet_type == 0x10 and login_body.startswith(struct.pack("<I", len(login_body)))
            body = b"\xED" + struct.pack("<H", len(self.type2)) + self.type2
            conn.sendall(_tds_packet(TDS_TABULAR, body))
            conn.settimeout(0.25)
            try:
                header = _recv_exact(conn, 8)
                packet_type = header[0]
                length = struct.unpack(">H", header[2:4])[0]
                payload = _recv_exact(conn, length - 8)
                if packet_type == 0x11 and payload.startswith(b"NTLMSSP\x00"):
                    self.type3_seen = struct.unpack_from("<I", payload, 8)[0] == 3
                conn.sendall(_tds_packet(TDS_TABULAR, b"\xFD" + b"\x00" * 12))
            except (OSError, TimeoutError):
                pass


def _recv_exact(sock, size):
    chunks = bytearray()
    while len(chunks) < size:
        part = sock.recv(size - len(chunks))
        if not part:
            raise OSError("closed")
        chunks.extend(part)
    return bytes(chunks)


def _fake_type2() -> bytes:
    target = "SQLLAB".encode("utf-16le")
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
            b"SQLCHAL!",
            b"\x00" * 8,
            struct.pack("<HHI", len(av), len(av), av_offset),
            target,
            av,
        ]
    )


if __name__ == "__main__":
    unittest.main()
