import base64
import struct
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from relayx.oracles.http import assess


def _sec_buf(length: int, offset: int) -> bytes:
    return struct.pack("<HHI", length, length, offset)


def _type2_token() -> str:
    target = "LAB".encode("utf-16le")
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
    msg = b"".join(
        [
            b"NTLMSSP\x00",
            struct.pack("<I", 2),
            _sec_buf(len(target), target_offset),
            struct.pack("<I", 0x00880201),
            b"ABCDEFGH",
            b"\x00" * 8,
            _sec_buf(len(av), av_offset),
            target,
            av,
        ]
    )
    return base64.b64encode(msg).decode("ascii")


class _NTLMHandler(BaseHTTPRequestHandler):
    messages = []

    def do_GET(self):
        auth = self.headers.get("Authorization", "")
        if auth.startswith("NTLM "):
            msg = base64.b64decode(auth.split()[1])
            _NTLMHandler.messages.append(struct.unpack_from("<I", msg, 8)[0])
            if _NTLMHandler.messages[-1] == 3:
                self.send_response(401)
                self.send_header("WWW-Authenticate", "NTLM")
                self.end_headers()
                return
        self.send_response(401)
        if auth.startswith("NTLM "):
            self.send_header("WWW-Authenticate", f"NTLM {_type2_token()}")
        else:
            self.send_header("WWW-Authenticate", "NTLM")
        self.end_headers()

    def log_message(self, format, *args):
        return


class HTTPOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _NTLMHandler.messages = []
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _NTLMHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join(timeout=2)

    def test_http_ntlm_challenge_flow(self):
        port = self.server.server_address[1]
        findings = assess("127.0.0.1", port, "http", timeout=2.0, paths=["/"])
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        evidence = {item.key: item for item in finding.evidence}
        self.assertTrue(evidence["ntlm_type2_challenge"].value)
        self.assertEqual(evidence["ntlm_type2_challenge"].raw["target_name"], "LAB")

    def test_http_auth_validation_sends_type3(self):
        _NTLMHandler.messages = []
        port = self.server.server_address[1]
        findings = assess(
            "127.0.0.1",
            port,
            "http",
            timeout=2.0,
            paths=["/"],
            auth_validation=True,
        )
        evidence = {item.key: item for item in findings[0].evidence}
        self.assertTrue(evidence["ntlm_authenticate_validation"].value)
        self.assertEqual(
            evidence["relayx_response_classification"].value,
            "synthetic_auth_rejected",
        )
        self.assertIn(1, _NTLMHandler.messages)
        self.assertIn(3, _NTLMHandler.messages)


if __name__ == "__main__":
    unittest.main()
