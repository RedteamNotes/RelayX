import base64
import struct
import unittest

from relayx.ntlm import (
    channel_bindings_hash_from_cert_sha256,
    extract_ntlm_challenge,
    make_type1,
    make_type3,
    md4,
    parse_type2,
)


def _sec_buf(length: int, offset: int) -> bytes:
    return struct.pack("<HHI", length, length, offset)


class NTLMTests(unittest.TestCase):
    def test_make_type1(self):
        msg = make_type1()
        self.assertTrue(msg.startswith(b"NTLMSSP\x00"))
        self.assertEqual(struct.unpack_from("<I", msg, 8)[0], 1)

    def test_md4_nt_hash_vector(self):
        self.assertEqual(
            md4("password".encode("utf-16le")).hex(),
            "8846f7eaee8fb117ad06bdd830b7586c",
        )

    def test_parse_type2_target_info(self):
        target = "CORP".encode("utf-16le")
        av = b"".join(
            [
                struct.pack("<HH", 2, len(target)),
                target,
                struct.pack("<HH", 3, len("dc01.corp.local".encode("utf-16le"))),
                "dc01.corp.local".encode("utf-16le"),
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
                b"12345678",
                b"\x00" * 8,
                _sec_buf(len(av), av_offset),
                target,
                av,
            ]
        )
        parsed = parse_type2(msg)
        self.assertEqual(parsed.target_name, "CORP")
        self.assertEqual(parsed.target_info["NbDomainName"], "CORP")
        self.assertEqual(parsed.target_info["DnsComputerName"], "dc01.corp.local")
        type3 = make_type3(
            parsed,
            username="redpen",
            password="RedteamN0t3s.",
            domain="CORP",
            cbt_hash=channel_bindings_hash_from_cert_sha256("00" * 32),
        )
        self.assertTrue(type3.startswith(b"NTLMSSP\x00"))
        self.assertEqual(struct.unpack_from("<I", type3, 8)[0], 3)

    def test_extract_ntlm_challenge(self):
        token = base64.b64encode(b"NTLMSSP\x00demo").decode("ascii")
        self.assertEqual(extract_ntlm_challenge(["Negotiate", f"NTLM {token}"]), token)


if __name__ == "__main__":
    unittest.main()
