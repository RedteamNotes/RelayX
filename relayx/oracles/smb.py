from __future__ import annotations

import os
import socket
import struct

from ..models import Confidence, Evidence, EvidenceType, Finding, Impact, Status


SMB_PORT = 445
SMB2_NEGOTIATE = 0
SMB2_SIGNING_ENABLED = 0x01
SMB2_SIGNING_REQUIRED = 0x02


def _netbios_wrap(payload: bytes) -> bytes:
    if len(payload) > 0xFFFFFF:
        raise ValueError("SMB payload too large")
    return b"\x00" + len(payload).to_bytes(3, "big") + payload


def _smb2_header(command: int = SMB2_NEGOTIATE) -> bytes:
    return b"".join(
        [
            b"\xfeSMB",
            struct.pack("<H", 64),  # StructureSize
            struct.pack("<H", 0),  # CreditCharge
            struct.pack("<I", 0),  # ChannelSequence/Reserved + Status in request
            struct.pack("<H", command),
            struct.pack("<H", 1),  # CreditRequest
            struct.pack("<I", 0),  # Flags
            struct.pack("<I", 0),  # NextCommand
            struct.pack("<Q", 1),  # MessageId
            struct.pack("<I", 0),  # ProcessId/Reserved
            struct.pack("<I", 0),  # TreeId
            struct.pack("<Q", 0),  # SessionId
            b"\x00" * 16,  # Signature
        ]
    )


def _smb2_negotiate_packet() -> bytes:
    dialects = [0x0202, 0x0210, 0x0300, 0x0302]
    request = b"".join(
        [
            struct.pack("<H", 36),  # StructureSize
            struct.pack("<H", len(dialects)),
            struct.pack("<H", SMB2_SIGNING_ENABLED),
            struct.pack("<H", 0),  # Reserved
            struct.pack("<I", 0),  # Capabilities
            os.urandom(16),  # ClientGuid
            struct.pack("<Q", 0),  # ClientStartTime
            b"".join(struct.pack("<H", d) for d in dialects),
        ]
    )
    return _netbios_wrap(_smb2_header() + request)


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        part = sock.recv(size - len(chunks))
        if not part:
            raise OSError("connection closed while reading SMB response")
        chunks.extend(part)
    return bytes(chunks)


def _probe_smb2(host: str, timeout: float) -> dict:
    with socket.create_connection((host, SMB_PORT), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(_smb2_negotiate_packet())
        nbss = _recv_exact(sock, 4)
        if nbss[0] != 0:
            raise OSError("unexpected NetBIOS session response")
        length = int.from_bytes(nbss[1:4], "big")
        response = _recv_exact(sock, length)
    if len(response) < 68 or response[:4] != b"\xfeSMB":
        raise OSError("not an SMB2 negotiate response")
    status = struct.unpack_from("<I", response, 8)[0]
    command = struct.unpack_from("<H", response, 12)[0]
    if command != SMB2_NEGOTIATE:
        raise OSError("unexpected SMB2 command in response")
    if status != 0:
        raise OSError(f"SMB2 negotiate returned status 0x{status:08x}")
    security_mode = struct.unpack_from("<H", response, 64 + 2)[0]
    dialect = struct.unpack_from("<H", response, 64 + 4)[0]
    return {
        "security_mode": security_mode,
        "signing_enabled": bool(security_mode & SMB2_SIGNING_ENABLED),
        "signing_required": bool(security_mode & SMB2_SIGNING_REQUIRED),
        "dialect": f"0x{dialect:04x}",
    }


def assess(host: str, timeout: float = 3.0) -> Finding:
    try:
        result = _probe_smb2(host, timeout=timeout)
    except OSError as exc:
        return Finding(
            host=host,
            port=SMB_PORT,
            protocol="smb",
            name="smb_signing",
            status=Status.UNKNOWN,
            confidence=Confidence.LOW,
            summary="SMB signing could not be determined.",
            evidence=[
                Evidence(
                    type=EvidenceType.ERROR,
                    key="smb_probe_error",
                    value=str(exc),
                    confidence=Confidence.LOW,
                )
            ],
            error=str(exc),
        )

    signing_required = result["signing_required"]
    if signing_required:
        status = Status.BLOCKED
        confidence = Confidence.HIGH
        summary = "SMB signing is required; SMB relay to this service is blocked."
        blockers = ["SMB signing required"]
        fixes: list[str] = []
        impact = Impact.INFO
    else:
        status = Status.RELAYABLE
        confidence = Confidence.HIGH
        summary = "SMB signing is not required; SMB relay target exposure exists."
        blockers = []
        fixes = ["Require SMB signing on this server."]
        impact = Impact.MEDIUM

    return Finding(
        host=host,
        port=SMB_PORT,
        protocol="smb",
        name="smb_signing",
        status=status,
        confidence=confidence,
        impact=impact,
        summary=summary,
        evidence=[
            Evidence(
                type=EvidenceType.OBSERVED,
                key="smb_security_mode",
                value=result["security_mode"],
                confidence=Confidence.HIGH,
                raw=result,
            ),
            Evidence(
                type=EvidenceType.OBSERVED,
                key="smb_signing_required",
                value=signing_required,
                confidence=Confidence.HIGH,
            ),
        ],
        blockers=blockers,
        fixes=fixes,
        opsec_notes=["Single SMB2 NEGOTIATE request; low-noise readiness probe."],
    )

