from __future__ import annotations

import socket
import ssl
from contextlib import closing
from dataclasses import dataclass


@dataclass(slots=True)
class ConnectResult:
    open: bool
    error: str = ""


def tcp_connect(host: str, port: int, timeout: float = 3.0) -> ConnectResult:
    try:
        with closing(socket.create_connection((host, port), timeout=timeout)):
            return ConnectResult(open=True)
    except OSError as exc:
        return ConnectResult(open=False, error=str(exc))


def tls_connect(host: str, port: int, timeout: float = 4.0) -> tuple[bool, str, dict]:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert(binary_form=False) or {}
                return True, "", cert
    except OSError as exc:
        return False, str(exc), {}
    except ssl.SSLError as exc:
        return False, str(exc), {}


def resolve_host(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return []
    addresses = []
    for info in infos:
        address = info[4][0]
        if address not in addresses:
            addresses.append(address)
    return addresses

