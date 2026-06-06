from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from .engine.operation_control import OperationControl, apply_start_throttle
from .models import Finding
from .net import tcp_connect
from .oracles import http, ldap, mssql, smb


DEFAULT_PORTS = {
    "smb": [445],
    "ldap": [389, 636],
    "http": [80, 8080],
    "https": [443, 8443],
    "mssql": [1433],
}


def assess_target(
    host: str,
    timeout: float = 3.0,
    include_closed: bool = False,
    challenge_flow: bool = True,
    mssql_prefer_tls: bool = True,
    auth_validation: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []

    if tcp_connect(host, 445, timeout=timeout).open:
        findings.append(smb.assess(host, timeout=timeout))
    elif include_closed:
        findings.append(smb.assess(host, timeout=timeout))

    for port in DEFAULT_PORTS["ldap"]:
        if tcp_connect(host, port, timeout=timeout).open:
            findings.append(
                ldap.assess(
                    host,
                    port=port,
                    timeout=timeout,
                    challenge_flow=challenge_flow,
                    auth_validation=auth_validation,
                )
            )

    for port in DEFAULT_PORTS["http"]:
        if tcp_connect(host, port, timeout=timeout).open:
            findings.extend(
                http.assess(
                    host,
                    port=port,
                    scheme="http",
                    timeout=timeout,
                    challenge_flow=challenge_flow,
                    auth_validation=auth_validation,
                )
            )

    for port in DEFAULT_PORTS["https"]:
        if tcp_connect(host, port, timeout=timeout).open:
            findings.extend(
                http.assess(
                    host,
                    port=port,
                    scheme="https",
                    timeout=timeout,
                    challenge_flow=challenge_flow,
                    auth_validation=auth_validation,
                )
            )

    for port in DEFAULT_PORTS["mssql"]:
        if tcp_connect(host, port, timeout=timeout).open:
            findings.append(
                mssql.assess(
                    host,
                    port=port,
                    timeout=timeout,
                    prefer_tls=mssql_prefer_tls,
                    auth_validation=auth_validation,
                )
            )

    return findings


def assess_targets(
    targets: list[str],
    timeout: float = 3.0,
    workers: int = 16,
    challenge_flow: bool = True,
    mssql_prefer_tls: bool = True,
    auth_validation: bool = False,
    operation_control: OperationControl | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    control = operation_control or OperationControl()
    with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        futures = {}
        for index, target in enumerate(targets):
            apply_start_throttle(control, index)
            futures[
                executor.submit(
                    assess_target,
                    target,
                    timeout,
                    False,
                    challenge_flow,
                    mssql_prefer_tls,
                    auth_validation,
                )
            ] = target
        for future in as_completed(futures):
            findings.extend(future.result())
    return findings
