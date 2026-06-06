from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class ScopePolicy:
    hosts: set[str] = field(default_factory=set)
    networks: list[ipaddress._BaseNetwork] = field(default_factory=list)

    def contains(self, host: str) -> bool:
        clean = host.strip().lower()
        if not clean:
            return False
        if clean in self.hosts:
            return True
        try:
            address = ipaddress.ip_address(clean)
        except ValueError:
            return False
        return any(address in network for network in self.networks)

    def filter(self, hosts: list[str]) -> list[str]:
        return [host for host in hosts if self.contains(host)]

    @property
    def empty(self) -> bool:
        return not self.hosts and not self.networks


def load_scope(value: str | None) -> ScopePolicy | None:
    if not value:
        return None
    path = Path(value)
    if path.exists():
        items = [
            line.split("#", 1)[0].strip()
            for line in path.read_text(encoding="utf-8").splitlines()
        ]
    else:
        items = [part.strip() for part in value.split(",")]
    policy = ScopePolicy()
    for item in items:
        if not item:
            continue
        try:
            if "/" in item:
                policy.networks.append(ipaddress.ip_network(item, strict=False))
            else:
                address = ipaddress.ip_address(item)
                policy.networks.append(ipaddress.ip_network(f"{address}/{address.max_prefixlen}"))
        except ValueError:
            policy.hosts.add(item.lower())
    return policy
