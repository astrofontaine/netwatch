"""netwatch/config.py — configuration dataclass + defaults."""

from __future__ import annotations
import json
from dataclasses import dataclass, field
from pathlib import Path

NETWATCH_DIR = Path.home() / ".netwatch"
CONFIG_FILE  = NETWATCH_DIR / "config.json"


@dataclass
class Config:
    subnet: str = "192.168.2.0/24"
    interval_seconds: int = 300          # daemon poll cadence (5 min)
    sudo_required: bool = True           # whether any discovery needs sudo

    # ordered list of techniques to try; omit any that shouldn't run
    discovery_techniques: list[str] = field(default_factory=lambda: [
        "ip_neigh",       # ip neigh show            — no sudo
        "proc_arp",       # /proc/net/arp read        — no sudo
        "ping_sweep",     # parallel ping             — no sudo (setuid bit)
        "fping",          # fping -a -q -g            — no sudo
        "nmap_ping",      # nmap -sn (ARP)            — sudo
        "arp_scan",       # arp-scan --localnet       — sudo
        "netdiscover",    # netdiscover -P -r         — sudo
    ])

    # which services the accessor should probe on new hosts
    access_probes: list[str] = field(default_factory=lambda: [
        "portscan", "ssh", "http", "snmp", "smb",
    ])

    # SNMP community strings to try (in order)
    snmp_communities: list[str] = field(default_factory=lambda: [
        "public", "private", "community",
    ])

    # SSH: how long to wait per connection attempt (seconds)
    ssh_timeout: int = 8

    # HTTP: connect timeout
    http_timeout: int = 5

    log_level: str = "INFO"

    # ── persistence ──────────────────────────────────────────────────────────

    def save(self, path: Path = CONFIG_FILE) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as fh:
            json.dump(self.__dict__, fh, indent=2)

    @classmethod
    def load(cls, path: Path = CONFIG_FILE) -> "Config":
        if not path.exists():
            return cls()
        with open(path) as fh:
            data = json.load(fh)
        valid = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**valid)
