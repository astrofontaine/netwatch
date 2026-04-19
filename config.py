"""netwatch/config.py — configuration dataclass + defaults."""

from __future__ import annotations
import ipaddress
import json
import logging
import platform
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger("netwatch.config")

NETWATCH_DIR = Path.home() / ".netwatch"
CONFIG_FILE  = NETWATCH_DIR / "config.json"

LEGACY_DEFAULT_SUBNET = "192.168.2.0/24"
DEFAULT_MAX_CANDIDATE_SUBNETS = 6


def _run(cmd: list[str]) -> str:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        return result.stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def _default_interface() -> str:
    system = platform.system()
    if system == "Darwin":
        route = _run(["route", "-n", "get", "default"])
        match = re.search(r"interface:\s+(\S+)", route)
        if match:
            return match.group(1)
    elif system == "Linux":
        route = _run(["ip", "route", "show", "default"])
        match = re.search(r"\bdev\s+(\S+)", route)
        if match:
            return match.group(1)
    return ""


def _unique_subnets(subnets: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for subnet in subnets:
        if not subnet or subnet in seen:
            continue
        seen.add(subnet)
        result.append(subnet)
    return result


def _valid_subnet(value: str) -> str | None:
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        return None


def _private_arp_subnets() -> list[str]:
    arp = _run(["arp", "-an"])
    if not arp:
        return []
    subnets: list[str] = []
    for match in re.finditer(r"\((\d+\.\d+\.\d+\.\d+)\)", arp):
        ip = match.group(1)
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if not isinstance(addr, ipaddress.IPv4Address):
            continue
        if addr.is_loopback or addr.is_link_local or addr.is_multicast or not addr.is_private:
            continue
        if addr.packed[-1] in (0, 255):
            continue
        subnets.append(str(ipaddress.ip_network(f"{ip}/24", strict=False)))
    return _unique_subnets(subnets)


def _candidate_subnets(
    primary: str,
    configured_extra: list[str],
    successful_subnets: list[str],
    max_candidates: int,
) -> tuple[str, list[str]]:
    preferred = _unique_subnets(
        [_valid_subnet(primary) or LEGACY_DEFAULT_SUBNET]
        + [_valid_subnet(s) for s in successful_subnets if _valid_subnet(s)]
        + [_valid_subnet(s) for s in detect_local_subnets() if _valid_subnet(s)]
        + [_valid_subnet(s) for s in configured_extra if _valid_subnet(s)]
    )
    arp_candidates = [
        subnet
        for subnet in (_valid_subnet(s) for s in _private_arp_subnets())
        if subnet and not any(
            ipaddress.ip_network(subnet, strict=False).subnet_of(ipaddress.ip_network(existing, strict=False))
            for existing in preferred
        )
    ]
    ordered = list(preferred)
    selected = [ipaddress.ip_network(subnet, strict=False) for subnet in ordered]
    for subnet in arp_candidates:
        net = ipaddress.ip_network(subnet, strict=False)
        if any(net.subnet_of(existing) or existing.subnet_of(net) for existing in selected):
            continue
        ordered.append(subnet)
        selected.append(net)
    if not ordered:
        ordered = [LEGACY_DEFAULT_SUBNET]
    limited = ordered[:max(1, max_candidates)]
    return limited[0], limited[1:]


def _darwin_local_subnets() -> list[str]:
    ifconfig = _run(["ifconfig"])
    if not ifconfig:
        return []

    blocks: list[tuple[str, str]] = []
    current = ""
    lines: list[str] = []
    for line in ifconfig.splitlines():
        if line and not line.startswith("\t") and not line.startswith(" "):
            if current and lines:
                blocks.append((current, "\n".join(lines)))
            current = line.split(":", 1)[0]
            lines = [line]
        elif current:
            lines.append(line)
    if current and lines:
        blocks.append((current, "\n".join(lines)))

    preferred = _default_interface()
    subnets: list[str] = []

    def priority(name: str, block: str) -> tuple[int, int, str]:
        is_preferred = 0 if preferred and name == preferred else 1
        is_bridge = 0 if name.startswith("bridge") else 1
        return (is_preferred, is_bridge, name)

    for name, block in sorted(blocks, key=lambda item: priority(item[0], item[1])):
        if name.startswith("lo"):
            continue
        if "status: active" not in block:
            continue
        match = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(0x[0-9a-fA-F]+)", block)
        if not match:
            continue
        ip = match.group(1)
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.is_loopback or addr.is_link_local:
            continue
        netmask = str(ipaddress.IPv4Address(int(match.group(2), 16)))
        subnet = str(ipaddress.ip_network(f"{ip}/{netmask}", strict=False))
        subnets.append(subnet)

    return _unique_subnets(subnets)


def _linux_local_subnets() -> list[str]:
    addr = _run(["ip", "-o", "-f", "inet", "addr", "show", "up"])
    subnets: list[str] = []
    for line in addr.splitlines():
        match = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+/\d+)\b", line)
        if not match:
            continue
        iface_match = re.match(r"\d+:\s+(\S+)\s+", line)
        if iface_match and iface_match.group(1).startswith("lo"):
            continue
        try:
            net = ipaddress.ip_interface(match.group(1))
        except ValueError:
            continue
        if net.ip.is_loopback or net.ip.is_link_local:
            continue
        subnets.append(str(net.network))
    return _unique_subnets(subnets)


def detect_local_subnets() -> list[str]:
    system = platform.system()
    if system == "Darwin":
        return _darwin_local_subnets() or [LEGACY_DEFAULT_SUBNET]
    if system == "Linux":
        return _linux_local_subnets() or [LEGACY_DEFAULT_SUBNET]
    return [LEGACY_DEFAULT_SUBNET]


def detect_default_subnet() -> str:
    return detect_local_subnets()[0]


def detect_extra_subnets() -> list[str]:
    local_subnets = detect_local_subnets()
    return local_subnets[1:] if len(local_subnets) > 1 else []


def default_discovery_techniques() -> list[str]:
    system = platform.system()
    if system == "Darwin":
        return [
            "arp_table",
            "mdns_browse",
            "ssdp",
            "ping_sweep",
            "tcp_connect_sweep",
        ]
    return [
        "ip_neigh",
        "proc_arp",
        "arp_table",
        "mdns_browse",
        "ssdp",
        "ping_sweep",
        "fping",
        "nmap_ping",
        "arp_scan",
        "netdiscover",
        "tcp_connect_sweep",
    ]


@dataclass
class Config:
    subnet: str = field(default_factory=detect_default_subnet)
    extra_subnets: list[str] = field(default_factory=detect_extra_subnets)
    successful_subnets: list[str] = field(default_factory=list)
    interval_seconds: int = 300          # daemon poll cadence (5 min)
    sudo_required: bool = True           # whether any discovery needs sudo
    max_candidate_subnets: int = DEFAULT_MAX_CANDIDATE_SUBNETS

    # ordered list of techniques to try; omit any that shouldn't run
    discovery_techniques: list[str] = field(default_factory=default_discovery_techniques)

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
    ping_timeout_seconds: float = 1.0
    tcp_sweep_timeout_seconds: float = 0.2

    log_level: str = "INFO"

    # ── persistence ──────────────────────────────────────────────────────────

    def save(self, path: Path = CONFIG_FILE) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.subnet, self.extra_subnets = _candidate_subnets(
            self.subnet,
            self.extra_subnets,
            self.successful_subnets,
            self.max_candidate_subnets,
        )
        with open(path, "w") as fh:
            json.dump(self.__dict__, fh, indent=2)

    def target_subnets(self) -> list[str]:
        primary, extra = _candidate_subnets(
            self.subnet,
            self.extra_subnets,
            self.successful_subnets,
            self.max_candidate_subnets,
        )
        return [primary] + extra

    def remember_successful_subnets(self, live_ips: set[str]) -> bool:
        nets = [ipaddress.ip_network(subnet, strict=False) for subnet in self.target_subnets()]
        seen: list[str] = []
        for ip in sorted(live_ips):
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            for net in nets:
                if addr in net:
                    seen.append(str(net))
                    break
        updated = _unique_subnets(seen + self.successful_subnets)
        if updated != self.successful_subnets:
            self.successful_subnets = updated
            return True
        return False

    @classmethod
    def load(cls, path: Path = CONFIG_FILE) -> "Config":
        if not path.exists():
            cfg = cls()
            log.info("[config] No config file found — using defaults  "
                     "(subnet=%s  extra_subnets=[%s]  interval=%ds)",
                     cfg.subnet, ", ".join(cfg.extra_subnets), cfg.interval_seconds)
            return cfg
        with open(path) as fh:
            data = json.load(fh)
        valid = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        cfg = cls(**valid)
        if "subnet" not in data:
            cfg.subnet = detect_default_subnet()
        cfg.subnet, cfg.extra_subnets = _candidate_subnets(
            cfg.subnet,
            cfg.extra_subnets,
            cfg.successful_subnets,
            cfg.max_candidate_subnets,
        )
        if "discovery_techniques" not in data:
            cfg.discovery_techniques = default_discovery_techniques()
        log.info(
            "[config] Loaded from %s  subnet=%s  extra_subnets=[%s]  "
            "successful_subnets=[%s]  interval=%ds  techniques=[%s]  probes=[%s]  log_level=%s",
            path, cfg.subnet, ", ".join(cfg.extra_subnets), ", ".join(cfg.successful_subnets),
            cfg.interval_seconds,
            ", ".join(cfg.discovery_techniques),
            ", ".join(cfg.access_probes),
            cfg.log_level,
        )
        return cfg
