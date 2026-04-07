"""netwatch/state.py — persistent host-state tracking."""

from __future__ import annotations
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path

from config import NETWATCH_DIR

STATE_FILE = NETWATCH_DIR / "hosts.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class HostRecord:
    ip: str
    first_seen: str = field(default_factory=_now)
    last_seen: str  = field(default_factory=_now)
    hostnames: list[str] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    services: dict[int, str] = field(default_factory=dict)   # port → service banner
    os_guess: str = ""
    access_results: dict[str, str] = field(default_factory=dict)  # service → result summary
    assessed: bool = False
    ssh_alias: str = ""          # e.g. "nw-192.168.2.12" once provisioned
    ssh_provisioned: bool = False


class HostState:
    def __init__(self) -> None:
        self._hosts: dict[str, HostRecord] = {}

    # ── disk I/O ─────────────────────────────────────────────────────────────

    def load(self, path: Path = STATE_FILE) -> None:
        if not path.exists():
            return
        with open(path) as fh:
            raw = json.load(fh)
        for ip, rec in raw.items():
            # services keys are ints (JSON stores them as strings)
            if "services" in rec:
                rec["services"] = {int(k): v for k, v in rec["services"].items()}
            self._hosts[ip] = HostRecord(**rec)

    def save(self, path: Path = STATE_FILE) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {}
        for ip, rec in self._hosts.items():
            d = asdict(rec)
            d["services"] = {str(k): v for k, v in d["services"].items()}
            data[ip] = d
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)

    # ── update + diff ─────────────────────────────────────────────────────────

    def update(self, live_ips: set[str]) -> tuple[set[str], set[str]]:
        """Merge newly discovered IPs into state.
        Returns (new_hosts, gone_hosts) relative to previous scan."""
        known = set(self._hosts.keys())
        new   = live_ips - known
        gone  = known - live_ips

        for ip in new:
            self._hosts[ip] = HostRecord(ip=ip)

        for ip in live_ips:
            if ip in self._hosts:
                self._hosts[ip].last_seen = _now()

        return new, gone

    def get(self, ip: str) -> HostRecord | None:
        return self._hosts.get(ip)

    def update_record(self, ip: str, **kwargs) -> None:
        rec = self._hosts.get(ip)
        if rec is None:
            return
        for k, v in kwargs.items():
            if hasattr(rec, k):
                setattr(rec, k, v)

    def all_hosts(self) -> list[HostRecord]:
        return sorted(self._hosts.values(), key=lambda r: r.ip)

    def unassessed(self) -> list[HostRecord]:
        return [r for r in self._hosts.values() if not r.assessed]
