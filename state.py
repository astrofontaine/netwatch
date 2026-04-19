"""netwatch/state.py — persistent host-state tracking with full change logging."""

from __future__ import annotations
import json
import logging
from dataclasses import dataclass, field, asdict, fields as dc_fields
from datetime import datetime, timezone
from pathlib import Path

from config import NETWATCH_DIR

STATE_FILE = NETWATCH_DIR / "hosts.json"

log = logging.getLogger("netwatch.state")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _fmt(v) -> str:
    """Compact representation of a value for log lines — truncated at 120 chars."""
    s = repr(v) if isinstance(v, (list, dict)) else str(v)
    return s[:120] + "…" if len(s) > 120 else s


# ── HostRecord ────────────────────────────────────────────────────────────────

@dataclass
class HostRecord:
    ip: str
    first_seen: str        = field(default_factory=_now)
    last_heard_from: str   = field(default_factory=_now)
    hostnames: list[str]   = field(default_factory=list)
    local_services: list[str] = field(default_factory=list)
    open_ports: list[int]  = field(default_factory=list)
    services: dict[int, str] = field(default_factory=dict)   # port → banner
    os_guess: str          = ""
    access_results: dict[str, str] = field(default_factory=dict)
    assessed: bool         = False
    mac_address: str       = ""
    ssh_alias: str         = ""
    ssh_provisioned: bool  = False
    # Append-only change log — capped at MAX_HISTORY entries per host
    history: list[dict]    = field(default_factory=list)


MAX_HISTORY = 500   # entries per host before oldest are dropped

_VALID_FIELDS = {f.name for f in dc_fields(HostRecord)}


# ── HostState ─────────────────────────────────────────────────────────────────

class HostState:
    def __init__(self) -> None:
        self._hosts: dict[str, HostRecord] = {}

    # ── disk I/O ─────────────────────────────────────────────────────────────

    def load(self, path: Path = STATE_FILE) -> None:
        if not path.exists():
            log.info("[state] No state file at %s — starting fresh", path)
            return
        with open(path) as fh:
            raw = json.load(fh)
        for ip, rec in raw.items():
            if "services" in rec:
                rec["services"] = {int(k): v for k, v in rec["services"].items()}
            if "last_heard_from" not in rec:
                rec["last_heard_from"] = rec.get("last_seen", _now())
            rec.pop("last_seen", None)
            # Defensive: ignore keys added/removed across versions
            safe = {k: v for k, v in rec.items() if k in _VALID_FIELDS}
            self._hosts[ip] = HostRecord(**safe)
        log.info("[state] Loaded %d host record(s) from %s", len(self._hosts), path)

    def save(self, path: Path = STATE_FILE) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {}
        for ip, rec in self._hosts.items():
            d = asdict(rec)
            d["services"] = {str(k): v for k, v in d["services"].items()}
            data[ip] = d
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)
        log.debug("[state] Saved %d host record(s) to %s", len(self._hosts), path)

    # ── history ───────────────────────────────────────────────────────────────

    def _append_history(self, ip: str, event: str, **kw) -> None:
        rec = self._hosts.get(ip)
        if rec is None:
            return
        entry: dict = {"ts": _now(), "event": event}
        entry.update(kw)
        rec.history.append(entry)
        if len(rec.history) > MAX_HISTORY:
            rec.history = rec.history[-MAX_HISTORY:]

    # ── update + diff ─────────────────────────────────────────────────────────

    def update(self, live_ips: set[str]) -> tuple[set[str], set[str]]:
        """Merge newly discovered IPs; return (new_hosts, gone_hosts)."""
        known = set(self._hosts.keys())
        new   = live_ips - known
        gone  = known - live_ips

        for ip in sorted(new):
            self._hosts[ip] = HostRecord(ip=ip)
            log.info("[state] NEW host discovered: %s", ip)
            self._append_history(ip, "first_seen")

        for ip in sorted(gone):
            rec = self._hosts.get(ip)
            if rec:
                ports_str = ", ".join(str(p) for p in sorted(rec.open_ports)) or "none"
                log.info(
                    "[state] HOST WENT OFFLINE: %s  (last_heard_from=%s  ports=%s  "
                    "alias=%s  assessed=%s)",
                    ip, rec.last_heard_from, ports_str,
                    rec.ssh_alias or "—", rec.assessed,
                )
                # Log prior probe results so nothing is silently lost
                for svc, res in rec.access_results.items():
                    log.info("[state]   last known %-10s %s", svc + ":", res)
                self._append_history(ip, "went_offline",
                                     last_ports=sorted(rec.open_ports),
                                     last_alias=rec.ssh_alias)

        for ip in live_ips:
            if ip in self._hosts:
                self._hosts[ip].last_heard_from = _now()

        return new, gone

    def get(self, ip: str) -> HostRecord | None:
        return self._hosts.get(ip)

    def update_record(self, ip: str, **kwargs) -> None:
        """Apply field updates; log every change that differs from current value."""
        rec = self._hosts.get(ip)
        if rec is None:
            log.warning("[state] update_record called for unknown host %s — skipping", ip)
            return
        for k, v in kwargs.items():
            if k not in _VALID_FIELDS:
                log.debug("[state] %s  ignoring unknown field %r", ip, k)
                continue
            old = getattr(rec, k)
            if old == v:
                continue
            # Skip noisy last_heard_from churn — tracked by update() already
            if k == "last_heard_from":
                setattr(rec, k, v)
                continue
            log.info("[state] %s  %-18s  %s  →  %s", ip, k, _fmt(old), _fmt(v))
            self._append_history(ip, "field_changed", field=k,
                                 old=old, new=v)
            setattr(rec, k, v)

    def all_hosts(self) -> list[HostRecord]:
        return sorted(self._hosts.values(), key=lambda r: r.ip)

    def unassessed(self) -> list[HostRecord]:
        return [r for r in self._hosts.values() if not r.assessed]
