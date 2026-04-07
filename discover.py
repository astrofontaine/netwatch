"""netwatch/discover.py — multi-technique LAN host discovery.

Each technique returns a set of IP strings.  All are merged by discover_all().
Techniques requiring sudo receive the password via the sudo_pass argument.
"""

from __future__ import annotations
import ipaddress
import re
import subprocess
import threading
from pathlib import Path
from typing import Callable
import logging

log = logging.getLogger("netwatch.discover")

# ── helpers ───────────────────────────────────────────────────────────────────

_IP_RE = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')


def _ips(text: str, exclude: set[str] | None = None) -> set[str]:
    """Extract all valid IPs from text, optionally skipping some."""
    found = set()
    for m in _IP_RE.finditer(text):
        ip = m.group(1)
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_loopback or addr.is_multicast:
                continue
            if exclude and ip in exclude:
                continue
            found.add(ip)
        except ValueError:
            pass
    return found


def _run(cmd: list[str], timeout: int = 60, input_: str | None = None) -> str:
    """Run a command, return stdout+stderr as a single string."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout,
            input=input_,
        )
        return result.stdout + result.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError) as e:
        log.debug("Command %s failed: %s", cmd[0], e)
        return ""


def _sudo(cmd: list[str], sudo_pass: str, timeout: int = 60) -> str:
    """Run cmd under sudo, supplying password via stdin."""
    return _run(["sudo", "-S", "-p", ""] + cmd, timeout=timeout, input_=sudo_pass + "\n")


def _tool_available(name: str) -> bool:
    return subprocess.run(["which", name], capture_output=True).returncode == 0


# ── individual techniques ─────────────────────────────────────────────────────

def _t_proc_arp(subnet: str, sudo_pass: str) -> set[str]:
    """Read kernel ARP cache — no root needed."""
    try:
        text = Path("/proc/net/arp").read_text()
        return _ips(text)
    except OSError:
        return set()


def _t_ip_neigh(subnet: str, sudo_pass: str) -> set[str]:
    """ip neigh show — neighbour table, no root needed."""
    return _ips(_run(["ip", "neigh", "show"]))


def _t_ping_sweep(subnet: str, sudo_pass: str) -> set[str]:
    """Parallel ping sweep using the setuid system ping binary."""
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return set()

    found: set[str] = set()
    lock = threading.Lock()

    def ping_one(ip: str) -> None:
        r = subprocess.run(
            ["ping", "-c1", "-W1", "-q", ip],
            capture_output=True, timeout=3,
        )
        if r.returncode == 0:
            with lock:
                found.add(ip)

    threads = []
    for addr in net.hosts():
        t = threading.Thread(target=ping_one, args=(str(addr),), daemon=True)
        t.start()
        threads.append(t)
        if len(threads) >= 128:          # cap parallelism
            for t in threads:
                t.join(timeout=4)
            threads.clear()
    for t in threads:
        t.join(timeout=4)

    return found


def _t_fping(subnet: str, sudo_pass: str) -> set[str]:
    """fping -a -q -g <subnet> — fast ICMP sweep."""
    if not _tool_available("fping"):
        log.debug("fping not found")
        return set()
    out = _run(["fping", "-a", "-q", "-g", subnet], timeout=60)
    return _ips(out)


def _t_nmap_ping(subnet: str, sudo_pass: str) -> set[str]:
    """nmap -sn (ARP + ICMP) — requires sudo for raw sockets."""
    if not _tool_available("nmap"):
        log.debug("nmap not found")
        return set()
    if sudo_pass:
        out = _sudo(["nmap", "-sn", "-T4", "--host-timeout", "10s", subnet],
                    sudo_pass, timeout=120)
    else:
        out = _run(["nmap", "-sn", "-T4", "--host-timeout", "10s", subnet], timeout=120)
    return _ips(out)


def _t_arp_scan(subnet: str, sudo_pass: str) -> set[str]:
    """arp-scan --localnet — ARP, very reliable."""
    if not _tool_available("arp-scan"):
        log.debug("arp-scan not found")
        return set()
    if sudo_pass:
        out = _sudo(["arp-scan", "--localnet", "--retry=2"], sudo_pass, timeout=60)
    else:
        out = _run(["arp-scan", "--localnet", "--retry=2"], timeout=60)
    return _ips(out)


def _t_netdiscover(subnet: str, sudo_pass: str) -> set[str]:
    """netdiscover -P (passive+active, one-shot) — requires sudo."""
    if not _tool_available("netdiscover"):
        log.debug("netdiscover not found")
        return set()
    if not sudo_pass:
        return set()
    out = _sudo(["netdiscover", "-P", "-r", subnet], sudo_pass, timeout=90)
    return _ips(out)


def _t_masscan(subnet: str, sudo_pass: str) -> set[str]:
    """masscan top ports — raw TCP, very fast, needs root."""
    if not _tool_available("masscan"):
        log.debug("masscan not found")
        return set()
    if not sudo_pass:
        return set()
    out = _sudo(
        ["masscan", subnet, "-p22,80,443,8080,23,21,3389", "--rate=1000",
         "--output-format", "list"],
        sudo_pass, timeout=120
    )
    return _ips(out)


# ── technique registry ────────────────────────────────────────────────────────

TECHNIQUES: dict[str, Callable[[str, str], set[str]]] = {
    "ip_neigh":    _t_ip_neigh,
    "proc_arp":    _t_proc_arp,
    "ping_sweep":  _t_ping_sweep,
    "fping":       _t_fping,
    "nmap_ping":   _t_nmap_ping,
    "arp_scan":    _t_arp_scan,
    "netdiscover": _t_netdiscover,
    "masscan":     _t_masscan,
}


# ── Discoverer ────────────────────────────────────────────────────────────────

class Discoverer:
    def __init__(self, subnet: str, techniques: list[str], sudo_pass: str = "") -> None:
        self.subnet     = subnet
        self.techniques = techniques
        self.sudo_pass  = sudo_pass

    def discover(self) -> set[str]:
        """Run all configured techniques in parallel, return merged IP set."""
        all_ips: set[str] = set()
        lock = threading.Lock()

        def run_technique(name: str) -> None:
            fn = TECHNIQUES.get(name)
            if fn is None:
                log.warning("Unknown technique: %s", name)
                return
            log.info("  [%s] scanning…", name)
            try:
                found = fn(self.subnet, self.sudo_pass)
                log.info("  [%s] → %d host(s)", name, len(found))
                with lock:
                    all_ips.update(found)
            except Exception as exc:
                log.warning("  [%s] error: %s", name, exc)

        threads = [
            threading.Thread(target=run_technique, args=(t,), daemon=True)
            for t in self.techniques
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=120)

        return all_ips
