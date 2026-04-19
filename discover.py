"""netwatch/discover.py — multi-technique LAN host discovery.

Each technique returns a set of IP strings.  All are merged by discover_all().
Techniques requiring sudo receive the password via the sudo_pass argument.
"""

from __future__ import annotations
import ipaddress
import os
import platform
import re
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable
import logging

log = logging.getLogger("netwatch.discover")

_COMMON_MDNS_TYPES = [
    "_workstation._tcp",
    "_ssh._tcp",
    "_smb._tcp",
    "_afpovertcp._tcp",
    "_device-info._tcp",
    "_airplay._tcp",
    "_raop._tcp",
    "_ipp._tcp",
    "_printer._tcp",
    "_http._tcp",
    "_https._tcp",
    "_googlecast._tcp",
    "_companion-link._tcp",
    "_hap._tcp",
]

_LOCAL_PROTOCOL_CACHE: dict[str, object] = {
    "ts": 0.0,
    "ttl": 20.0,
    "hosts": {},
}
_LOCAL_PROTOCOL_LOCK = threading.Lock()

# ── helpers ───────────────────────────────────────────────────────────────────

_IP_RE = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')


def _ips(text: str, exclude: set[str] | None = None) -> set[str]:
    """Extract all valid IPs from text, optionally skipping some."""
    found = set()
    for m in _IP_RE.finditer(text):
        ip = m.group(1)
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_loopback or addr.is_multicast or addr.is_unspecified:
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


def _platform() -> str:
    return platform.system()


def _new_local_protocol_entry() -> dict[str, set[str]]:
    return {
        "names": set(),
        "services": set(),
        "sources": set(),
    }


def _merge_local_protocol_host(
    hosts: dict[str, dict[str, set[str]]],
    ip: str,
    *,
    names: set[str] | None = None,
    services: set[str] | None = None,
    source: str = "",
) -> None:
    if not ip:
        return
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback or addr.is_multicast:
            return
    except ValueError:
        return

    host = hosts.setdefault(ip, _new_local_protocol_entry())
    if names:
        host["names"].update(n for n in names if n and n != ip)
    if services:
        host["services"].update(s for s in services if s)
    if source:
        host["sources"].add(source)


def _hostname_candidates(name: str) -> set[str]:
    cleaned = name.rstrip(".")
    if not cleaned:
        return set()
    result = {cleaned}
    if cleaned.endswith(".local"):
        result.add(cleaned[:-6])
    return {n for n in result if n}


def _resolve_ipv4(hostname: str) -> set[str]:
    found: set[str] = set()
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror:
        return found
    for info in infos:
        ip = info[4][0]
        try:
            addr = ipaddress.ip_address(ip)
            if not addr.is_loopback and not addr.is_multicast:
                found.add(ip)
        except ValueError:
            continue
    return found


def _browse_dns_sd(service_type: str, timeout: float = 1.5) -> list[str]:
    if not _tool_available("dns-sd"):
        return []
    proc = subprocess.Popen(
        ["dns-sd", "-B", service_type, "local."],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        time.sleep(timeout)
        proc.terminate()
        out, _ = proc.communicate(timeout=2)
    except Exception:
        proc.kill()
        out, _ = proc.communicate()

    instances: list[str] = []
    suffix = f".{service_type}.local."
    for line in out.splitlines():
        if " Add " not in line and "\tAdd" not in line:
            continue
        idx = line.find("local.")
        if idx == -1:
            continue
        rest = line[idx + len("local."):].strip()
        if not rest.endswith(suffix):
            continue
        instance = rest[: -len(suffix)].strip()
        if instance and instance not in instances:
            instances.append(instance)
    return instances


def _resolve_dns_sd_instance(instance: str, service_type: str) -> dict[str, object]:
    if not _tool_available("dns-sd"):
        return {"hostnames": set(), "ips": set(), "service": ""}
    proc = subprocess.Popen(
        ["dns-sd", "-L", instance, service_type, "local."],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        time.sleep(1.2)
        proc.terminate()
        out, _ = proc.communicate(timeout=2)
    except Exception:
        proc.kill()
        out, _ = proc.communicate()

    hostnames: set[str] = set()
    ips: set[str] = set()
    service_label = f"mDNS {service_type} {instance}"

    for line in out.splitlines():
        match = re.search(r"can be reached at (\S+)\.:([0-9]+)", line)
        if match:
            host = match.group(1).rstrip(".")
            port = match.group(2)
            hostnames.update(_hostname_candidates(host))
            ips.update(_resolve_ipv4(host))
            service_label = f"mDNS {service_type} {instance} port={port}"
            continue
        if line.lstrip().startswith("txtvers=") or "=" in line:
            txt = line.strip()
            if txt:
                service_label = f"{service_label} txt={txt[:80]}"

    if not hostnames:
        hostnames.update(_hostname_candidates(instance))

    return {"hostnames": hostnames, "ips": ips, "service": service_label}


def _discover_mdns_hosts(timeout: float = 1.2) -> dict[str, dict[str, set[str]]]:
    hosts: dict[str, dict[str, set[str]]] = {}

    if _tool_available("avahi-browse"):
        out = _run(["avahi-browse", "-arp", "-t"], timeout=max(2, int(timeout * 4)))
        for line in out.splitlines():
            if not line.startswith("="):
                continue
            parts = line.split(";")
            if len(parts) < 9:
                continue
            _, _, _, instance, service_type, domain, host, address, port, *txt = parts
            names = _hostname_candidates(host)
            if instance:
                names.add(instance)
            txt_suffix = f" txt={' '.join(txt)[:80]}" if txt else ""
            service = f"mDNS {service_type} {instance} port={port}{txt_suffix}"
            _merge_local_protocol_host(
                hosts, address,
                names=names,
                services={service},
                source="mdns",
            )
        return hosts

    if not _tool_available("dns-sd"):
        return hosts

    for service_type in _COMMON_MDNS_TYPES:
        for instance in _browse_dns_sd(service_type, timeout=timeout):
            resolved = _resolve_dns_sd_instance(instance, service_type)
            for ip in sorted(resolved["ips"]):
                _merge_local_protocol_host(
                    hosts, ip,
                    names=set(resolved["hostnames"]),
                    services={str(resolved["service"])},
                    source="mdns",
                )

    return hosts


def _discover_ssdp_hosts(timeout: float = 1.0) -> dict[str, dict[str, set[str]]]:
    hosts: dict[str, dict[str, set[str]]] = {}
    message = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 1\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    ).encode()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.settimeout(timeout)
        sock.sendto(message, ("239.255.255.250", 1900))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, (ip, _) = sock.recvfrom(8192)
            except socket.timeout:
                break
            text = data.decode(errors="replace")
            headers: dict[str, str] = {}
            for line in text.splitlines():
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()
            service_bits = []
            if headers.get("server"):
                service_bits.append(f"server={headers['server'][:60]}")
            if headers.get("st"):
                service_bits.append(f"st={headers['st'][:80]}")
            if headers.get("usn"):
                service_bits.append(f"usn={headers['usn'][:80]}")
            if headers.get("location"):
                service_bits.append(f"location={headers['location'][:80]}")
            service = "SSDP " + " ".join(service_bits) if service_bits else "SSDP response"
            _merge_local_protocol_host(
                hosts, ip,
                services={service},
                source="ssdp",
            )
    except OSError:
        return hosts
    finally:
        sock.close()

    return hosts


def _get_local_protocol_hosts(force_refresh: bool = False) -> dict[str, dict[str, set[str]]]:
    with _LOCAL_PROTOCOL_LOCK:
        cached_hosts = _LOCAL_PROTOCOL_CACHE.get("hosts", {})
        now = time.time()
        if (
            not force_refresh
            and cached_hosts
            and now - float(_LOCAL_PROTOCOL_CACHE.get("ts", 0.0)) < float(_LOCAL_PROTOCOL_CACHE.get("ttl", 20.0))
        ):
            return cached_hosts  # type: ignore[return-value]

        hosts: dict[str, dict[str, set[str]]] = {}
        for discovered in (_discover_mdns_hosts(), _discover_ssdp_hosts()):
            for ip, entry in discovered.items():
                _merge_local_protocol_host(
                    hosts, ip,
                    names=entry["names"],
                    services=entry["services"],
                    source=",".join(sorted(entry["sources"])),
                )

        _LOCAL_PROTOCOL_CACHE["ts"] = now
        _LOCAL_PROTOCOL_CACHE["hosts"] = hosts
        return hosts


# ── individual techniques ─────────────────────────────────────────────────────

def _t_proc_arp(subnet: str, sudo_pass: str) -> set[str]:
    """Read kernel ARP cache — no root needed."""
    try:
        text = Path("/proc/net/arp").read_text()
        return _ips(text)
    except OSError:
        return set()


def _t_ip_neigh(subnet: str, sudo_pass: str) -> set[str]:
    """ip neigh show — neighbour table, no root needed.  Skips FAILED entries."""
    found = set()
    for line in _run(["ip", "neigh", "show"]).splitlines():
        if "FAILED" in line:
            continue
        m = _IP_RE.search(line)
        if m:
            ip = m.group(1)
            try:
                addr = ipaddress.ip_address(ip)
                if not addr.is_loopback and not addr.is_multicast:
                    found.add(ip)
            except ValueError:
                pass
    return found


def _t_ping_sweep(subnet: str, sudo_pass: str) -> set[str]:
    """Parallel ping sweep using the setuid system ping binary."""
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return set()

    found: set[str] = set()
    lock = threading.Lock()
    system = _platform()

    timeout_seconds = float(os.environ.get("NETWATCH_PING_TIMEOUT", "1.0"))
    timeout_ms = max(1, int(timeout_seconds * 1000))

    def ping_cmd(ip: str) -> list[str]:
        if system == "Darwin":
            return ["ping", "-c", "1", "-t", "1", ip]
        timeout_flag = max(1, int(round(timeout_seconds)))
        return ["ping", "-c1", f"-W{timeout_flag}", "-q", ip]

    def ping_one(ip: str) -> None:
        try:
            r = subprocess.run(
                ping_cmd(ip),
                capture_output=True, timeout=max(2.0, timeout_seconds + 1.0),
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
            return
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
                t.join(timeout=max(2.0, timeout_seconds + 1.0))
            threads.clear()
    for t in threads:
        t.join(timeout=max(2.0, timeout_seconds + 1.0))

    return found


def _t_arp_table(subnet: str, sudo_pass: str) -> set[str]:
    """Parse the system ARP cache via arp(8), which exists on macOS and many Linux hosts."""
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return set()
    out = _run(["arp", "-an"])
    return {
        ip for ip in _ips(out)
        if ipaddress.ip_address(ip) in net
        and ipaddress.ip_address(ip) not in (net.network_address, net.broadcast_address)
    }


def _t_mdns_browse(subnet: str, sudo_pass: str) -> set[str]:
    """Browse Bonjour/mDNS advertisements and resolve them to IPv4 hosts."""
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return set()
    hosts = _get_local_protocol_hosts()
    return {
        ip for ip, entry in hosts.items()
        if "mdns" in entry["sources"] and ipaddress.ip_address(ip) in net
    }


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


def _t_tcp_connect_sweep(subnet: str, sudo_pass: str) -> set[str]:
    """Probe a few common ports to find live hosts without raw socket privileges."""
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return set()

    ports = [22, 80, 443, 445, 548, 8000, 8080, 8443, 62078]
    timeout = float(os.environ.get("NETWATCH_TCP_SWEEP_TIMEOUT", "0.2"))
    found: set[str] = set()
    lock = threading.Lock()

    def probe_host(ip: str) -> None:
        for port in ports:
            try:
                with socket.create_connection((ip, port), timeout=timeout):
                    with lock:
                        found.add(ip)
                    return
            except OSError:
                continue

    threads = []
    for addr in net.hosts():
        t = threading.Thread(target=probe_host, args=(str(addr),), daemon=True)
        t.start()
        threads.append(t)
        if len(threads) >= 128:
            for worker in threads:
                worker.join(timeout=max(1.0, timeout * len(ports)))
            threads.clear()
    for worker in threads:
        worker.join(timeout=max(1.0, timeout * len(ports)))

    return found


def _t_ssdp(subnet: str, sudo_pass: str) -> set[str]:
    """Discover UPnP/SSDP-speaking hosts via multicast M-SEARCH."""
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return set()
    hosts = _get_local_protocol_hosts()
    return {
        ip for ip, entry in hosts.items()
        if "ssdp" in entry["sources"] and ipaddress.ip_address(ip) in net
    }


# ── enrichment helpers ────────────────────────────────────────────────────────

def get_mac(ip: str) -> str:
    """Return the MAC address for ip, or '' if unknown.

    Sources tried in order:
      1. /proc/net/arp  (fast, kernel ARP cache)
      2. ip neigh show  (picks up STALE entries /proc misses)
      3. ip link show   (own interface — for the local machine's IP)
    """
    try:
        text = Path("/proc/net/arp").read_text()
        for line in text.splitlines():
            parts = line.split()
            if parts and parts[0] == ip and len(parts) >= 4:
                mac = parts[3]
                if mac != "00:00:00:00:00:00":
                    return mac
    except OSError:
        pass

    # ip neigh show catches STALE entries /proc/net/arp may not have
    for line in _run(["ip", "neigh", "show", ip]).splitlines():
        m = re.search(r'lladdr\s+([0-9a-f:]{17})', line)
        if m:
            return m.group(1)

    # Local machine: find which interface owns this IP by scanning ip addr show
    addr_text = _run(["ip", "addr", "show"])
    current_iface = None
    for line in addr_text.splitlines():
        m = re.match(r'^\d+:\s+(\S+?)[@:]', line)
        if m:
            current_iface = m.group(1)
        if current_iface and f" {ip}/" in line and "inet " in line:
            # Found the owning interface — extract its MAC from its block
            iface_block = _run(["ip", "link", "show", current_iface])
            mac_m = re.search(r'link/ether\s+([0-9a-f:]{17})', iface_block)
            if mac_m:
                return mac_m.group(1)

    return ""


def get_local_services(ip: str) -> list[str]:
    """Return local-protocol observations for ip, such as mDNS/Bonjour and SSDP."""
    hosts = _get_local_protocol_hosts()
    entry = hosts.get(ip)
    if not entry:
        return []
    return sorted(entry["services"])


def get_hostnames(ip: str, timeout: float = 2.0) -> list[str]:
    """Return all resolvable names for ip, deduplicated and sorted.

    Sources tried:
      1. socket.gethostbyaddr()  — system resolver (DNS + /etc/hosts + mDNS via nsswitch)
      2. avahi-resolve-address   — mDNS (.local names) if avahi-utils is installed
      3. nmblookup -A            — NetBIOS name if samba-client is installed
    """
    names: set[str] = set()

    entry = _get_local_protocol_hosts().get(ip)
    if entry:
        names.update(entry["names"])

    # 1 — system resolver
    try:
        hostname, aliases, _ = socket.gethostbyaddr(ip)
        if hostname and hostname != ip:
            names.add(hostname)
        for a in aliases:
            if a and a != ip:
                names.add(a)
    except (socket.herror, socket.gaierror, OSError):
        pass

    # 2 — avahi mDNS (catches .local names that the system resolver may miss)
    if subprocess.run(["which", "avahi-resolve"], capture_output=True).returncode == 0:
        r = _run(["avahi-resolve", "--address", ip], timeout=int(timeout) + 1)
        for line in r.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == ip:
                name = parts[1].rstrip(".")
                if name and name != ip:
                    names.add(name)

    # 3 — NetBIOS (Windows/Samba/macOS hosts)
    if subprocess.run(["which", "nmblookup"], capture_output=True).returncode == 0:
        r = _run(["nmblookup", "-A", ip], timeout=int(timeout) + 1)
        for line in r.splitlines():
            # Match individual host entries — skip GROUP lines and __MSBROWSE__
            m = re.match(r'^\s+(\S+)\s+<\w+>\s+-\s+\S+\s+<ACTIVE>', line)
            if m and "<GROUP>" not in line:
                name = m.group(1).strip()
                if name not in ("__MSBROWSE__",) and name != ip:
                    names.add(name)

    result = sorted(names)
    if result:
        log.debug("[hostnames] %s → %s", ip, result)
    return result


# ── technique registry ────────────────────────────────────────────────────────

TECHNIQUES: dict[str, Callable[[str, str], set[str]]] = {
    "ip_neigh":    _t_ip_neigh,
    "proc_arp":    _t_proc_arp,
    "arp_table":   _t_arp_table,
    "mdns_browse": _t_mdns_browse,
    "ssdp":        _t_ssdp,
    "ping_sweep":  _t_ping_sweep,
    "fping":       _t_fping,
    "nmap_ping":   _t_nmap_ping,
    "arp_scan":    _t_arp_scan,
    "netdiscover": _t_netdiscover,
    "masscan":     _t_masscan,
    "tcp_connect_sweep": _t_tcp_connect_sweep,
}


# ── Discoverer ────────────────────────────────────────────────────────────────

class Discoverer:
    def __init__(
        self,
        subnet: str,
        techniques: list[str],
        sudo_pass: str = "",
        extra_subnets: list[str] | None = None,
    ) -> None:
        self.subnet     = subnet
        self.extra_subnets = extra_subnets or []
        self.techniques = techniques
        self.sudo_pass  = sudo_pass

    def discover(self) -> set[str]:
        """Run all configured techniques in parallel, return merged IP set."""
        all_ips: set[str] = set()
        lock = threading.Lock()
        target_subnets = [self.subnet] + [s for s in self.extra_subnets if s != self.subnet]
        if any(t in {"mdns_browse", "ssdp"} for t in self.techniques):
            _get_local_protocol_hosts(force_refresh=True)

        def run_technique(name: str, subnet: str) -> None:
            fn = TECHNIQUES.get(name)
            if fn is None:
                log.warning("Unknown technique: %s", name)
                return
            log.info("  [%s] scanning %s…", name, subnet)
            try:
                found = fn(subnet, self.sudo_pass)
                log.info("  [%s] %s → %d host(s)", name, subnet, len(found))
                with lock:
                    all_ips.update(found)
            except Exception as exc:
                log.warning("  [%s] %s error: %s", name, subnet, exc)

        threads = [
            threading.Thread(target=run_technique, args=(t, subnet), daemon=True)
            for t in self.techniques
            for subnet in target_subnets
        ]
        for t in threads:
            t.start()
        deadline = time.time() + 120
        for t in threads:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            t.join(timeout=remaining)

        # Filter to candidate subnets and drop network/broadcast addresses.
        try:
            nets = [ipaddress.ip_network(subnet, strict=False) for subnet in target_subnets]
            all_ips = {
                ip for ip in all_ips
                if any(
                    ipaddress.ip_address(ip) in net
                    and ipaddress.ip_address(ip) not in (net.network_address, net.broadcast_address)
                    for net in nets
                )
            }
        except ValueError:
            pass

        return all_ips
