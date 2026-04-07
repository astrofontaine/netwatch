"""netwatch/accessor.py — service assessment and credential testing for new hosts.

Probes: portscan → SSH → HTTP/HTTPS → SNMP → SMB
Results are summarised as short strings stored in HostRecord.access_results.
"""

from __future__ import annotations
import logging
import socket
import subprocess
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from creds import CredVault
    from config import Config

log = logging.getLogger("netwatch.accessor")


# ── low-level helpers ─────────────────────────────────────────────────────────

def _run(cmd: list[str], timeout: int = 15, input_: str | None = None) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, input=input_)
        return r.returncode, r.stdout + r.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return -1, ""


def _tcp_open(ip: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


# ── port scan ─────────────────────────────────────────────────────────────────

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1723, 3306, 3389, 5900, 6379, 8080, 8443, 8888,
    27017, 9200, 1883, 5683,  # MQTT, CoAP (IoT)
]


def probe_portscan(ip: str, cfg: "Config") -> dict[int, str]:
    """Return {port: banner} for open ports.  Uses nmap if available, else raw sockets."""
    open_ports: dict[int, str] = {}

    if subprocess.run(["which", "nmap"], capture_output=True).returncode == 0:
        rc, out = _run(
            ["nmap", "-sV", "-T4", f"--host-timeout={cfg.ssh_timeout * 3}s",
             "-p", ",".join(str(p) for p in TOP_PORTS), ip],
            timeout=90
        )
        # parse "PORT   STATE SERVICE  VERSION"
        for line in out.splitlines():
            m = re.match(r'(\d+)/tcp\s+open\s+(\S+)\s*(.*)', line)
            if m:
                open_ports[int(m.group(1))] = f"{m.group(2)} {m.group(3)}".strip()
    else:
        # fallback: raw socket connect scan
        for port in TOP_PORTS:
            if _tcp_open(ip, port, timeout=1.5):
                open_ports[port] = "open"

    return open_ports


# ── SSH ───────────────────────────────────────────────────────────────────────

def probe_ssh(ip: str, cfg: "Config", vault: "CredVault") -> str:
    """Try stored SSH credentials.  Returns result summary."""
    if not _tcp_open(ip, 22):
        return "port closed"

    try:
        import paramiko
    except ImportError:
        # fallback: try with sshpass + ssh CLI
        return _probe_ssh_cli(ip, cfg, vault)

    creds = vault.get(ip, "ssh")
    if not creds:
        return "no credentials"

    for c in creds:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            if c.get("type") == "key_path":
                client.connect(ip, port=22, username=c["user"],
                               key_filename=c["secret"],
                               timeout=cfg.ssh_timeout, allow_agent=True)
            else:
                client.connect(ip, port=22, username=c["user"],
                               password=c["secret"],
                               timeout=cfg.ssh_timeout, allow_agent=False,
                               look_for_keys=False)

            _, stdout, _ = client.exec_command("uname -a")
            banner = stdout.read(256).decode(errors="replace").strip()
            client.close()
            return f"SUCCESS user={c['user']} banner={banner!r}"

        except paramiko.AuthenticationException:
            log.debug("SSH auth failed: %s@%s", c.get("user"), ip)
        except Exception as exc:
            log.debug("SSH error %s@%s: %s", c.get("user"), ip, exc)

    return "auth failed for all stored credentials"


def _probe_ssh_cli(ip: str, cfg: "Config", vault: "CredVault") -> str:
    creds = vault.get(ip, "ssh")
    if not creds:
        return "no credentials"
    for c in creds:
        if c.get("type") == "key_path":
            rc, out = _run([
                "ssh", "-q", "-o", "StrictHostKeyChecking=no",
                "-o", "ConnectTimeout=5",
                "-i", c["secret"],
                f"{c['user']}@{ip}", "uname -a"
            ], timeout=cfg.ssh_timeout + 2)
        elif subprocess.run(["which", "sshpass"], capture_output=True).returncode == 0:
            rc, out = _run([
                "sshpass", "-p", c["secret"],
                "ssh", "-q", "-o", "StrictHostKeyChecking=no",
                "-o", "ConnectTimeout=5",
                f"{c['user']}@{ip}", "uname -a"
            ], timeout=cfg.ssh_timeout + 2)
        else:
            continue
        if rc == 0:
            return f"SUCCESS user={c['user']} banner={out.strip()!r}"
    return "auth failed for all stored credentials"


# ── HTTP / HTTPS ──────────────────────────────────────────────────────────────

def probe_http(ip: str, cfg: "Config", vault: "CredVault") -> str:
    """Check HTTP/HTTPS reachability and test any stored API tokens."""
    results = []
    for scheme, port in [("https", 443), ("http", 80), ("http", 8080), ("https", 8443)]:
        if not _tcp_open(ip, port, timeout=1.5):
            continue
        url = f"{scheme}://{ip}:{port}/"
        try:
            import requests
            pats = vault.get(ip, "pat") + vault.get(ip, "http")
            headers = {}
            if pats:
                p = pats[0]
                headers["Authorization"] = f"Bearer {p['secret']}"
            resp = requests.get(url, headers=headers, timeout=cfg.http_timeout,
                                verify=False, allow_redirects=True)
            results.append(f"{scheme}:{port} → HTTP {resp.status_code} "
                           f"Server:{resp.headers.get('Server','?')}")
        except Exception as exc:
            results.append(f"{scheme}:{port} → error: {exc!s:.60}")
    return " | ".join(results) if results else "no http ports open"


# ── SNMP ──────────────────────────────────────────────────────────────────────

def probe_snmp(ip: str, cfg: "Config", vault: "CredVault") -> str:
    if not _tcp_open(ip, 161) and not subprocess.run(
            ["which", "snmpwalk"], capture_output=True).returncode == 0:
        return "snmp unavailable"

    communities = [c["secret"] for c in vault.get(ip, "snmp")] or cfg.snmp_communities
    for community in communities:
        rc, out = _run(
            ["snmpwalk", "-v2c", "-c", community, "-t", "2", "-r", "1",
             ip, "system"],
            timeout=10
        )
        if rc == 0 and out.strip():
            sys_desc = next((l for l in out.splitlines() if "sysDescr" in l), out[:120])
            return f"SUCCESS community={community!r} sysDescr={sys_desc.strip()!r}"
    return "no SNMP response with known communities"


# ── SMB ───────────────────────────────────────────────────────────────────────

def probe_smb(ip: str, cfg: "Config", vault: "CredVault") -> str:
    if not _tcp_open(ip, 445):
        return "port closed"
    if subprocess.run(["which", "smbclient"], capture_output=True).returncode != 0:
        return "smbclient not installed"
    # try anonymous first
    rc, out = _run(["smbclient", "-N", "-L", f"//{ip}/"], timeout=10)
    if rc == 0:
        return f"anonymous: {out[:120].strip()}"
    # try stored creds
    for c in vault.get(ip, "smb"):
        rc, out = _run(
            ["smbclient", "-L", f"//{ip}/", "-U",
             f"{c['user']}%{c['secret']}"],
            timeout=10
        )
        if rc == 0:
            return f"SUCCESS user={c['user']}: {out[:80].strip()}"
    return "no anonymous or authenticated SMB access"


# ── Accessor ──────────────────────────────────────────────────────────────────

class Accessor:
    def __init__(self, cfg: "Config", vault: "CredVault") -> None:
        self.cfg   = cfg
        self.vault = vault

    def assess(self, ip: str) -> dict:
        """Run all configured probes against ip.  Returns results dict."""
        log.info("Assessing %s …", ip)
        results: dict = {}
        open_ports: dict[int, str] = {}

        probes = self.cfg.access_probes

        if "portscan" in probes:
            log.info("  [%s] port scan", ip)
            open_ports = probe_portscan(ip, self.cfg)
            results["portscan"] = (
                ", ".join(f"{p}/{s}" for p, s in sorted(open_ports.items()))
                or "no open ports found"
            )

        if "ssh" in probes and (22 in open_ports or "ssh" in open_ports.values()):
            log.info("  [%s] SSH probe", ip)
            results["ssh"] = probe_ssh(ip, self.cfg, self.vault)

        if "http" in probes:
            log.info("  [%s] HTTP probe", ip)
            results["http"] = probe_http(ip, self.cfg, self.vault)

        if "snmp" in probes:
            log.info("  [%s] SNMP probe", ip)
            results["snmp"] = probe_snmp(ip, self.cfg, self.vault)

        if "smb" in probes and (445 in open_ports or 139 in open_ports):
            log.info("  [%s] SMB probe", ip)
            results["smb"] = probe_smb(ip, self.cfg, self.vault)

        return results
