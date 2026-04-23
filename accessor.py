"""netwatch/accessor.py — service assessment and credential testing for new hosts.

Probes: portscan → SSH → HTTP/HTTPS → SNMP → SMB
Results are summarised as short strings stored in HostRecord.access_results.
"""

from __future__ import annotations
import datetime
import json
import logging
import socket
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
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


# ── SSH state snapshot ────────────────────────────────────────────────────────

def _collect_ssh_snapshot(ip: str, user: str, client: "paramiko.SSHClient",
                          commands: list[str]) -> None:
    """Run ssh_state_commands over an open paramiko client and save output.

    Snapshots land in ~/.netwatch/snapshots/<ip>_<timestamp>.json.
    Intended as the hook point for future Collector integration.
    """
    from config import NETWATCH_DIR
    snapshot_dir = NETWATCH_DIR / "snapshots"
    snapshot_dir.mkdir(parents=True, exist_ok=True)

    results: dict[str, str] = {}
    for cmd in commands:
        try:
            _, stdout, stderr = client.exec_command(cmd, timeout=10)
            out = stdout.read(4096).decode(errors="replace").strip()
            err = stderr.read(512).decode(errors="replace").strip()
            results[cmd] = out if out else err
        except Exception as exc:
            results[cmd] = f"ERROR: {exc}"

    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = snapshot_dir / f"{ip}_{ts}.json"
    payload = {"ip": ip, "user": user, "collected_at": ts, "commands": results}
    path.write_text(json.dumps(payload, indent=2))
    log.info("  [%s] SSH state snapshot saved → %s", ip, path)


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
        timeout = getattr(cfg, "portscan_connect_timeout_seconds", 0.25)
        with ThreadPoolExecutor(max_workers=min(32, len(TOP_PORTS))) as pool:
            futures = {
                pool.submit(_tcp_open, ip, port, timeout): port
                for port in TOP_PORTS
            }
            for future in as_completed(futures):
                port = futures[future]
                try:
                    if future.result():
                        open_ports[port] = "open"
                except Exception:
                    continue

    return open_ports


def probe_ssh(ip: str, cfg: "Config", vault: "CredVault") -> tuple[str, str]:
    """Try stored SSH credentials.  Returns (ssh summary, privilege summary)."""
    if not _tcp_open(ip, 22):
        return "port closed", "not checked"

    try:
        import paramiko
    except ImportError:
        # fallback: try with sshpass + ssh CLI
        return _probe_ssh_cli(ip, cfg, vault)

    creds = vault.get(ip, "ssh")
    if not creds:
        return "no credentials", "not checked"

    first_success = ""
    best_privilege = ""
    for c in creds:
        client = None
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

            # Mutual SSH key provisioning (idempotent — safe to re-run)
            alias = ""
            try:
                from keyprovisioner import KeyProvisioner
                prov = KeyProvisioner().provision(ip, c["user"], client)
                if prov.get("our_key_installed"):
                    alias = prov["alias"]
            except Exception as exc:
                log.debug("Key provisioning skipped for %s: %s", ip, exc)

            if cfg.ssh_state_commands:
                try:
                    _collect_ssh_snapshot(ip, c["user"], client, cfg.ssh_state_commands)
                except Exception as exc:
                    log.debug("SSH state snapshot failed for %s: %s", ip, exc)

            privilege = _probe_privilege_paramiko(ip, vault, client, c)
            _remember_successful_ssh_cred(ip, vault, c)
            suffix = f" alias={alias}" if alias else ""
            summary = f"SUCCESS user={c['user']} banner={banner!r}{suffix}"
            if not first_success:
                first_success = summary
                best_privilege = privilege
            elif _privilege_rank(privilege) > _privilege_rank(best_privilege):
                best_privilege = privilege

            if _privilege_rank(privilege) >= 2:
                return summary, privilege

        except paramiko.AuthenticationException:
            log.info("  [%s] SSH auth failed: user=%s", ip, c.get("user"))
        except Exception as exc:
            log.info("  [%s] SSH error: user=%s  %s", ip, c.get("user"), exc)
        finally:
            if client is not None:
                client.close()

    if first_success:
        return first_success, best_privilege or "no sudo/root access confirmed"
    return "auth failed for all stored credentials", "not checked"


def _privilege_rank(result: str) -> int:
    if result.startswith("root access confirmed"):
        return 3
    if result.startswith("sudo "):
        return 2
    if result.startswith("no sudo/root access confirmed"):
        return 1
    return 0


def _probe_ssh_cli(ip: str, cfg: "Config", vault: "CredVault") -> tuple[str, str]:
    creds = vault.get(ip, "ssh")
    if not creds:
        return "no credentials", "not checked"
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
            _remember_successful_ssh_cred(ip, vault, c)
            return f"SUCCESS user={c['user']} banner={out.strip()!r}", "not checked (ssh CLI fallback)"
    return "auth failed for all stored credentials", "not checked"


def _probe_privilege_paramiko(ip: str, vault: "CredVault", client, cred: dict) -> str:
    """Check root/passwordless sudo/same-password sudo without logging secrets."""
    user = cred.get("user", "")
    try:
        _, stdout, _ = client.exec_command("id -u", timeout=5)
        uid = stdout.read(64).decode(errors="replace").strip()
        if uid == "0" or user == "root":
            _remember_admin_cred(ip, vault, "root", cred)
            return f"root access confirmed user={user}"
    except Exception as exc:
        return f"privilege check failed: {exc}"

    try:
        _, stdout, _ = client.exec_command(
            "sudo -n true >/dev/null 2>&1 && echo passwordless || echo no",
            timeout=5,
        )
        result = stdout.read(64).decode(errors="replace").strip()
        if result == "passwordless":
            _remember_admin_cred(ip, vault, "sudo", cred)
            return f"sudo passwordless confirmed user={user}"
    except Exception:
        pass

    if cred.get("type") == "password" and cred.get("secret"):
        try:
            stdin, stdout, _ = client.exec_command("sudo -S -p '' true", timeout=5)
            stdin.write(cred["secret"] + "\n")
            stdin.flush()
            rc = stdout.channel.recv_exit_status()
            if rc == 0:
                _remember_admin_cred(ip, vault, "sudo", cred)
                return f"sudo with stored password confirmed user={user}"
        except Exception:
            pass

    su_result = _probe_su_root(ip, vault, client, cred)
    if su_result:
        return su_result

    return f"no sudo/root access confirmed user={user}"


def _probe_su_root(ip: str, vault: "CredVault", client, ssh_cred: dict) -> str:
    """Try su - with stored root credentials over an interactive shell."""
    for root_cred in _root_password_candidates(ip, vault):
        password = root_cred.get("secret")
        if not password:
            continue
        try:
            shell = client.invoke_shell(width=120, height=40)
            shell.settimeout(5)
            _drain_shell(shell)
            shell.send("su -\n")
            _read_until_shell(shell, ("Password:", "password:"), timeout=5)
            shell.send(password + "\n")
            output = _read_until_shell(shell, ("#", "su: Authentication failure", "Authentication failure"), timeout=8)
            if "Authentication failure" in output:
                continue
            shell.send("id -u\n")
            id_output = _read_until_shell(shell, ("0", "#"), timeout=5)
            if re.search(r"(^|\D)0(\D|$)", id_output):
                su_cred = dict(root_cred)
                su_cred["via_user"] = ssh_cred.get("user", "")
                vault.set(ip, "su", su_cred)
                log.info("  [%s] Stored confirmed su credential in vault: via=%s user=%s type=%s",
                         ip, ssh_cred.get("user"), root_cred.get("user"), root_cred.get("type", "?"))
                shell.close()
                return f"su root confirmed via user={ssh_cred.get('user')}"
            shell.close()
        except Exception as exc:
            log.debug("  [%s] su root check failed via user=%s: %s", ip, ssh_cred.get("user"), exc)
    return ""


def _root_password_candidates(ip: str, vault: "CredVault") -> list[dict]:
    candidates = []
    for service in ("root", "su", "ssh"):
        for cred in vault.get(ip, service):
            if cred.get("type") == "password" and cred.get("user") == "root":
                key = (cred.get("user"), cred.get("secret"), cred.get("type"))
                if key not in {(c.get("user"), c.get("secret"), c.get("type")) for c in candidates}:
                    candidates.append(cred)
    return candidates


def _drain_shell(shell) -> str:
    data = ""
    while shell.recv_ready():
        data += shell.recv(4096).decode(errors="replace")
    return data


def _read_until_shell(shell, needles: tuple[str, ...], timeout: float) -> str:
    import time
    deadline = time.time() + timeout
    data = ""
    while time.time() < deadline:
        if shell.recv_ready():
            data += shell.recv(4096).decode(errors="replace")
            if any(needle in data for needle in needles):
                return data
        time.sleep(0.1)
    return data


def _remember_admin_cred(ip: str, vault: "CredVault", service: str, cred: dict) -> None:
    """Persist the credential that proved root/sudo access under an admin scope."""
    try:
        admin_cred = dict(cred)
        vault.set(ip, service, admin_cred)
        log.info("  [%s] Stored confirmed %s credential in vault: user=%s type=%s",
                 ip, service, cred.get("user"), cred.get("type", "?"))
    except Exception as exc:
        log.warning("  [%s] Could not persist %s credential: %s", ip, service, exc)


def _remember_successful_ssh_cred(ip: str, vault: "CredVault", cred: dict) -> None:
    """Persist a working fallback SSH credential under the host-specific scope."""
    try:
        host_creds = vault._data.get(ip, {}).get("ssh", [])
        for existing in host_creds:
            if (
                existing.get("user") == cred.get("user")
                and existing.get("secret") == cred.get("secret")
                and existing.get("type") == cred.get("type")
            ):
                return
        vault.set(ip, "ssh", dict(cred))
        log.info("  [%s] Stored successful SSH credential in host-specific vault scope: user=%s type=%s",
                 ip, cred.get("user"), cred.get("type", "?"))
    except Exception as exc:
        log.warning("  [%s] Could not persist successful SSH credential: %s", ip, exc)


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
        log.info("Assessing %s — probes: %s", ip, ", ".join(self.cfg.access_probes))
        results: dict = {}
        open_ports: dict[int, str] = {}

        probes = self.cfg.access_probes

        if "portscan" in probes:
            log.info("  [%s] port scan", ip)
            open_ports = probe_portscan(ip, self.cfg)
            # Fallback: if nmap found nothing, verify critical ports via direct TCP
            # connect so SSH/HTTP probes still fire without consulting local SSH config.
            if not open_ports:
                for port, banner in [(22, "ssh"), (80, "http"), (443, "https"),
                                     (8080, "http-alt"), (445, "microsoft-ds")]:
                    if _tcp_open(ip, port, timeout=2.0):
                        open_ports[port] = f"{banner} (tcp-verified)"
                        log.info("  [%s] nmap missed port %d — confirmed via direct TCP connect",
                                 ip, port)
            results["portscan"] = (
                ", ".join(f"{p}/{s}" for p, s in sorted(open_ports.items()))
                or "no open ports found"
            )

        if "ssh" in probes and (22 in open_ports or "ssh" in open_ports.values()):
            log.info("  [%s] SSH probe", ip)
            ssh_result, privilege_result = probe_ssh(ip, self.cfg, self.vault)
            results["ssh"] = ssh_result
            results["privilege"] = privilege_result

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
