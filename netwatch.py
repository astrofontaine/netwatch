#!/usr/bin/env python3
"""netwatch — periodic LAN discovery + access assessment.

Usage:
  python3 netwatch.py --once                # one discovery+assess cycle
  python3 netwatch.py --daemon              # loop forever (--interval seconds)
  python3 netwatch.py --add-cred           # interactive credential entry
  python3 netwatch.py --list-hosts         # show known hosts
  python3 netwatch.py --list-creds         # show vault contents
  python3 netwatch.py --assess <IP>        # force re-assess a single host
  python3 netwatch.py --subnet 10.0.0.0/24 # override subnet

All options can be combined.  Sudo password is prompted once and held in memory.
"""

from __future__ import annotations
import argparse
import getpass
import logging
import os
import re
import socket
import sys
import time
from pathlib import Path

# allow running from any cwd
sys.path.insert(0, str(Path(__file__).parent))

from config import Config, NETWATCH_DIR
from creds import CredVault, MissingDependencyError
from discover import Discoverer, get_local_services, get_mac, get_hostnames
from accessor import Accessor
from state import HostState

# ── logging setup ─────────────────────────────────────────────────────────────

LOG_FILE = NETWATCH_DIR / "logs" / "netwatch.log"


def setup_logging(level: str) -> None:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    fmt = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
    datefmt = "%Y-%m-%dT%H:%M:%S"
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format=fmt, datefmt=datefmt,
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(LOG_FILE),
        ],
    )
    # suppress verbose libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("paramiko").setLevel(logging.WARNING)


log = logging.getLogger("netwatch")


# ── sudo password ─────────────────────────────────────────────────────────────

def get_sudo_pass(cfg: Config) -> str:
    """Prompt for sudo password once; verify it works."""
    if not cfg.sudo_required:
        return ""
    # try passwordless first
    import subprocess
    if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0:
        log.info("Passwordless sudo available.")
        return ""
    pw = getpass.getpass("sudo password (for privileged discovery): ")
    test = subprocess.run(
        ["sudo", "-S", "-p", "", "true"],
        input=pw + "\n", capture_output=True, text=True,
    )
    if test.returncode != 0:
        log.warning("sudo password incorrect — privileged techniques will be skipped.")
        return ""
    return pw


# ── core cycle ────────────────────────────────────────────────────────────────

def run_cycle(
    cfg: Config,
    vault: CredVault,
    state: HostState,
    accessor: Accessor,
    sudo_pass: str,
) -> None:
    subnets = cfg.target_subnets()
    log.info("─── Discovery cycle starting — subnets %s", ", ".join(subnets))

    os.environ["NETWATCH_PING_TIMEOUT"] = str(cfg.ping_timeout_seconds)
    os.environ["NETWATCH_TCP_SWEEP_TIMEOUT"] = str(cfg.tcp_sweep_timeout_seconds)
    discoverer = Discoverer(cfg.subnet, cfg.discovery_techniques, sudo_pass, cfg.extra_subnets)
    live_ips   = discoverer.discover()
    log.info("Discovery complete: %d live host(s) found.", len(live_ips))
    if cfg.remember_successful_subnets(live_ips):
        cfg.save()
        log.info("[config] Updated successful subnet history: %s", ", ".join(cfg.successful_subnets))

    new_hosts, gone_hosts = state.update(live_ips)

    if gone_hosts:
        log.info("Hosts no longer visible: %s", ", ".join(sorted(gone_hosts)))

    # Refresh MACs (fast, local ARP) for all live hosts
    for ip in live_ips:
        mac = get_mac(ip)
        if mac:
            state.update_record(ip, mac_address=mac)

    # Resolve hostnames and local protocol signals in parallel.
    _enrich_identity(state, live_ips)

    if new_hosts:
        log.info("NEW host(s): %s — starting assessment.", ", ".join(sorted(new_hosts)))
        for ip in sorted(new_hosts):
            results = accessor.assess(ip)
            open_ports_str = results.get("portscan", "")
            open_ports = []
            if open_ports_str and open_ports_str != "no open ports found":
                open_ports = [int(m) for m in re.findall(r'(\d+)/', open_ports_str)]
            # Extract SSH alias if key provisioning ran
            ssh_alias, ssh_provisioned = _parse_ssh_alias(results.get("ssh", ""))
            state.update_record(
                ip,
                open_ports=open_ports,
                services={},
                access_results=results,
                assessed=True,
                ssh_alias=ssh_alias,
                ssh_provisioned=ssh_provisioned,
            )
            _log_assessment(ip, results)
    else:
        log.info("No new hosts this cycle.")

    state.save()
    log.info("─── Cycle complete.")


def _parse_ssh_alias(ssh_result: str) -> tuple[str, bool]:
    """Extract alias=<value> from an SSH probe result string."""
    m = re.search(r'\balias=(\S+)', ssh_result)
    if m:
        return m.group(1), True
    return "", False


def _log_assessment(ip: str, results: dict) -> None:
    log.info("  Assessment for %s:", ip)
    for probe, result in results.items():
        log.info("    %-10s %s", probe + ":", result)


# ── display helpers ───────────────────────────────────────────────────────────

# Verbose negatives that carry zero information — compress to "—" in long view.
_EMPTY_RESULTS = {
    "no open ports found",
    "no http ports open",
    "no snmp response with known communities",
    "no anonymous or authenticated smb access",
    "snmp unavailable",
    "smbclient not installed",
}


def _fmt_probe(result: str) -> str:
    """Compress known empty-result strings to '—'; leave informative ones alone."""
    return "—" if result.lower() in _EMPTY_RESULTS else result


def _probe_hits(access_results: dict) -> str:
    """Return space-separated names of probes with positive (non-empty) results."""
    hits = [svc for svc, res in access_results.items()
            if res.lower() not in _EMPTY_RESULTS
            and not res.lower().startswith("port closed")
            and not res.lower().startswith("no credentials")]
    return " ".join(hits) if hits else "—"


def _short_ts(iso: str) -> str:
    """Trim ISO-8601 timestamp to 'YYYY-MM-DD HH:MM'."""
    return iso[:16].replace("T", " ")


# ── CLI commands ──────────────────────────────────────────────────────────────

def _enrich_identity(state: HostState, ips: set[str]) -> None:
    """Resolve hostnames and local protocol observations for a set of IPs."""
    import threading
    import time
    lock = threading.Lock()
    results: dict[str, list[str]] = {}
    local_services: dict[str, list[str]] = {}

    def resolve(ip: str) -> None:
        names = get_hostnames(ip)
        services = get_local_services(ip)
        with lock:
            if names:
                results[ip] = names
            if services:
                local_services[ip] = services

    threads = [threading.Thread(target=resolve, args=(ip,), daemon=True) for ip in ips]
    for t in threads:
        t.start()
    deadline = time.time() + 10
    for t in threads:
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        t.join(timeout=remaining)

    for ip, names in results.items():
        rec = state.get(ip)
        if rec and sorted(rec.hostnames) != names:
            state.update_record(ip, hostnames=names)
    for ip, services in local_services.items():
        rec = state.get(ip)
        if rec and sorted(rec.local_services) != services:
            state.update_record(ip, local_services=services)
    if results:
        log.info("[names] Resolved hostname(s) for: %s",
                 ", ".join(f"{ip}={v[0]}" for ip, v in sorted(results.items())))
    if local_services:
        log.info("[local] Local protocol detail for: %s",
                 ", ".join(f"{ip}={len(v)} signal(s)" for ip, v in sorted(local_services.items())))


def _refresh_macs(state: HostState) -> None:
    """Fast ARP-only MAC refresh for display commands.

    Hostname resolution is intentionally excluded here — it requires external
    processes with multi-second timeouts per host.  That runs in run_cycle()
    instead, where it can be parallelised without blocking the display path.
    """
    mac_found = 0
    for r in state.all_hosts():
        if not r.mac_address:
            mac = get_mac(r.ip)
            if mac:
                state.update_record(r.ip, mac_address=mac)
                mac_found += 1
    if mac_found:
        log.info("[macs] Enriched %d host(s) with MAC addresses from ARP", mac_found)


def cmd_list_hosts(state: HostState) -> None:
    """One line per host — quick overview."""
    hosts = state.all_hosts()
    if not hosts:
        print("No hosts in state yet.")
        return
    hdr = f"  {'IP':<17} {'Alias':<16} {'Ports':<16} {'Last heard':<17} Hits"
    print(f"\n{hdr}")
    print("  " + "─" * (len(hdr) - 2))
    for r in hosts:
        alias  = r.ssh_alias or "—"
        ports  = ",".join(str(p) for p in sorted(r.open_ports)[:6]) or "—"
        ts     = _short_ts(r.last_heard_from)
        hits   = _probe_hits(r.access_results) if r.assessed else "not assessed"
        print(f"  {r.ip:<17} {alias:<16} {ports:<16} {ts:<17} {hits}")
    print()


def cmd_list_hosts_long(state: HostState) -> None:
    """Detailed host blocks — one card per host."""
    hosts = state.all_hosts()
    if not hosts:
        print("No hosts in state yet.")
        return

    W = 58  # card width

    for r in hosts:
        alias = r.ssh_alias or "—"
        ports = ", ".join(str(p) for p in sorted(r.open_ports)) or "—"
        ts    = _short_ts(r.last_heard_from)
        mac   = r.mac_address or "—"

        # ── card header ──────────────────────────────────────────
        print(f"\n  ── {r.ip} {'─' * (W - len(r.ip) - 4)}")
        print(f"  {'alias:':<10} {alias:<22}  {'last heard:':<10} {ts}")
        print(f"  {'ports:':<10} {ports:<22}  {'mac:':<10} {mac}")
        if r.hostnames:
            print(f"  {'names:':<10} {', '.join(r.hostnames)}")
        if r.local_services:
            print(f"  {'local:':<10} {' | '.join(r.local_services[:3])}")
        if not r.assessed:
            print(f"  (not yet assessed)")
            continue

        # ── probe results ────────────────────────────────────────
        print(f"  {'─' * W}")
        if r.access_results:
            positives = [(s, res) for s, res in r.access_results.items()
                         if _fmt_probe(res) != "—"]
            negatives = [s for s, res in r.access_results.items()
                         if _fmt_probe(res) == "—"]
            for svc, res in positives:
                print(f"  {svc + ':':<12} {res}")
            if negatives:
                print(f"  {'no data:':<12} {', '.join(negatives)}")



def cmd_force_assess(ip: str, cfg: Config, vault: CredVault, state: HostState) -> None:
    accessor = Accessor(cfg, vault)
    results  = accessor.assess(ip)
    ssh_alias, ssh_provisioned = _parse_ssh_alias(results.get("ssh", ""))
    kwargs: dict = {"access_results": results, "assessed": True}
    if ssh_alias:
        kwargs["ssh_alias"] = ssh_alias
        kwargs["ssh_provisioned"] = ssh_provisioned
    mac = get_mac(ip)
    if mac:
        kwargs["mac_address"] = mac
    state.update_record(ip, **kwargs)
    state.save()
    _log_assessment(ip, results)


def cmd_provision_ssh(ip: str, cfg: Config, vault: CredVault, state: HostState) -> None:
    """Force mutual SSH key exchange with ip, regardless of prior state."""
    try:
        import paramiko
    except ImportError:
        print("paramiko not available — install python3-paramiko")
        return

    from keyprovisioner import KeyProvisioner

    creds = vault.get(ip, "ssh")
    if not creds:
        print(f"No SSH credentials stored for {ip}. Use --add-cred first.")
        return

    for c in creds:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            if c.get("type") == "key_path":
                client.connect(ip, username=c["user"], key_filename=c["secret"],
                               timeout=cfg.ssh_timeout)
            else:
                client.connect(ip, username=c["user"], password=c["secret"],
                               timeout=cfg.ssh_timeout, allow_agent=False,
                               look_for_keys=False)
        except Exception as exc:
            print(f"  SSH connect failed ({c['user']}@{ip}): {exc}")
            continue

        # Prompt for alias before provisioning
        default_alias = ip
        try:
            raw = input(f"  SSH alias for {ip} [{default_alias}]: ").strip()
        except EOFError:
            raw = ""
        alias = raw if raw else default_alias

        print(f"  Connected as {c['user']}@{ip} — running key provisioner…")
        result = KeyProvisioner().provision(ip, c["user"], client, alias=alias)
        client.close()

        print(f"  our key installed  : {result['our_key_installed']}")
        print(f"  their key installed: {result['their_key_installed']}")
        print(f"  our config updated : {result['our_config_updated']}")
        print(f"  their config updated: {result['their_config_updated']}")
        print(f"  passwordless test  : {result['test_passed']}")
        if result.get("error"):
            print(f"  error              : {result['error']}")

        if result["our_key_installed"]:
            state.update_record(
                ip,
                ssh_alias=result["alias"],
                ssh_provisioned=result["test_passed"],
            )
            state.save()

        alias = result["alias"]
        if result["test_passed"]:
            # Live verification — show the user it actually works right now
            import subprocess as _sp
            check = _sp.run(
                ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
                 alias, "echo netwatch-ok && whoami"],
                capture_output=True, text=True, timeout=12,
            )
            verified = check.returncode == 0 and "netwatch-ok" in check.stdout
            whoami = check.stdout.replace("netwatch-ok", "").strip()
            if verified:
                print(f"\n  Live check PASSED — logged in as: {whoami or '(unknown)'}")
            else:
                print(f"\n  Live check FAILED: {(check.stdout + check.stderr).strip()[:120]}")
            print(f"\n{'─'*50}")
            print(f"  Use this alias — NOT the bare IP:")
            print(f"    ssh {alias}")
            print(f"    scp {alias}:/path/to/file .")
            print(f"    ssh {alias} 'journalctl -n 50'")
            print(f"{'─'*50}")
        elif result["our_key_installed"]:
            print(f"\n  Key installed but passwordless test failed.")
            print(f"  Config block written — try manually: ssh {alias}")
        else:
            print(f"\n  Provisioning incomplete — check error above.")
        return

    print(f"All SSH credentials failed for {ip}.")


def cmd_show_host(ip: str, state: HostState) -> None:
    """Print full detail for a single host."""
    rec = state.get(ip)
    if not rec:
        print(f"Host {ip} not in state. Run --assess {ip} to add it.")
        return

    print(f"\n{'─'*60}")
    print(f"  Host         {rec.ip}")
    if rec.mac_address:
        print(f"  MAC          {rec.mac_address}")
    if rec.hostnames:
        print(f"  Hostnames    {', '.join(rec.hostnames)}")
    if rec.local_services:
        print(f"  Local proto  {' | '.join(rec.local_services)}")
    print(f"  First seen   {rec.first_seen}")
    print(f"  Last heard   {rec.last_heard_from}")
    print(f"  Assessed     {'yes' if rec.assessed else 'no'}")
    print(f"  Open ports   {', '.join(str(p) for p in sorted(rec.open_ports)) or '—'}")
    if rec.os_guess:
        print(f"  OS guess     {rec.os_guess}")
    print(f"  SSH alias    {rec.ssh_alias or '—'}")
    print(f"  SSH ready    {'yes — ssh ' + rec.ssh_alias if rec.ssh_provisioned else 'no'}")
    if rec.access_results:
        print(f"\n  Probe results:")
        for svc, res in rec.access_results.items():
            print(f"    {svc:<12} {res}")
    if rec.ssh_provisioned:
        print(f"\n  Quick access:")
        print(f"    ssh {rec.ssh_alias}")
        print(f"    scp {rec.ssh_alias}:/var/log/syslog .")
        print(f"    ssh {rec.ssh_alias} 'journalctl -n 50'")
    print()


# ── alias management ─────────────────────────────────────────────────────────

def cmd_set_alias(ip: str, alias: str, state: HostState) -> None:
    """Rename the SSH config block for ip and optionally add to /etc/hosts."""
    import subprocess as _sp

    ssh_cfg  = Path.home() / ".ssh" / "config"
    hosts_f  = Path("/etc/hosts")

    # ── 1. rewrite ~/.ssh/config block ───────────────────────────────────────
    if ssh_cfg.exists():
        text = ssh_cfg.read_text()
        # Find existing block for this IP (marker-delimited)
        marker_re = re.compile(
            rf'(# >>> netwatch: {re.escape(ip)}\n)'
            rf'Host \S+(\n(?:[ \t]+.*\n)*?)'
            rf'(# <<< netwatch: {re.escape(ip)}\n?)',
            re.MULTILINE,
        )
        if marker_re.search(text):
            new_text = marker_re.sub(
                rf'\g<1>Host {alias}\g<2>\g<3>', text
            )
            ssh_cfg.write_text(new_text)
            print(f"  ~/.ssh/config   updated: Host {alias}")
            log.info("[alias] %s  ssh_alias updated in ~/.ssh/config → %s", ip, alias)
        else:
            print(f"  ~/.ssh/config   no netwatch block for {ip} — run -p {ip} first to provision")
    else:
        print(f"  ~/.ssh/config   not found")

    # ── 2. update state ───────────────────────────────────────────────────────
    rec = state.get(ip)
    if rec:
        state.update_record(ip, ssh_alias=alias)
        state.save()
        print(f"  hosts.json      ssh_alias = {alias}")

    # ── 3. /etc/hosts (marker-delimited, needs sudo) ──────────────────────────
    # Build the entry we want
    names = [alias]
    if rec and rec.hostnames:
        for h in rec.hostnames:
            if h.lower() != alias.lower():
                names.append(h)
    entry_line = f"{ip:<16} {' '.join(names)}"
    block = (
        f"# >>> netwatch: {ip}\n"
        f"{entry_line}\n"
        f"# <<< netwatch: {ip}\n"
    )

    try:
        hosts_text = hosts_f.read_text()
    except PermissionError:
        hosts_text = None

    hosts_re = re.compile(
        rf'^# >>> netwatch: {re.escape(ip)}\n.*?^# <<< netwatch: {re.escape(ip)}\n?',
        re.MULTILINE | re.DOTALL,
    )

    if hosts_text is not None:
        if hosts_re.search(hosts_text):
            new_hosts = hosts_re.sub(block, hosts_text)
        else:
            sep = "\n" if hosts_text and not hosts_text.endswith("\n\n") else ""
            new_hosts = hosts_text.rstrip("\n") + "\n" + sep + block

        if new_hosts != hosts_text:
            # Try direct write first (works if we own the file or have write perm)
            try:
                hosts_f.write_text(new_hosts)
                print(f"  /etc/hosts      {entry_line}")
                log.info("[alias] %s  /etc/hosts updated: %s", ip, entry_line)
            except PermissionError:
                # Fall back to sudo tee — let sudo use the real terminal for its prompt
                result = _sp.run(
                    ["sudo", "tee", str(hosts_f)],
                    input=new_hosts, text=True,
                    stdout=_sp.DEVNULL,   # suppress tee's echo to stdout
                )
                if result.returncode == 0:
                    print(f"  /etc/hosts      {entry_line}  (via sudo)")
                    log.info("[alias] %s  /etc/hosts updated via sudo: %s", ip, entry_line)
                else:
                    print(f"  /etc/hosts      sudo failed — add manually:")
                    print(f"    echo '{entry_line}' | sudo tee -a /etc/hosts")
                    log.warning("[alias] %s  /etc/hosts sudo tee failed", ip)
        else:
            print(f"  /etc/hosts      already up to date")
    else:
        print(f"  /etc/hosts      permission denied — add manually:")
        print(f"    echo '{entry_line}' | sudo tee -a /etc/hosts")

    # ── 4. push reverse mapping to remote ────────────────────────────────────
    # Only possible if we can actually SSH there right now
    our_ip       = _our_source_ip(ip)
    our_hostname = socket.gethostname()                       # "debian-claude"
    our_short    = our_hostname.split("-")[-1] \
                   if "-" in our_hostname else our_hostname   # "claude"
    our_names    = " ".join(dict.fromkeys([our_short, our_hostname]))  # deduped

    if our_ip and our_ip != "127.0.0.1":
        ok_conn, _ = _ssh_run(alias, "echo ok", timeout=5)
        if ok_conn:
            # /etc/hosts on remote
            check_ok, check_out = _ssh_run(
                alias, f"grep -q '{our_ip}' /etc/hosts && echo exists || echo missing")
            if "exists" in check_out:
                print(f"  remote /etc/hosts   {our_ip} already present")
                log.info("[alias] remote /etc/hosts already has %s", our_ip)
            else:
                # Try passwordless sudo first (-n = non-interactive)
                entry = f"{our_ip:<16} {our_names}"
                sudo_ok, sudo_out = _ssh_run(
                    alias,
                    f"printf '# >>> netwatch: {our_ip}\\n{entry}\\n# <<< netwatch: {our_ip}\\n'"
                    f" | sudo -n tee -a /etc/hosts > /dev/null && echo ok || echo fail")
                if "ok" in sudo_out:
                    print(f"  remote /etc/hosts   {entry}")
                    log.info("[alias] remote /etc/hosts updated: %s", entry)
                else:
                    print(f"  remote /etc/hosts   sudo required — run on {alias}:")
                    print(f"    echo '{entry}' | sudo tee -a /etc/hosts")
                    log.warning("[alias] remote /etc/hosts needs manual update for %s", our_ip)

            # ~/.ssh/config on remote — replace entire netwatch block with correct alias
            our_user = _run_local(["whoami"]) or "longshot"
            new_block = (
                f"# >>> netwatch: {our_ip}\n"
                f"Host {our_short}\n"
                f"    HostName {our_ip}\n"
                f"    User {our_user}\n"
                f"    StrictHostKeyChecking accept-new\n"
                f"# <<< netwatch: {our_ip}\n"
            )
            # Encode the block as base64 so the script is self-contained with no quoting issues
            import base64 as _b64
            block_b64 = _b64.b64encode(new_block.encode()).decode()
            script2 = (
                "import re, base64\n"
                "from pathlib import Path\n"
                f"ip = {our_ip!r}\n"
                f"block = base64.b64decode({block_b64!r}).decode()\n"
                "c = Path.home() / '.ssh' / 'config'\n"
                "c.touch(mode=0o600)\n"
                "t = c.read_text()\n"
                "pat = re.compile(\n"
                "    r'# >>> netwatch: ' + re.escape(ip) + r'\\n'\n"
                "    r'.*?'\n"
                "    r'# <<< netwatch: ' + re.escape(ip) + r'\\n?',\n"
                "    re.DOTALL)\n"
                "cleaned = pat.sub('', t)\n"
                "result = cleaned.rstrip('\\n') + '\\n' + block\n"
                "c.write_text(result)\n"
                "print('ok')\n"
            )
            cfg_ok, cfg_out = _ssh_run_script(alias, script2)
            if "ok" in cfg_out:
                print(f"  remote ~/.ssh/config  Host {our_short} → {our_ip}")
                log.info("[alias] remote ssh config updated: Host %s for %s", our_short, our_ip)
            else:
                print(f"  remote ~/.ssh/config  could not update: {cfg_out[:60]}")
        else:
            print(f"  remote updates      skipped — cannot reach {alias} right now")
            log.warning("[alias] could not reach %s to push reverse mapping", alias)

    print(f"\n  Local:  ssh {alias}   scp {alias}:/path/to/file .")
    print(f"  Remote: ssh {our_short}   scp {our_short}:/path/to/file .")

    # ── 5. propagate all known aliases to every reachable host ───────────────
    print()
    cmd_sync_aliases(state, quiet=False)


def cmd_sync_aliases(state: "HostState", quiet: bool = False) -> None:
    """Push all netwatch SSH config blocks to every reachable aliased host.

    Each reachable host ends up with SSH alias entries for every OTHER known
    host, so `ssh proxmox` works from macbook without hopping through claude.
    """
    import base64 as _b64

    our_ip       = _our_source_ip("8.8.8.8") or ""
    our_hostname = socket.gethostname()
    our_short    = our_hostname.split("-")[-1] if "-" in our_hostname else our_hostname
    our_user     = _run_local(["whoami"]) or "longshot"

    # Build the full set of SSH blocks: all known hosts with an alias
    # (ip → (alias, ssh_user))
    aliased: dict[str, tuple[str, str]] = {}
    for rec in state.all_hosts():
        if rec.ssh_alias:
            ssh_user = _parse_ssh_user(rec) or "admin"
            aliased[rec.ip] = (rec.ssh_alias, ssh_user)

    # Include ourselves so remote hosts get a block back to this machine
    if our_ip and our_short:
        aliased[our_ip] = (our_short, our_user)

    if not aliased:
        if not quiet:
            print("  No aliased hosts in state yet — run -A <IP> <NAME> first.")
        return

    # Determine which remote hosts we can reach (has alias + not us)
    reachable = {
        ip: (alias, user)
        for ip, (alias, user) in aliased.items()
        if ip != our_ip
    }

    if not reachable:
        if not quiet:
            print("  No remote aliased hosts to sync to.")
        return

    pushed = 0
    failed = 0
    for target_ip, (target_alias, _) in sorted(reachable.items()):
        # Build the blocks this target should receive: everyone except itself
        blocks_for_target = ""
        for src_ip, (src_alias, src_user) in sorted(aliased.items()):
            if src_ip == target_ip:
                continue
            blocks_for_target += (
                f"# >>> netwatch: {src_ip}\n"
                f"Host {src_alias}\n"
                f"    HostName {src_ip}\n"
                f"    User {src_user}\n"
                f"    StrictHostKeyChecking accept-new\n"
                f"# <<< netwatch: {src_ip}\n"
            )

        if not blocks_for_target:
            continue

        block_b64 = _b64.b64encode(blocks_for_target.encode()).decode()
        # Build list of IPs whose blocks we're managing, so old removed hosts
        # get cleaned up too
        managed_ips = [ip for ip in aliased if ip != target_ip]

        script = (
            "import re, base64\n"
            "from pathlib import Path\n"
            f"managed = {managed_ips!r}\n"
            f"new_blocks = base64.b64decode({block_b64!r}).decode()\n"
            "c = Path.home() / '.ssh' / 'config'\n"
            "c.touch(mode=0o600)\n"
            "t = c.read_text()\n"
            "# Remove all managed netwatch blocks\n"
            "for ip in managed:\n"
            "    t = re.sub(\n"
            "        r'# >>> netwatch: ' + re.escape(ip) + r'\\n'\n"
            "        r'.*?'\n"
            "        r'# <<< netwatch: ' + re.escape(ip) + r'\\n?',\n"
            "        '', t, flags=re.DOTALL)\n"
            "result = t.rstrip('\\n') + '\\n' + new_blocks\n"
            "c.write_text(result)\n"
            "print('ok')\n"
        )

        ok, out = _ssh_run_script(target_alias, script)
        if ok and "ok" in out:
            n = len(managed_ips)
            if not quiet:
                print(f"  {target_alias:<16}  synced {n} alias(es)")
            log.info("[sync] %s (%s): pushed %d SSH alias blocks", target_alias, target_ip, n)
            pushed += 1
        else:
            if not quiet:
                print(f"  {target_alias:<16}  unreachable or error: {out[:60]}")
            log.warning("[sync] %s (%s): sync failed: %s", target_alias, target_ip, out[:80])
            failed += 1

    if not quiet:
        print(f"\n  Sync complete — {pushed} host(s) updated, {failed} skipped.")


# ── SSH status helpers ────────────────────────────────────────────────────────

def _parse_ssh_user(rec: "HostRecord") -> str:
    """Extract the SSH username from a host's access_results, if available."""
    ssh_result = rec.access_results.get("ssh", "")
    m = re.search(r'user=(\S+)', ssh_result)
    return m.group(1) if m else ""


def _run_local(cmd: list[str], timeout: int = 5) -> str:
    """Run a local command, return stdout stripped. Empty string on error."""
    import subprocess as _sp
    try:
        r = _sp.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ""


def _ssh_run_script(alias: str, script: str, timeout: int = 10) -> tuple[bool, str]:
    """Run a Python script on alias by piping it to python3 via stdin."""
    import subprocess as _sp
    try:
        r = _sp.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
             "-o", "StrictHostKeyChecking=accept-new", alias, "python3"],
            input=script, capture_output=True, text=True, timeout=timeout,
        )
        out = (r.stdout + r.stderr).strip()
        return r.returncode == 0, out
    except Exception as e:
        return False, str(e)


def _ssh_run(alias: str, remote_cmd: str, timeout: int = 8) -> tuple[bool, str]:
    """Run a command on alias via BatchMode SSH. Returns (success, stdout+stderr)."""
    import subprocess as _sp
    r = _sp.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
         "-o", "StrictHostKeyChecking=accept-new", alias, remote_cmd],
        capture_output=True, text=True, timeout=timeout,
    )
    return r.returncode == 0, (r.stdout + r.stderr).strip()


def _check_local_ssh_config(ip: str) -> str:
    """Return the Host alias from the netwatch block for ip, or ''."""
    cfg = Path.home() / ".ssh" / "config"
    if not cfg.exists():
        return ""
    m = re.search(rf'# >>> netwatch: {re.escape(ip)}\nHost (\S+)', cfg.read_text())
    return m.group(1) if m else ""


def _check_known_hosts(ip: str) -> bool:
    kh = Path.home() / ".ssh" / "known_hosts"
    return kh.exists() and ip in kh.read_text()


def _our_pubkey() -> str:
    pub = Path.home() / ".ssh" / "netwatch_id_ed25519.pub"
    return pub.read_text().strip() if pub.exists() else ""


def _our_source_ip(remote_ip: str) -> str:
    import subprocess as _sp
    r = _sp.run(["ip", "route", "get", remote_ip], capture_output=True, text=True)
    m = re.search(r'\bsrc\s+(\S+)', r.stdout)
    return m.group(1) if m else ""


def _row(ok, label: str, detail: str) -> None:
    sym = "✓" if ok is True else ("✗" if ok is False else "?")
    print(f"    {sym}  {label:<16} {detail}")


def cmd_ssh_status(ip: str, state: HostState) -> None:
    """Live SSH connectivity verification — outbound and inbound."""
    import subprocess as _sp
    import time

    rec   = state.get(ip)
    alias = (rec.ssh_alias if rec and rec.ssh_alias else ip)
    our_ip = _our_source_ip(ip)

    log.info("[ssh-status] Checking %s (alias=%s our_ip=%s)", ip, alias, our_ip)

    W = 58
    print(f"\n  ── SSH status: {ip} {'─' * (W - len(ip) - 14)}")
    print(f"  alias: {alias}   our ip: {our_ip}")

    # ── outbound: this machine → remote ──────────────────────
    print(f"\n  outbound  (this machine → {ip})")
    print(f"  {'─' * W}")

    # 1. passwordless connect
    t0 = time.time()
    ok_conn, out = _ssh_run(alias, "echo netwatch-ok")
    ok_conn = ok_conn and "netwatch-ok" in out
    elapsed = time.time() - t0
    _row(ok_conn, "connect",
         f"passwordless ({elapsed:.1f}s)" if ok_conn else out[:60])
    log.info("[ssh-status] connect → %s (%s)", "ok" if ok_conn else "FAIL", out[:80])

    # 2. remote hostname via SSH (light scp equivalent)
    if ok_conn:
        ok2, hn = _ssh_run(alias, "cat /etc/hostname 2>/dev/null || hostname")
        _row(ok2, "remote name", f'"{hn.strip()}"' if ok2 else hn[:60])
        log.info("[ssh-status] remote hostname → %r", hn.strip())
    else:
        _row(None, "remote name", "skipped — connect failed")

    # 3. local ~/.ssh/config block
    cfg_alias = _check_local_ssh_config(ip)
    _row(bool(cfg_alias), "config block",
         f"Host {cfg_alias} in ~/.ssh/config" if cfg_alias
         else f"no netwatch block for {ip}")
    log.info("[ssh-status] local config block → %s", cfg_alias or "MISSING")

    # 4. known_hosts entry
    kh_ok = _check_known_hosts(ip)
    _row(kh_ok, "known_hosts",
         f"{ip} fingerprint on record" if kh_ok else "not in known_hosts")
    log.info("[ssh-status] known_hosts → %s", "ok" if kh_ok else "missing")

    # 5. our netwatch pubkey present on remote
    our_pub = _our_pubkey()
    if our_pub and ok_conn:
        safe = our_pub.replace("'", "'\\''")
        ok5, _ = _ssh_run(alias,
            f"grep -qF '{safe}' ~/.ssh/authorized_keys && echo yes || echo no")
        our_key_there = ok5 and _.strip() == "yes"
        _row(our_key_there, "our key",
             "netwatch pubkey in remote authorized_keys" if our_key_there
             else "netwatch pubkey NOT found on remote")
        log.info("[ssh-status] our key on remote → %s", "ok" if our_key_there else "MISSING")
    else:
        _row(None, "our key",
             "no netwatch key generated" if not our_pub else "skipped — connect failed")

    # ── inbound: remote → this machine ───────────────────────
    print(f"\n  inbound   ({ip} → this machine)")
    print(f"  {'─' * W}")

    if not ok_conn:
        print(f"    (skipped — cannot reach {ip})")
        print()
        return

    # 6. their pubkey in our authorized_keys
    ok6, their_pub = _ssh_run(alias,
        "if [ -f ~/.ssh/netwatch_id_ed25519.pub ]; then "
        "cat ~/.ssh/netwatch_id_ed25519.pub; "
        "else ls ~/.ssh/*.pub 2>/dev/null | head -1 | xargs -r cat 2>/dev/null; fi")
    if ok6 and their_pub.startswith("ssh-"):
        ak = Path.home() / ".ssh" / "authorized_keys"
        their_key_here = ak.exists() and their_pub.split()[1] in ak.read_text()
        _row(their_key_here, "their key",
             "remote pubkey in our authorized_keys" if their_key_here
             else "remote pubkey NOT in our authorized_keys")
        log.info("[ssh-status] their key here → %s", "ok" if their_key_here else "MISSING")
    else:
        _row(None, "their key", "could not read remote pubkey")

    # 7. netwatch block for us in remote ~/.ssh/config
    ok7, _ = _ssh_run(alias,
        f"grep -q '>>> netwatch: {our_ip}' ~/.ssh/config 2>/dev/null "
        f"&& echo yes || echo no")
    their_cfg_ok = ok7 and _.strip() == "yes"
    _row(their_cfg_ok, "their config",
         f"netwatch block for {our_ip} in remote ~/.ssh/config" if their_cfg_ok
         else f"no block for {our_ip} in remote ~/.ssh/config")
    log.info("[ssh-status] their config block for us → %s",
             "ok" if their_cfg_ok else "missing")

    # 8. reverse SSH: from remote, SSH back to this machine
    if our_ip:
        reverse_target = f"nw-{our_ip}" if their_cfg_ok else our_ip
        ok8, rev_out = _ssh_run(alias,
            f"ssh -o BatchMode=yes -o ConnectTimeout=5 "
            f"-o StrictHostKeyChecking=accept-new {reverse_target} "
            f"'echo netwatch-reverse-ok' 2>&1",
            timeout=15)
        reverse_ok = "netwatch-reverse-ok" in rev_out
        _row(reverse_ok, "reverse ssh",
             f"{ip} → {reverse_target}: ok" if reverse_ok
             else (rev_out[:60] or "no response"))
        log.info("[ssh-status] reverse ssh %s→%s → %s  %s",
                 ip, reverse_target, "ok" if reverse_ok else "FAIL", rev_out[:80])
    else:
        _row(None, "reverse ssh", "could not determine our source IP")

    print()


# ── main ──────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="netwatch — LAN discovery & assessment")
    p.add_argument("-o", "--once",      action="store_true", help="run one cycle and exit")
    p.add_argument("-d", "--daemon",    action="store_true", help="run continuously")
    p.add_argument("-i", "--interval",  type=int,            help="daemon interval seconds (overrides config)")
    p.add_argument("-s", "--subnet",                         help="override subnet (CIDR)")
    p.add_argument("-c", "--add-cred",  action="store_true", help="interactively add a credential")
    p.add_argument("-l", "--list-hosts",     action="store_true", help="one-line host table (short)")
    p.add_argument("-L", "--list-hosts-long",action="store_true", help="host table with probe detail (long)")
    p.add_argument("-C", "--list-creds",action="store_true", help="print vault contents")
    p.add_argument("-a", "--assess",         metavar="IP", help="force re-assess a single host")
    p.add_argument("-p", "--provision-ssh",  metavar="IP", help="force SSH key provisioning for a host")
    p.add_argument("-H", "--show-host",      metavar="IP", help="show full detail for a host")
    p.add_argument("-S", "--ssh-status",     metavar="IP",   help="verify SSH/SCP access both directions")
    p.add_argument("-A", "--set-alias", nargs=2, metavar=("IP", "NAME"), help="set friendly name for a host (updates ssh config + /etc/hosts)")
    p.add_argument("-y", "--sync-aliases", action="store_true", help="push all SSH aliases to every reachable host")
    p.add_argument("-n", "--no-sudo",   action="store_true", help="skip privileged techniques")
    p.add_argument("-q", "--quiet",     action="store_true", help="suppress INFO logs")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    cfg = Config.load()
    runtime_sudo_required = cfg.sudo_required
    if args.subnet:
        cfg.subnet = args.subnet
        cfg.extra_subnets = []
        cfg.successful_subnets = []
    if args.no_sudo:
        runtime_sudo_required = False
    if args.quiet:
        cfg.log_level = "WARNING"

    setup_logging(cfg.log_level)

    log.info("─── netwatch starting  pid=%d  subnet=%s  extra_subnets=[%s]  "
             "successful_subnets=[%s]  interval=%ds  sudo=%s",
             os.getpid(), cfg.subnet, ", ".join(cfg.extra_subnets),
             ", ".join(cfg.successful_subnets),
             cfg.interval_seconds, runtime_sudo_required)
    log.info("    discovery : %s", "  ".join(cfg.discovery_techniques))
    log.info("    probes    : %s", "  ".join(cfg.access_probes))

    # ── vault ─────────────────────────────────────────────────────────────────
    vault = CredVault()
    needs_vault = (args.add_cred or args.list_creds or args.once or args.daemon
                   or args.assess or args.provision_ssh)
    if needs_vault:
        try:
            unlocked = vault.unlock()
        except MissingDependencyError as exc:
            print(exc, file=sys.stderr)
            sys.exit(2)
        if not unlocked:
            sys.exit(1)

    # ── credential management commands ────────────────────────────────────────
    _more = args.once or args.daemon or args.assess or args.provision_ssh

    if args.add_cred:
        vault.interactive_add()
        if not (_more or args.list_hosts or args.list_hosts_long):
            vault.lock()
            return

    if args.list_creds:
        vault.interactive_list()
        if not _more:
            vault.lock()
            return

    # ── state ─────────────────────────────────────────────────────────────────
    state = HostState()
    state.load()

    if args.list_hosts or args.list_hosts_long:
        _refresh_macs(state)
        state.save()

    if args.list_hosts:
        cmd_list_hosts(state)
        if not _more:
            return

    if args.list_hosts_long:
        cmd_list_hosts_long(state)
        if not _more:
            return

    if args.show_host:
        cmd_show_host(args.show_host, state)
        if not _more:
            return

    if args.ssh_status:
        cmd_ssh_status(args.ssh_status, state)
        if not _more:
            return

    if args.set_alias:
        cmd_set_alias(args.set_alias[0], args.set_alias[1], state)
        if not _more:
            return

    if args.sync_aliases:
        cmd_sync_aliases(state, quiet=False)
        if not _more:
            return

    if args.assess:
        cmd_force_assess(args.assess, cfg, vault, state)
        if not (args.once or args.daemon):
            vault.lock()
            return

    if args.provision_ssh:
        cmd_provision_ssh(args.provision_ssh, cfg, vault, state)
        if not (args.once or args.daemon):
            vault.lock()
            return

    if not (args.once or args.daemon):
        vault.lock()
        return

    # ── sudo ──────────────────────────────────────────────────────────────────
    sudo_cfg = Config(**cfg.__dict__)
    sudo_cfg.sudo_required = runtime_sudo_required
    sudo_pass = get_sudo_pass(sudo_cfg)
    accessor  = Accessor(cfg, vault)

    # ── run ───────────────────────────────────────────────────────────────────
    if args.once:
        run_cycle(cfg, vault, state, accessor, sudo_pass)
        vault.lock()
        return

    if args.daemon:
        interval = args.interval or cfg.interval_seconds
        log.info("Daemon mode: interval=%ds, subnets=%s", interval,
                 ", ".join(cfg.target_subnets()))
        while True:
            try:
                run_cycle(cfg, vault, state, accessor, sudo_pass)
            except KeyboardInterrupt:
                log.info("Interrupted.")
                break
            except Exception as exc:
                log.exception("Cycle error: %s", exc)
            log.info("Sleeping %ds…", interval)
            time.sleep(interval)
        vault.lock()


if __name__ == "__main__":
    main()
