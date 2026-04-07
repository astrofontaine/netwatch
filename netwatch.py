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
import sys
import time
from pathlib import Path

# allow running from any cwd
sys.path.insert(0, str(Path(__file__).parent))

from config import Config, NETWATCH_DIR
from creds import CredVault
from discover import Discoverer
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
    log.info("─── Discovery cycle starting — subnet %s", cfg.subnet)

    discoverer = Discoverer(cfg.subnet, cfg.discovery_techniques, sudo_pass)
    live_ips   = discoverer.discover()
    log.info("Discovery complete: %d live host(s) found.", len(live_ips))

    new_hosts, gone_hosts = state.update(live_ips)

    if gone_hosts:
        log.info("Hosts no longer visible: %s", ", ".join(sorted(gone_hosts)))

    if new_hosts:
        log.info("NEW host(s): %s — starting assessment.", ", ".join(sorted(new_hosts)))
        for ip in sorted(new_hosts):
            results = accessor.assess(ip)
            open_ports_str = results.get("portscan", "")
            open_ports = []
            if open_ports_str and open_ports_str != "no open ports found":
                import re
                open_ports = [int(m) for m in re.findall(r'(\d+)/', open_ports_str)]
            state.update_record(
                ip,
                open_ports=open_ports,
                services={},
                access_results=results,
                assessed=True,
            )
            _log_assessment(ip, results)
    else:
        log.info("No new hosts this cycle.")

    state.save()
    log.info("─── Cycle complete.")


def _log_assessment(ip: str, results: dict) -> None:
    log.info("  Assessment for %s:", ip)
    for probe, result in results.items():
        log.info("    %-10s %s", probe + ":", result)


# ── CLI commands ──────────────────────────────────────────────────────────────

def cmd_list_hosts(state: HostState) -> None:
    hosts = state.all_hosts()
    if not hosts:
        print("No hosts in state yet.")
        return
    print(f"\n{'IP':<18} {'First seen':<22} {'Last seen':<22} {'Ports':<30} {'Assessed'}")
    print("─" * 100)
    for r in hosts:
        ports = ",".join(str(p) for p in sorted(r.open_ports)[:8]) or "—"
        print(f"{r.ip:<18} {r.first_seen:<22} {r.last_seen:<22} {ports:<30} {'yes' if r.assessed else 'no'}")
        if r.access_results:
            for svc, res in r.access_results.items():
                print(f"  {'':18} {svc}: {res[:80]}")
    print()


def cmd_force_assess(ip: str, cfg: Config, vault: CredVault, state: HostState) -> None:
    accessor = Accessor(cfg, vault)
    results  = accessor.assess(ip)
    state.update_record(ip, access_results=results, assessed=True)
    state.save()
    _log_assessment(ip, results)


# ── main ──────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="netwatch — LAN discovery & assessment")
    p.add_argument("--once",      action="store_true", help="run one cycle and exit")
    p.add_argument("--daemon",    action="store_true", help="run continuously")
    p.add_argument("--interval",  type=int,            help="daemon interval seconds (overrides config)")
    p.add_argument("--subnet",                         help="override subnet (CIDR)")
    p.add_argument("--add-cred",  action="store_true", help="interactively add a credential")
    p.add_argument("--list-hosts",action="store_true", help="print known host table")
    p.add_argument("--list-creds",action="store_true", help="print vault contents")
    p.add_argument("--assess",    metavar="IP",        help="force re-assess a single host")
    p.add_argument("--no-sudo",   action="store_true", help="skip privileged techniques")
    p.add_argument("--quiet",     action="store_true", help="suppress INFO logs")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    cfg = Config.load()
    if args.subnet:
        cfg.subnet = args.subnet
    if args.no_sudo:
        cfg.sudo_required = False
    if args.quiet:
        cfg.log_level = "WARNING"

    setup_logging(cfg.log_level)

    # ── vault ─────────────────────────────────────────────────────────────────
    vault = CredVault()
    needs_vault = args.add_cred or args.list_creds or args.once or args.daemon or args.assess
    if needs_vault:
        if not vault.unlock():
            sys.exit(1)

    # ── credential management commands ────────────────────────────────────────
    if args.add_cred:
        vault.interactive_add()
        if not (args.once or args.daemon or args.assess or args.list_hosts):
            vault.lock()
            return

    if args.list_creds:
        vault.interactive_list()
        if not (args.once or args.daemon or args.assess):
            vault.lock()
            return

    # ── state ─────────────────────────────────────────────────────────────────
    state = HostState()
    state.load()

    if args.list_hosts:
        cmd_list_hosts(state)
        if not (args.once or args.daemon or args.assess):
            return

    if args.assess:
        cmd_force_assess(args.assess, cfg, vault, state)
        if not (args.once or args.daemon):
            vault.lock()
            return

    if not (args.once or args.daemon):
        vault.lock()
        return

    # ── sudo ──────────────────────────────────────────────────────────────────
    sudo_pass = get_sudo_pass(cfg)
    accessor  = Accessor(cfg, vault)

    # ── run ───────────────────────────────────────────────────────────────────
    if args.once:
        run_cycle(cfg, vault, state, accessor, sudo_pass)
        vault.lock()
        return

    if args.daemon:
        interval = args.interval or cfg.interval_seconds
        log.info("Daemon mode: interval=%ds, subnet=%s", interval, cfg.subnet)
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
