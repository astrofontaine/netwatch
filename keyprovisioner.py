"""netwatch/keyprovisioner.py — mutual SSH key exchange for newly accessed hosts.

Sequence for each new host we successfully SSH into:
  1. Ensure we have ~/.ssh/netwatch_id_ed25519 (generate once, reused for all hosts)
  2. Install our pubkey in remote ~/.ssh/authorized_keys
  3. Ensure remote has their own keypair (generate ed25519 if absent)
  4. Retrieve remote pubkey → install in our ~/.ssh/authorized_keys
  5. Add/update a marker-delimited Host block in our ~/.ssh/config
  6. Add/update a reciprocal Host block in remote ~/.ssh/config
  7. Populate our ~/.ssh/known_hosts via ssh-keyscan (so BatchMode works)
  8. Test passwordless: ssh -o BatchMode=yes nw-<ip> "echo netwatch-ok"

The Host alias is  nw-<ip>  (e.g. nw-192.168.2.12).
Config blocks are wrapped in:
  # >>> netwatch: <ip>
  ...
  # <<< netwatch: <ip>
so they can be safely replaced on re-provision without touching other entries.
"""

from __future__ import annotations
import getpass
import logging
import os
import re
import stat
import subprocess
import threading
from pathlib import Path

log = logging.getLogger("netwatch.keyprov")

# ── paths ─────────────────────────────────────────────────────────────────────

SSH_DIR         = Path.home() / ".ssh"
NETWATCH_KEY    = SSH_DIR / "netwatch_id_ed25519"
NETWATCH_PUB    = SSH_DIR / "netwatch_id_ed25519.pub"
SSH_CONFIG      = SSH_DIR / "config"
AUTHORIZED_KEYS = SSH_DIR / "authorized_keys"
KNOWN_HOSTS     = SSH_DIR / "known_hosts"

_file_lock = threading.Lock()   # serialise all local SSH-dir writes


# ── helpers: local ────────────────────────────────────────────────────────────

def _our_source_ip(remote_ip: str) -> str:
    """Return the local IP address used to reach remote_ip."""
    r = subprocess.run(["ip", "route", "get", remote_ip],
                       capture_output=True, text=True)
    m = re.search(r'\bsrc\s+(\S+)', r.stdout)
    return m.group(1) if m else "127.0.0.1"


def _ensure_netwatch_keypair() -> str:
    """Generate ~/.ssh/netwatch_id_ed25519 if absent. Returns pubkey content."""
    SSH_DIR.mkdir(mode=0o700, exist_ok=True)
    if not NETWATCH_KEY.exists():
        log.info("Generating netwatch keypair: %s", NETWATCH_KEY)
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-q",
             "-C", f"netwatch@{getpass.getuser()}",
             "-f", str(NETWATCH_KEY)],
            check=True, capture_output=True,
        )
        NETWATCH_KEY.chmod(0o600)
        NETWATCH_PUB.chmod(0o644)
    return NETWATCH_PUB.read_text().strip()


def _add_to_authorized_keys(pubkey: str) -> None:
    """Append pubkey to our authorized_keys (idempotent)."""
    AUTHORIZED_KEYS.touch(mode=0o600)
    AUTHORIZED_KEYS.chmod(0o600)
    existing = AUTHORIZED_KEYS.read_text()
    if pubkey in existing:
        return
    with open(AUTHORIZED_KEYS, "a") as fh:
        fh.write(f"\n{pubkey}\n")
    log.info("  Added remote pubkey to our authorized_keys.")


def _update_ssh_config_local(ip: str, user: str) -> str:
    """Add/replace a marker-delimited Host block for ip. Returns alias used."""
    alias = f"nw-{ip}"
    block = (
        f"# >>> netwatch: {ip}\n"
        f"Host {alias}\n"
        f"    HostName {ip}\n"
        f"    User {user}\n"
        f"    IdentityFile {NETWATCH_KEY}\n"
        f"    StrictHostKeyChecking accept-new\n"
        f"    UserKnownHostsFile {KNOWN_HOSTS}\n"
        f"# <<< netwatch: {ip}\n"
    )
    SSH_CONFIG.touch(mode=0o600)
    SSH_CONFIG.chmod(0o600)
    text = SSH_CONFIG.read_text()
    text = _replace_or_append_block(text, ip, block)
    SSH_CONFIG.write_text(text)
    log.info("  Updated our ~/.ssh/config: Host %s", alias)
    return alias


def _add_to_known_hosts(ip: str) -> None:
    """Run ssh-keyscan and add the host key to known_hosts (idempotent)."""
    r = subprocess.run(
        ["ssh-keyscan", "-T", "3", "-H", ip],
        capture_output=True, text=True, timeout=10,
    )
    if not r.stdout.strip():
        log.warning("  ssh-keyscan returned nothing for %s", ip)
        return
    KNOWN_HOSTS.touch(mode=0o600)
    existing = KNOWN_HOSTS.read_text()
    lines_to_add = [
        ln for ln in r.stdout.splitlines()
        if ln.strip() and ln not in existing
    ]
    if lines_to_add:
        with open(KNOWN_HOSTS, "a") as fh:
            fh.write("\n".join(lines_to_add) + "\n")
    log.info("  Updated ~/.ssh/known_hosts for %s", ip)


def _replace_or_append_block(text: str, ip: str, block: str) -> str:
    """Replace the netwatch-managed block for ip, or append it."""
    start = f"# >>> netwatch: {ip}"
    end   = f"# <<< netwatch: {ip}"
    pattern = re.compile(
        rf'^{re.escape(start)}.*?^{re.escape(end)}\n?',
        re.MULTILINE | re.DOTALL,
    )
    if pattern.search(text):
        return pattern.sub(block, text)
    # append with a blank separator
    sep = "\n" if text and not text.endswith("\n\n") else ""
    return text.rstrip("\n") + "\n" + sep + block


# ── helpers: remote (via paramiko) ────────────────────────────────────────────

def _rexec(client, cmd: str) -> tuple[int, str]:
    """Run cmd on remote; returns (exit_code, stdout+stderr)."""
    try:
        _in, _out, _err = client.exec_command(cmd, timeout=15)
        out = _out.read().decode(errors="replace")
        err = _err.read().decode(errors="replace")
        rc  = _out.channel.recv_exit_status()
        return rc, out + err
    except Exception as exc:
        return -1, str(exc)


def _install_our_key_on_remote(client, our_pubkey: str) -> bool:
    """Push our pubkey into remote ~/.ssh/authorized_keys."""
    # Escape special chars for the shell heredoc-free approach
    safe_key = our_pubkey.replace("'", "'\\''")
    script = (
        "set -e; "
        "mkdir -p ~/.ssh; chmod 700 ~/.ssh; "
        "touch ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys; "
        f"grep -qF '{safe_key}' ~/.ssh/authorized_keys "
        f"|| printf '%s\\n' '{safe_key}' >> ~/.ssh/authorized_keys"
    )
    rc, out = _rexec(client, script)
    if rc != 0:
        log.warning("  Failed to install our key on remote: %s", out.strip())
        return False
    log.info("  Our pubkey installed in remote authorized_keys.")
    return True


def _ensure_remote_keypair(client) -> str | None:
    """Ensure remote has an ed25519 keypair; return their pubkey or None."""
    # Check for any existing pubkey
    rc, out = _rexec(client,
        "if ls ~/.ssh/*.pub 2>/dev/null | head -1 | grep -q .; then "
        "  cat $(ls ~/.ssh/*.pub | head -1); "
        "else "
        "  mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
        "  ssh-keygen -t ed25519 -N '' -q -f ~/.ssh/id_ed25519 && "
        "  cat ~/.ssh/id_ed25519.pub; "
        "fi"
    )
    if rc != 0 or not out.strip():
        log.warning("  Could not ensure remote keypair: %s", out.strip())
        return None
    pubkey = out.strip().split("\n")[0]   # first line = the key
    if not pubkey.startswith("ssh-"):
        log.warning("  Unexpected remote pubkey output: %r", pubkey[:80])
        return None
    log.info("  Remote keypair confirmed.")
    return pubkey


def _update_ssh_config_remote(client, our_ip: str, our_user: str) -> bool:
    """Push a Host nw-<our_ip> block to remote ~/.ssh/config."""
    alias = f"nw-{our_ip}"
    # We pass the config block via a python3 one-liner (avoids quoting nightmares)
    block = (
        f"# >>> netwatch: {our_ip}\\n"
        f"Host {alias}\\n"
        f"    HostName {our_ip}\\n"
        f"    User {our_user}\\n"
        f"    StrictHostKeyChecking accept-new\\n"
        f"# <<< netwatch: {our_ip}\\n"
    )
    # Use python3 on the remote to update the config file safely
    py_script = f"""
import re, os
from pathlib import Path
config = Path.home() / '.ssh' / 'config'
config.parent.mkdir(mode=0o700, exist_ok=True)
config.touch(mode=0o600)
os.chmod(config, 0o600)
text = config.read_text()
block = "{block}"
start = "# >>> netwatch: {our_ip}"
end   = "# <<< netwatch: {our_ip}"
pattern = re.compile(
    r'^' + re.escape(start) + r'.*?^' + re.escape(end) + r'\\n?',
    re.MULTILINE | re.DOTALL)
if pattern.search(text):
    text = pattern.sub(block, text)
else:
    text = text.rstrip('\\n') + '\\n' + block
config.write_text(text)
print('ok')
"""
    rc, out = _rexec(client, f"python3 -c {repr(py_script)}")
    if rc != 0 or "ok" not in out:
        # fallback: append without dedup (still functional)
        block_raw = (
            f"# >>> netwatch: {our_ip}\n"
            f"Host {alias}\n"
            f"    HostName {our_ip}\n"
            f"    User {our_user}\n"
            f"    StrictHostKeyChecking accept-new\n"
            f"# <<< netwatch: {our_ip}\n"
        )
        safe = block_raw.replace("'", "'\\''")
        rc2, out2 = _rexec(client,
            f"mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
            f"touch ~/.ssh/config && chmod 600 ~/.ssh/config && "
            f"printf '%s' '{safe}' >> ~/.ssh/config"
        )
        if rc2 != 0:
            log.warning("  Could not update remote ~/.ssh/config: %s", out2.strip())
            return False
    log.info("  Remote ~/.ssh/config updated: Host %s → %s@%s", alias, our_user, our_ip)
    return True


# ── test ─────────────────────────────────────────────────────────────────────

def _test_passwordless(alias: str) -> bool:
    """Test that we can SSH to alias with BatchMode (no password, no prompt)."""
    r = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
         alias, "echo netwatch-ok"],
        capture_output=True, text=True, timeout=12,
    )
    success = r.returncode == 0 and "netwatch-ok" in r.stdout
    if success:
        log.info("  Passwordless test PASSED → ssh %s works.", alias)
    else:
        log.warning("  Passwordless test FAILED for %s: %s", alias, (r.stdout + r.stderr).strip())
    return success


# ── public API ────────────────────────────────────────────────────────────────

class KeyProvisioner:
    """Call provision() with an open paramiko SSHClient after successful auth."""

    def provision(self, ip: str, user: str, client) -> dict:
        """
        Perform full mutual key exchange.

        Returns a result dict:
          our_key_installed   : bool
          their_key_installed : bool
          our_config_updated  : bool
          their_config_updated: bool
          test_passed         : bool
          alias               : str   (e.g. "nw-192.168.2.12")
          error               : str   (empty on full success)
        """
        result = {
            "our_key_installed":    False,
            "their_key_installed":  False,
            "our_config_updated":   False,
            "their_config_updated": False,
            "test_passed":          False,
            "alias":                f"nw-{ip}",
            "error":                "",
        }
        our_ip   = _our_source_ip(ip)
        our_user = getpass.getuser()

        log.info("[keyprov] Starting mutual key exchange with %s (user=%s)", ip, user)

        with _file_lock:
            try:
                our_pubkey = _ensure_netwatch_keypair()
            except Exception as exc:
                result["error"] = f"keygen failed: {exc}"
                log.error("[keyprov] %s", result["error"])
                return result

            # 1 — install our key on remote
            result["our_key_installed"] = _install_our_key_on_remote(client, our_pubkey)
            if not result["our_key_installed"]:
                result["error"] = "Could not install our pubkey on remote"
                return result

            # 2 — get/generate remote keypair and add to our authorized_keys
            their_pubkey = _ensure_remote_keypair(client)
            if their_pubkey:
                _add_to_authorized_keys(their_pubkey)
                result["their_key_installed"] = True
            else:
                log.warning("[keyprov] Skipping reverse key (remote keygen unavailable)")

            # 3 — update our ssh config
            try:
                _add_to_known_hosts(ip)
                alias = _update_ssh_config_local(ip, user)
                result["our_config_updated"] = True
                result["alias"] = alias
            except Exception as exc:
                log.warning("[keyprov] Local config update failed: %s", exc)

        # 4 — update remote ssh config (no file lock needed — different file)
        if our_ip and our_ip != "127.0.0.1":
            result["their_config_updated"] = _update_ssh_config_remote(
                client, our_ip, our_user
            )

        # 5 — test
        if result["our_config_updated"]:
            result["test_passed"] = _test_passwordless(result["alias"])

        status = "FULL SUCCESS" if all([
            result["our_key_installed"],
            result["our_config_updated"],
            result["test_passed"],
        ]) else "PARTIAL"
        log.info("[keyprov] %s for %s (alias: %s)", status, ip, result["alias"])
        return result
