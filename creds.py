"""netwatch/creds.py — encrypted credential vault (Fernet / PBKDF2).

Schema (in-memory, encrypted at rest):
  {
    "_default": {                    # tried on every unknown host
      "ssh":  [{"user": "debian", "secret": "...", "type": "password"}, ...],
      "snmp": [{"community": "public"}, ...]
    },
    "192.168.2.5": {                 # host-specific overrides
      "ssh":  [{"user": "admin", "secret": "...", "type": "key_path"}],
      "http": [{"user": "", "secret": "GHPAT_xxx", "type": "pat"}]
    }
  }

Secret types:
  password   plain password (SSH, web, SMB …)
  key_path   path to a local private key file
  pat        Personal Access Token / API key
  community  SNMP community string (stored as "secret" field)
"""

from __future__ import annotations
import base64
import getpass
import json
import os
import stat
from pathlib import Path
from typing import Optional

from config import NETWATCH_DIR

VAULT_FILE = NETWATCH_DIR / "vault.enc"
SALT_FILE  = NETWATCH_DIR / ".vault.salt"   # 0600


# ── crypto helpers ────────────────────────────────────────────────────────────

def _derive_key(passphrase: str, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))


def _load_salt() -> bytes:
    if SALT_FILE.exists():
        return SALT_FILE.read_bytes()
    salt = os.urandom(32)
    SALT_FILE.parent.mkdir(parents=True, exist_ok=True)
    SALT_FILE.write_bytes(salt)
    SALT_FILE.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return salt


# ── CredVault ─────────────────────────────────────────────────────────────────

class CredVault:
    def __init__(self) -> None:
        self._data: dict = {}
        self._fernet = None
        self._unlocked = False

    # ── unlock / lock ─────────────────────────────────────────────────────────

    def unlock(self, passphrase: Optional[str] = None) -> bool:
        """Decrypt vault from disk.  Prompts for passphrase if not supplied."""
        from cryptography.fernet import Fernet, InvalidToken

        if passphrase is None:
            passphrase = getpass.getpass("Vault passphrase: ")

        salt = _load_salt()
        key  = _derive_key(passphrase, salt)
        self._fernet = Fernet(key)

        if not VAULT_FILE.exists():
            # new vault — initialise with empty defaults
            self._data = {"_default": {"ssh": [], "snmp": []}}
            self._unlocked = True
            self._save()
            return True

        try:
            raw = self._fernet.decrypt(VAULT_FILE.read_bytes())
            self._data = json.loads(raw)
            self._unlocked = True
            return True
        except InvalidToken:
            print("Wrong passphrase.")
            self._fernet = None
            return False

    def lock(self) -> None:
        self._save()
        self._data = {}
        self._fernet = None
        self._unlocked = False

    def _save(self) -> None:
        if not self._fernet:
            return
        raw = json.dumps(self._data).encode()
        VAULT_FILE.parent.mkdir(parents=True, exist_ok=True)
        VAULT_FILE.write_bytes(self._fernet.encrypt(raw))
        VAULT_FILE.chmod(stat.S_IRUSR | stat.S_IWUSR)

    # ── credential access ─────────────────────────────────────────────────────

    def get(self, host: str, service: str) -> list[dict]:
        """Return credentials for host+service, falling back to _default."""
        self._check_unlocked()
        host_creds    = self._data.get(host, {}).get(service, [])
        default_creds = self._data.get("_default", {}).get(service, [])
        # host-specific first, then defaults (no duplicates by user)
        seen: set[str] = set()
        merged = []
        for c in host_creds + default_creds:
            key = f"{c.get('user','')}:{c.get('secret','')}"
            if key not in seen:
                seen.add(key)
                merged.append(c)
        return merged

    def set(self, host: str, service: str, cred: dict) -> None:
        """Add or update a credential entry.  host='_default' for global."""
        self._check_unlocked()
        self._data.setdefault(host, {}).setdefault(service, [])
        # replace existing entry for same user, or append
        entries = self._data[host][service]
        user = cred.get("user", "")
        for i, e in enumerate(entries):
            if e.get("user", "") == user:
                entries[i] = cred
                self._save()
                return
        entries.append(cred)
        self._save()

    def remove(self, host: str, service: str, user: str) -> bool:
        self._check_unlocked()
        entries = self._data.get(host, {}).get(service, [])
        before = len(entries)
        self._data[host][service] = [e for e in entries if e.get("user") != user]
        self._save()
        return len(self._data[host][service]) < before

    def list_hosts(self) -> list[str]:
        self._check_unlocked()
        return [h for h in self._data if h != "_default"]

    def _check_unlocked(self) -> None:
        if not self._unlocked:
            raise RuntimeError("Vault is locked — call unlock() first.")

    # ── interactive add ───────────────────────────────────────────────────────

    def interactive_add(self) -> None:
        """Guided prompt to add a new credential."""
        self._check_unlocked()
        print("\n── Add credential ─────────────────────────────────")
        host = input("Host IP (or '_default' for all hosts): ").strip() or "_default"
        print("Services: ssh  http  snmp  smb  pat")
        service = input("Service: ").strip().lower()
        print("Types: password  key_path  pat  community")
        ctype = input("Type: ").strip().lower()

        cred: dict = {"type": ctype}

        if ctype == "community":
            cred["secret"] = input("Community string: ").strip()
            cred["user"]   = ""
        elif ctype == "key_path":
            cred["user"]   = input("Username: ").strip()
            cred["secret"] = input("Path to private key file: ").strip()
        elif ctype == "pat":
            cred["user"]   = input("Username (or blank): ").strip()
            cred["secret"] = getpass.getpass("PAT / token: ")
        else:
            cred["user"]   = input("Username: ").strip()
            cred["secret"] = getpass.getpass("Password: ")

        self.set(host, service, cred)
        print(f"Saved: {host} / {service} / {ctype} ({cred.get('user','<no user>')})")

    def interactive_list(self) -> None:
        self._check_unlocked()
        print("\n── Stored credentials ─────────────────────────────")
        for host, services in self._data.items():
            for svc, entries in services.items():
                for e in entries:
                    secret_hint = ("*" * 6 + e["secret"][-3:]) if e.get("secret") else ""
                    print(f"  {host:20s}  {svc:8s}  {e.get('type','?'):10s}  "
                          f"{e.get('user',''):15s}  {secret_hint}")
