# netwatch — Claude context

## Project overview

LAN discovery and access-assessment tool. Scans `192.168.2.0/24` (this VM is `192.168.2.11`) on a 5-minute cron cycle. Finds new hosts, assesses them for open services, and attempts access using stored credentials.

## Module map

| File | Role |
|------|------|
| `netwatch.py` | CLI entrypoint, daemon loop, `run_cycle()` |
| `discover.py` | 8 parallel discovery techniques; `Discoverer.discover()` returns `set[str]` of IPs |
| `accessor.py` | Service probes: `probe_portscan`, `probe_ssh`, `probe_http`, `probe_snmp`, `probe_smb`; `Accessor.assess()` runs them all |
| `creds.py` | `CredVault` — Fernet-encrypted vault, PBKDF2-SHA256 key derivation (480k iterations), host-scoped + `_default` credentials |
| `state.py` | `HostState` / `HostRecord` — JSON persistence at `~/.netwatch/hosts.json` |
| `config.py` | `Config` dataclass — JSON persistence at `~/.netwatch/config.json`; `NETWATCH_DIR = ~/.netwatch` |
| `keyprovisioner.py` | `KeyProvisioner.provision()` — mutual SSH key exchange via open paramiko client |
| `install.sh` | apt installs + cron entry (`*/5 * * * *`) |

## Runtime data locations

All data lives under `~/.netwatch/` (not in the repo):
- `vault.enc` — encrypted credentials
- `.vault.salt` — PBKDF2 salt (never log or expose)
- `hosts.json` — known host state
- `config.json` — runtime config
- `logs/` — `netwatch.log`, `cron.log`

## Key design decisions

- **Discovery is always parallel** — `Discoverer.discover()` runs all configured techniques in threads and merges results.
- **Vault is locked at rest** — `CredVault.unlock()` decrypts into memory; `lock()` re-encrypts and wipes. Always call `lock()` before exit.
- **Credentials fall back to `_default`** — `vault.get(host, service)` merges host-specific creds on top of `_default` creds.
- **Successful fallback SSH credentials are remembered** — if a `_default` or otherwise guessed SSH credential successfully authenticates to a host, `accessor.py` persists that same credential under the host-specific `ssh` vault scope so future access does not depend only on broad defaults.
- **Admin access is assessed separately** — successful SSH probes also check root access, passwordless sudo, sudo with the stored password, and `su -` using stored root credentials. Confirmed admin credentials are persisted under host-specific `root`, `sudo`, or `su` vault scopes.
- **SSH probes try paramiko first**, fall back to `sshpass`+ssh CLI if paramiko is absent.
- **SSH config blocks are marker-delimited** — `# >>> netwatch: <ip>` / `# <<< netwatch: <ip>` so re-provision is safe.
- **`HostRecord.assessed`** is set to `True` once an assess cycle completes, preventing redundant re-assessment.

## Common tasks

### Add a credential interactively
```bash
python3 netwatch.py --add-cred
```

### Run a single cycle (useful for testing)
```bash
python3 netwatch.py --once --no-sudo   # skip privileged techniques
python3 netwatch.py --once             # with sudo (prompts once)
```

### Force re-assess a host
```bash
python3 netwatch.py --assess 192.168.2.X
```

### Check host state
```bash
python3 netwatch.py --list-hosts
```

## Dependencies

All apt-installed (see `install.sh`): `nmap`, `arp-scan`, `fping`, `masscan`, `netdiscover`, `snmp`, `smbclient`, `sshpass`, `python3-paramiko`, `python3-scapy`, `python3-cryptography`.

Tools degrade gracefully when absent — each discovery technique checks `which <tool>` before running.

## Notes

- The BBB (BeagleBone Black) on this LAN is accessed via `ssh bbb` using `~/.ssh/id_ed25519_bbb`.
- A second VM (Codex) is planned on this subnet.
- `--no-sudo` skips: `nmap_ping`, `arp_scan`, `netdiscover`, `masscan`.
- `sudo` password is prompted once and held in memory for the duration of a daemon run.
