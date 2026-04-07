# netwatch

Periodic LAN discovery and access-assessment daemon for small networks. Runs every 5 minutes via cron, finds new hosts, and attempts access using stored credentials.

## What it does

1. **Discovers** live hosts on a subnet using up to 8 parallel techniques (ARP cache, ping sweep, fping, nmap, arp-scan, netdiscover, masscan).
2. **Assesses** each new host: port scan → SSH → HTTP/HTTPS → SNMP → SMB.
3. **Stores** credentials in a Fernet-encrypted vault (`~/.netwatch/vault.enc`) and host state in `~/.netwatch/hosts.json`.
4. **Provisions** mutual SSH key exchange for hosts where SSH access succeeds (`keyprovisioner.py`).

## Requirements

Run once as a sudoer:

```bash
./install.sh
```

This installs: `nmap`, `arp-scan`, `fping`, `masscan`, `netdiscover`, `snmp`, `smbclient`, `sshpass`, `python3-paramiko`, `python3-scapy`, `python3-cryptography`.

## Usage

```bash
# One discovery + assessment cycle
python3 netwatch.py --once

# Run as a daemon (default interval: 5 min)
python3 netwatch.py --daemon

# Add a credential to the vault
python3 netwatch.py --add-cred

# Show known hosts and their assessment results
python3 netwatch.py --list-hosts

# Show vault contents (secrets are masked)
python3 netwatch.py --list-creds

# Force re-assess a specific host
python3 netwatch.py --assess 192.168.2.5

# Override subnet
python3 netwatch.py --once --subnet 10.0.0.0/24

# Skip privileged discovery techniques
python3 netwatch.py --once --no-sudo
```

## Configuration

Config is stored at `~/.netwatch/config.json` and auto-created on first run with these defaults:

| Key | Default | Description |
|-----|---------|-------------|
| `subnet` | `192.168.2.0/24` | Target subnet |
| `interval_seconds` | `300` | Daemon poll cadence |
| `sudo_required` | `true` | Enable privileged discovery techniques |
| `discovery_techniques` | see below | Ordered list of discovery methods |
| `access_probes` | `portscan, ssh, http, snmp, smb` | Services to probe on new hosts |
| `snmp_communities` | `public, private, community` | SNMP community strings to try |
| `ssh_timeout` | `8` | SSH connect timeout (seconds) |
| `http_timeout` | `5` | HTTP connect timeout (seconds) |

Default discovery techniques (run in parallel): `ip_neigh`, `proc_arp`, `ping_sweep`, `fping`, `nmap_ping`, `arp_scan`, `netdiscover`.

## Credential vault

Credentials are encrypted at rest with Fernet (PBKDF2-SHA256, 480k iterations). The vault passphrase is prompted once per session and the vault is locked when done.

Supported credential types:
- `password` — plain password (SSH, SMB, HTTP)
- `key_path` — path to a local private key file (SSH)
- `pat` — Personal Access Token / API key (HTTP)
- `community` — SNMP community string

Credentials can be scoped to a specific host IP or set globally under `_default` to be tried on every new host.

## Runtime files

| Path | Purpose |
|------|---------|
| `~/.netwatch/config.json` | Configuration |
| `~/.netwatch/vault.enc` | Encrypted credential vault |
| `~/.netwatch/.vault.salt` | PBKDF2 salt (0600) |
| `~/.netwatch/hosts.json` | Known host state |
| `~/.netwatch/logs/netwatch.log` | Main log |
| `~/.netwatch/logs/cron.log` | Cron output |

## File structure

```
netwatch/
├── netwatch.py        # CLI entrypoint + daemon loop
├── discover.py        # 8 parallel discovery techniques
├── accessor.py        # portscan → SSH → HTTP → SNMP → SMB probes
├── creds.py           # Fernet-encrypted credential vault
├── state.py           # Host state persistence (hosts.json)
├── config.py          # Config dataclass + defaults
├── keyprovisioner.py  # Mutual SSH key exchange for accessible hosts
└── install.sh         # apt installs + cron setup
```

## SSH key provisioning

When SSH access to a new host succeeds, `KeyProvisioner` performs a mutual key exchange:
1. Generates `~/.ssh/netwatch_id_ed25519` if absent.
2. Installs our pubkey in the remote's `authorized_keys`.
3. Retrieves (or generates) the remote's keypair and adds it to our `authorized_keys`.
4. Writes a marker-delimited `Host nw-<ip>` block in our `~/.ssh/config`.
5. Pushes a reciprocal block to the remote's `~/.ssh/config`.
6. Populates `~/.ssh/known_hosts` via `ssh-keyscan`.
7. Tests passwordless login: `ssh -o BatchMode=yes nw-<ip> "echo netwatch-ok"`.

SSH config blocks are wrapped in `# >>> netwatch: <ip>` / `# <<< netwatch: <ip>` markers so they can be safely updated on re-provision without touching other entries.
