# netwatch

Periodic LAN discovery and access-assessment daemon for small networks. Scans a subnet every 5 minutes via cron, finds new hosts, probes their services, attempts access using stored credentials, and maintains a mesh of SSH aliases across all known machines.

---

## Table of contents

1. [What it does](#what-it-does)
2. [Installation](#installation)
3. [Quick start](#quick-start)
4. [CLI reference](#cli-reference)
5. [Configuration](#configuration)
6. [Credential vault](#credential-vault)
7. [SSH aliases and propagation](#ssh-aliases-and-propagation)
8. [SSH key provisioning](#ssh-key-provisioning)
9. [SSH status verification](#ssh-status-verification)
10. [Discovery techniques](#discovery-techniques)
11. [Service probes](#service-probes)
12. [Host state and history](#host-state-and-history)
13. [Runtime files](#runtime-files)
14. [File structure](#file-structure)
15. [FAQ](#faq)

---

## What it does

1. **Discovers** live hosts on a subnet using up to 8 parallel techniques (ARP cache, ping sweep, fping, nmap, arp-scan, netdiscover, masscan).
2. **Enriches** each host with its MAC address and all resolvable names (DNS, mDNS `.local`, NetBIOS).
3. **Assesses** each new host: port scan → SSH → HTTP/HTTPS → SNMP → SMB.
4. **Provisions** mutual SSH key exchange when SSH access succeeds, so both machines can reach each other passwordlessly.
5. **Manages SSH aliases** — friendly names like `ssh macbook` or `ssh proxmox` that are kept in sync across all reachable machines automatically.
6. **Tracks history** — every field change on every host is timestamped and stored for auditing.

---

## Installation

Run once as a sudoer:

```bash
./install.sh
```

Installs apt packages: `nmap`, `arp-scan`, `fping`, `masscan`, `netdiscover`, `snmp`, `smbclient`, `sshpass`, `python3-paramiko`, `python3-scapy`, `python3-cryptography`.

Also installs a cron entry: `*/5 * * * * python3 /path/to/netwatch.py --once`.

---

## Quick start

```bash
# First run — seed the vault with credentials
python3 netwatch.py -c

# Run one discovery + assessment cycle
python3 netwatch.py -o

# See what was found
python3 netwatch.py -l

# See full detail per host
python3 netwatch.py -L

# Start the daemon
python3 netwatch.py -d
```

---

## CLI reference

Every flag has a short (`-x`) and long (`--word`) form.

| Short | Long | Argument | Description |
|-------|------|----------|-------------|
| `-o` | `--once` | — | Run one discovery + assessment cycle and exit |
| `-d` | `--daemon` | — | Run continuously (default interval: 5 min) |
| `-i` | `--interval` | seconds | Override daemon poll interval |
| `-s` | `--subnet` | CIDR | Override subnet (e.g. `10.0.0.0/24`) |
| `-c` | `--add-cred` | — | Interactively add a credential to the vault |
| `-l` | `--list-hosts` | — | One-line host table (IP, alias, open ports, last seen) |
| `-L` | `--list-hosts-long` | — | Card view per host with full probe results |
| `-C` | `--list-creds` | — | Print vault contents (secrets masked) |
| `-a` | `--assess` | IP | Force re-assess a single host |
| `-p` | `--provision-ssh` | IP | Force SSH key provisioning for a host |
| `-H` | `--show-host` | IP | Show full detail for one host |
| `-S` | `--ssh-status` | IP | 8-point SSH verification both directions |
| `-A` | `--set-alias` | IP NAME | Set friendly SSH alias for a host |
| `-y` | `--sync-aliases` | — | Push all SSH aliases to every reachable host |
| `-n` | `--no-sudo` | — | Skip privileged discovery techniques |
| `-q` | `--quiet` | — | Suppress INFO logs (errors still shown) |

### Examples

```bash
# Skip sudo (no arp-scan, nmap, masscan, netdiscover)
python3 netwatch.py -o -n

# Force re-assess the MacBook
python3 netwatch.py -a 192.168.2.1

# Name a host and propagate the alias everywhere
python3 netwatch.py -A 192.168.2.1 macbook

# Verify SSH works both ways to a host
python3 netwatch.py -S 192.168.2.1

# Run daemon with a 10-minute interval on a different subnet
python3 netwatch.py -d -i 600 -s 10.0.1.0/24
```

---

## Configuration

Stored at `~/.netwatch/config.json`. Auto-created on first run with defaults.

| Key | Default | Description |
|-----|---------|-------------|
| `subnet` | `192.168.2.0/24` | Target subnet |
| `interval_seconds` | `300` | Daemon poll cadence (seconds) |
| `sudo_required` | `true` | Enable privileged discovery techniques |
| `discovery_techniques` | see below | Ordered list of techniques to run |
| `access_probes` | `portscan, ssh, http, snmp, smb` | Services to probe on new hosts |
| `snmp_communities` | `public, private, community` | SNMP community strings to try |
| `ssh_timeout` | `8` | SSH connect timeout (seconds) |
| `http_timeout` | `5` | HTTP connect timeout (seconds) |
| `log_level` | `INFO` | Logging level (`DEBUG`, `INFO`, `WARNING`) |

Default discovery techniques (all run in parallel):

```
ip_neigh      ip neigh show         — no sudo
proc_arp      /proc/net/arp         — no sudo
ping_sweep    parallel ping         — no sudo (uses setuid bit)
fping         fping -a -q -g        — no sudo
nmap_ping     nmap -sn (ARP+ICMP)   — sudo
arp_scan      arp-scan --localnet   — sudo
netdiscover   netdiscover -P -r     — sudo
```

`masscan` is available but not enabled by default — add it to `discovery_techniques` in config if you want it.

---

## Credential vault

Credentials are Fernet-encrypted at rest, keyed with PBKDF2-SHA256 (480k iterations). The vault passphrase is prompted once per session; memory is wiped when the vault locks.

### Credential types

| Type | Used for | Fields |
|------|----------|--------|
| `password` | SSH, SMB, HTTP | `user`, `secret` |
| `key_path` | SSH | `user`, `secret` (path to private key file) |
| `pat` | HTTP / API tokens | `user` (optional), `secret` |
| `community` | SNMP | `secret` (community string) |

### Scoping

- Credentials under `_default` are tried on every host.
- Credentials under a specific IP are tried first, then `_default` credentials fill in (no duplicates by username).

### Interactive management

```bash
# Add a credential
python3 netwatch.py -c

# List all stored credentials (secrets masked)
python3 netwatch.py -C
```

### Vault files

| File | Purpose |
|------|---------|
| `~/.netwatch/vault.enc` | Encrypted vault (Fernet) |
| `~/.netwatch/.vault.salt` | PBKDF2 salt — never log, never expose (mode 0600) |

---

## SSH aliases and propagation

netwatch manages `Host` blocks in `~/.ssh/config` for every known host, delimited by markers so they can be safely updated without touching your other entries.

### Setting an alias

```bash
python3 netwatch.py -A 192.168.2.1 macbook
```

This:
1. Rewrites the `Host` line in the local `~/.ssh/config` netwatch block for that IP.
2. Updates `ssh_alias` in `hosts.json`.
3. Adds/updates a marker-delimited entry in the local `/etc/hosts`.
4. SSHes to the target and updates its `/etc/hosts` with this machine's IP and alias.
5. SSHes to the target and rewrites its `~/.ssh/config` block for this machine to use this machine's short hostname.
6. Runs a full alias sync (`-y`) so all other reachable hosts also get updated.

After this you can run `ssh macbook` from this machine and `ssh claude` from the MacBook.

### SSH config block format

```
# >>> netwatch: 192.168.2.1
Host macbook
    HostName 192.168.2.1
    User davidfontaine
    StrictHostKeyChecking accept-new
# <<< netwatch: 192.168.2.1
```

Blocks are idempotent — running `-A` again replaces the existing block cleanly, never duplicates.

### Syncing aliases across all hosts

```bash
python3 netwatch.py -y
```

Reads all aliased hosts from state, SSHes to each reachable one, and writes/replaces all other hosts' netwatch SSH blocks in their `~/.ssh/config`. After a sync:

- `ssh proxmox` works from the MacBook.
- `ssh macbook` works from Proxmox.
- `ssh claude` works from anywhere.

`-y` runs automatically at the end of every `-A` command, so you don't usually need to call it manually.

---

## SSH key provisioning

When SSH access to a new host succeeds during assessment, `KeyProvisioner` automatically performs a mutual key exchange. You can also trigger it manually:

```bash
python3 netwatch.py -p 192.168.2.5
```

### What it does

1. Generates `~/.ssh/netwatch_id_ed25519` locally if it doesn't exist.
2. Installs our public key in the remote's `~/.ssh/authorized_keys`.
3. Retrieves (or generates) the remote's keypair and installs it in our `~/.ssh/authorized_keys`.
4. Writes a marker-delimited `Host <alias>` block in our `~/.ssh/config`.
5. Pushes a reciprocal block to the remote's `~/.ssh/config`.
6. Adds the remote host to our `~/.ssh/known_hosts` via `ssh-keyscan`.
7. Tests passwordless login: `ssh -o BatchMode=yes <alias> "echo netwatch-ok"`.

After provisioning, `ssh <alias>` and `scp <alias>:/path ./` work without a password from both sides.

---

## SSH status verification

```bash
python3 netwatch.py -S 192.168.2.1
```

Runs 8 checks and prints a ✓/✗/? result for each:

| Check | What it verifies |
|-------|-----------------|
| Local SSH config block | `~/.ssh/config` has a netwatch block for this IP |
| Alias resolves | The `Host` alias in the block resolves to the correct IP |
| Host in known_hosts | Remote host key is in `~/.ssh/known_hosts` |
| Outbound SSH (BatchMode) | `ssh -o BatchMode=yes <alias> echo ok` succeeds |
| Remote reports correct IP | Remote sees us coming from the expected source IP |
| Remote has our pubkey | Our public key appears in the remote's `authorized_keys` |
| Remote SSH config block | Remote's `~/.ssh/config` has a block pointing back to us |
| Inbound SSH (via remote) | Remote can `ssh <our-alias> echo ok` back to us |

If any check fails, the output tells you exactly which step to fix.

---

## Discovery techniques

All techniques run in parallel threads and results are merged. Only IPs within the configured subnet are kept (stale ARP entries for external IPs are filtered out).

| Technique | Command | Needs sudo |
|-----------|---------|------------|
| `ip_neigh` | `ip neigh show` (skips FAILED entries) | No |
| `proc_arp` | Read `/proc/net/arp` | No |
| `ping_sweep` | `ping -c1 -W1` (up to 128 parallel threads) | No |
| `fping` | `fping -a -q -g <subnet>` | No |
| `nmap_ping` | `nmap -sn -T4` | Sudo (for ARP mode) |
| `arp_scan` | `arp-scan --localnet --retry=2` | Sudo |
| `netdiscover` | `netdiscover -P -r <subnet>` | Sudo |
| `masscan` | `masscan -p22,80,443,… --rate=1000` | Sudo |

Each technique checks `which <tool>` before running and silently skips if the tool is absent. Tools degrade gracefully — the system works with whatever is installed.

### Host enrichment (runs after discovery)

- **MAC address** — looked up from `/proc/net/arp`, then `ip neigh show`, then `ip addr show` (handles the case where the IP belongs to this machine itself).
- **Hostnames** — resolved in parallel threads: system resolver (`gethostbyaddr`), mDNS via `avahi-resolve` (`.local` names), NetBIOS via `nmblookup` (Windows/macOS/Samba hosts).

---

## Service probes

Run against every new host (or on demand with `-a`). Controlled by `access_probes` in config.

### Port scan

Uses `nmap -sV` if available, otherwise falls back to raw socket connects. Probes ~26 common ports including SSH, HTTP/S, SMB, RDP, MQTT, SNMP, Redis, MongoDB, and more.

### SSH

1. Tries paramiko with all stored credentials (host-specific first, then `_default`).
2. Falls back to `sshpass` + ssh CLI if paramiko is not installed.
3. On success: runs `uname -a`, captures the banner, and automatically triggers mutual SSH key provisioning.
4. Stores the SSH username, banner, and alias in the host record.

### HTTP/HTTPS

Tries four combinations: `https:443`, `http:80`, `http:8080`, `https:8443`. Reports HTTP status code and `Server:` header. Injects a Bearer token from the vault if one is stored for the host.

### SNMP

Tries community strings from the vault (host-specific, then `_default`), then falls back to `config.snmp_communities`. Reports the `sysDescr` on success.

### SMB

Tries anonymous access first (`smbclient -N -L`), then stored credentials. Reports share listing on success.

---

## Host state and history

State is persisted at `~/.netwatch/hosts.json`. Every field change is logged to the application log and appended to a per-host history (capped at 500 events).

### HostRecord fields

| Field | Description |
|-------|-------------|
| `ip` | IP address |
| `mac_address` | MAC from ARP cache or `ip neigh` |
| `hostnames` | All resolvable names (DNS, mDNS, NetBIOS) |
| `ssh_alias` | Friendly name set with `-A` |
| `first_seen` | ISO timestamp of first discovery |
| `last_seen` | ISO timestamp of most recent discovery |
| `assessed` | `true` once at least one probe cycle has completed |
| `access_results` | Dict of probe name → result string |
| `history` | List of timestamped field-change events (max 500) |

### Viewing host data

```bash
# One-line table of all hosts
python3 netwatch.py -l

# Card view with full probe results
python3 netwatch.py -L

# Full detail for one host (all fields + history)
python3 netwatch.py -H 192.168.2.1
```

---

## Runtime files

| Path | Purpose |
|------|---------|
| `~/.netwatch/config.json` | Configuration |
| `~/.netwatch/vault.enc` | Encrypted credential vault |
| `~/.netwatch/.vault.salt` | PBKDF2 salt (mode 0600 — protect this file) |
| `~/.netwatch/hosts.json` | Known host state and history |
| `~/.netwatch/logs/netwatch.log` | Main log |
| `~/.netwatch/logs/cron.log` | Cron output |

---

## File structure

```
netwatch/
├── netwatch.py        # CLI entrypoint, argument parsing, daemon loop, all commands
├── discover.py        # 8 parallel discovery techniques + MAC/hostname enrichment
├── accessor.py        # portscan → SSH → HTTP → SNMP → SMB probes
├── creds.py           # Fernet-encrypted credential vault
├── state.py           # Host state persistence with field-level change logging
├── config.py          # Config dataclass + JSON persistence
├── keyprovisioner.py  # Mutual SSH key exchange via open paramiko session
└── install.sh         # apt installs + cron setup
```

---

## FAQ

**Why are there hosts like 192.168.2.3–.7 showing up with no data?**

Stale ARP/neighbour entries — typically from VMs or containers on the same host that were recently running. They have no open ports because the hosts aren't actually up. They'll age out of the ARP cache over time.

**An external IP appeared in my host list.**

The kernel ARP cache sometimes retains entries from active connections (VPN, remote SSH, etc.). netwatch filters results to the configured subnet, so this only appears if the external IP falls within that range. It will drop out when the connection ends and the ARP entry expires.

**`-l` or `-L` is slow.**

These commands read directly from `hosts.json` — they should be instant. If they're slow, check whether `avahi-daemon` or `nmbd` are stalled on the system; those are only called during discovery cycles, not list commands. If a discovery cycle is running concurrently, wait for it to finish.

**`ssh macbook` works from this machine but `ssh proxmox` fails from the MacBook with "Permission denied".**

Two separate things: alias resolution and key authorization. `-y` syncs aliases (so the hostname resolves to the right IP) but the MacBook's SSH key still needs to be in Proxmox's `authorized_keys`. Run `python3 netwatch.py -p 192.168.2.2` from this machine to provision keys, then `-y` to push the updated config.

**I changed a host's alias but the old name still works on some machines.**

Run `python3 netwatch.py -y` to re-push all current aliases to every reachable host.

**The vault passphrase prompt appears even for `-l`.**

It shouldn't — `-l` and `-L` read `hosts.json` only and never touch the vault. If you're seeing a prompt, another flag in the same command line (like `-o` or `-a`) is triggering vault access.

**How do I add an SSH private key (not a password) for a host?**

```bash
python3 netwatch.py -c
# Host IP: 192.168.2.5   (or _default for all hosts)
# Service: ssh
# Type: key_path
# Username: admin
# Path to private key: /home/longshot/.ssh/id_ed25519_myhost
```

**How do I re-assess a host that's already been assessed?**

```bash
python3 netwatch.py -a 192.168.2.5
```

This clears the `assessed` flag and re-runs all configured probes.

**How do I enable `masscan`?**

Edit `~/.netwatch/config.json` and add `"masscan"` to the `discovery_techniques` list. masscan requires sudo and is not enabled by default because it sends raw packets at high rate — use with care on shared networks.

**Where are logs?**

- `~/.netwatch/logs/netwatch.log` — all INFO/WARNING/ERROR output from the daemon and CLI commands.
- `~/.netwatch/logs/cron.log` — stdout/stderr captured by cron on each scheduled run.
- Run with `-q` to suppress INFO output in interactive sessions.
