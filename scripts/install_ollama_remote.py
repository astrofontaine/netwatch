#!/usr/bin/env python3
"""Install Ollama on a netwatch-managed SSH host.

Uses netwatch's credential vault for SSH and root/su access. Secrets are never
printed. Intended for Debian-like hosts with systemd.
"""

from __future__ import annotations

import argparse
import base64
import shlex
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from creds import CredVault  # noqa: E402


DEFAULT_MODEL = "qwen2.5:7b-instruct-q4_K_M"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Install Ollama on a netwatch-managed host")
    p.add_argument("host", help="Host/IP/SSH alias, e.g. qwen or 192.168.2.18")
    p.add_argument("--ip", help="Vault scope IP if host is an SSH alias")
    p.add_argument("--model", default=DEFAULT_MODEL, help=f"Model to pull, default: {DEFAULT_MODEL}")
    return p.parse_args()


def vault_creds(vault: CredVault, scope: str) -> tuple[list[dict], list[dict]]:
    ssh_creds = vault.get(scope, "ssh")
    root_creds = []
    for service in ("su", "root", "ssh"):
        for cred in vault.get(scope, service):
            if cred.get("type") == "password" and cred.get("user") == "root":
                key = (cred.get("user"), cred.get("secret"), cred.get("type"))
                if key not in {(c.get("user"), c.get("secret"), c.get("type")) for c in root_creds}:
                    root_creds.append(cred)
    return ssh_creds, root_creds


def connect(host: str, ssh_creds: list[dict]):
    import paramiko

    last_error = None
    for cred in ssh_creds:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            kwargs = {
                "hostname": host,
                "port": 22,
                "username": cred["user"],
                "timeout": 10,
            }
            if cred.get("type") == "key_path":
                kwargs["key_filename"] = cred["secret"]
                kwargs["allow_agent"] = True
            else:
                kwargs["password"] = cred["secret"]
                kwargs["allow_agent"] = False
                kwargs["look_for_keys"] = False
            client.connect(**kwargs)
            return client, cred
        except Exception as exc:  # keep trying vault candidates
            last_error = exc
    raise RuntimeError(f"SSH connection failed for all stored credentials: {last_error}")


def read_until(shell, needles: tuple[str, ...], timeout: float = 30) -> str:
    deadline = time.time() + timeout
    data = ""
    while time.time() < deadline:
        if shell.recv_ready():
            chunk = shell.recv(4096).decode(errors="replace")
            data += chunk
            sys.stdout.write(chunk)
            sys.stdout.flush()
            if any(needle in data for needle in needles):
                return data
        time.sleep(0.1)
    return data


def run_root_script(client, root_password: str, script: str) -> None:
    shell = client.invoke_shell(width=160, height=48)
    shell.settimeout(10)
    read_until(shell, ("$", "#"), timeout=10)
    shell.send("su -\n")
    read_until(shell, ("Password:", "password:"), timeout=10)
    shell.send(root_password + "\n")
    su_output = read_until(shell, ("#", "Authentication failure"), timeout=10)
    if "Authentication failure" in su_output:
        raise RuntimeError("su authentication failed")

    payload = base64.b64encode(script.encode()).decode()
    marker = "__NETWATCH_OLLAMA_INSTALL_DONE__"
    command = f"base64 -d <<'EOF' | bash\n{payload}\nEOF\necho {marker}:$?\n"
    shell.send(command)
    output = read_until(shell, (marker,), timeout=3600)
    if f"{marker}:0" not in output:
        raise RuntimeError("remote Ollama install script failed")
    shell.close()


def install_script(model: str) -> str:
    quoted_model = shlex.quote(model)
    return f"""#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
LOG=/var/log/netwatch-ollama-install.log
exec > >(tee -a "$LOG") 2>&1

echo "[$(date -Is)] Starting Ollama install for model: {model}"
df -h /

# Ollama's Linux install currently lays down several GB of runtime libraries.
# The requested 7B q4 model is about 4.7 GB. Require enough room up front so
# hosts with small root disks fail before the network-heavy pull.
avail_kb=$(df --output=avail / | tail -1)
required_kb=$((12 * 1024 * 1024))
if [ "$avail_kb" -lt "$required_kb" ]; then
  echo "ERROR: / has $(awk "BEGIN {{printf \\"%.1f\\", $avail_kb/1024/1024}}") GB free; need at least 12 GB for Ollama plus {model}."
  echo "Expand the disk or configure OLLAMA_MODELS on a larger persistent mount, then rerun."
  exit 70
fi

if ! command -v curl >/dev/null 2>&1; then
  apt-get update
  apt-get install -y curl ca-certificates
fi

if ! command -v ollama >/dev/null 2>&1; then
  curl -fsSL https://ollama.com/install.sh | sh
fi

mkdir -p /etc/systemd/system/ollama.service.d
cat > /etc/systemd/system/ollama.service.d/override.conf <<'EOF'
[Service]
Environment="OLLAMA_HOST=0.0.0.0:11434"
EOF

systemctl daemon-reload
systemctl enable --now ollama
systemctl restart ollama

for _ in $(seq 1 30); do
  if ollama list >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

ollama pull {quoted_model}

echo "Ollama installed. Listening on 0.0.0.0:11434. Model ready."
ollama list
"""


def main() -> int:
    args = parse_args()
    scope = args.ip or args.host

    vault = CredVault()
    if not vault.unlock():
        return 1
    try:
        ssh_creds, root_creds = vault_creds(vault, scope)
        if not ssh_creds:
            raise RuntimeError(f"No SSH credentials in vault for {scope}")
        if not root_creds:
            raise RuntimeError(f"No root/su credential in vault for {scope}")

        client, ssh_cred = connect(args.host, ssh_creds)
        print(f"Connected to {args.host} as {ssh_cred.get('user')}")
        try:
            run_root_script(client, root_creds[0]["secret"], install_script(args.model))
        finally:
            client.close()
    finally:
        vault.lock()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
