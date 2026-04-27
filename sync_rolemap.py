#!/usr/bin/env python3
"""Sync the canonical role map to every reachable machine.

This script treats config/rolemap.json as the source of truth and writes:
  - config/rolemap.hosts in the repo
  - config/rolemap.ssh_config in the repo
  - /etc/rolemap.json on each target
  - /etc/rolemap.hosts on each target
  - /etc/rolemap.ssh_config on each target
  - a canonical rolemap block in ~/.ssh/config on each target

It intentionally does not rewrite /etc/hosts; that remains a separate step.
"""

from __future__ import annotations

import json
import shlex
import subprocess
import sys
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent
CONFIG_DIR = REPO_DIR / "config"
ROLEMAP_JSON = CONFIG_DIR / "rolemap.json"
ROLEMAP_HOSTS = CONFIG_DIR / "rolemap.hosts"
ROLEMAP_SSH_CONFIG = CONFIG_DIR / "rolemap.ssh_config"

# Access CredVault from the local repo without requiring package installation.
sys.path.insert(0, str(REPO_DIR))
from creds import CredVault  # noqa: E402


def render_hosts_fragment(rolemap: dict) -> str:
    lines = ["# >>> rolemap"]
    for host in rolemap["hosts"]:
        lines.append(f'{host["ip"]:<15} {host["name"]}')
    lines.append("# <<< rolemap")
    return "\n".join(lines) + "\n"


def render_ssh_fragment(rolemap: dict) -> str:
    lines = ["# >>> rolemap"]
    for host in rolemap["hosts"]:
        lines.extend(
            [
                f'Host {host["name"]}',
                f'    HostName {host["ip"]}',
                f'    User {host["ssh_user"]}',
                "    IdentityFile ~/.ssh/netwatch_id_ed25519",
                "    StrictHostKeyChecking accept-new",
                "    UserKnownHostsFile ~/.ssh/known_hosts",
            ]
        )
    lines.append("# <<< rolemap")
    return "\n".join(lines) + "\n"


def load_rolemap() -> dict:
    return json.loads(ROLEMAP_JSON.read_text())


def write_generated_hosts(rolemap: dict) -> str:
    fragment = render_hosts_fragment(rolemap)
    ROLEMAP_HOSTS.write_text(fragment)
    return fragment


def write_generated_ssh_config(rolemap: dict) -> str:
    fragment = render_ssh_fragment(rolemap)
    ROLEMAP_SSH_CONFIG.write_text(fragment)
    return fragment


def update_local_ssh_config(ssh_payload: str) -> None:
    ssh_config = Path.home() / ".ssh" / "config"
    ssh_config.parent.mkdir(parents=True, exist_ok=True)
    text = ssh_config.read_text() if ssh_config.exists() else ""
    start = "# >>> rolemap\n"
    end = "# <<< rolemap\n"

    if start in text and end in text:
        pre = text.split(start, 1)[0].rstrip("\n")
        post = text.split(end, 1)[1].lstrip("\n")
        merged = pre + ("\n\n" if pre else "") + ssh_payload.rstrip("\n") + "\n"
        if post:
            merged += "\n" + post
    else:
        merged = text.rstrip("\n")
        if merged:
            merged += "\n\n"
        merged += ssh_payload

    ssh_config.write_text(merged if merged.endswith("\n") else merged + "\n")
    subprocess.run(["chmod", "600", str(ssh_config)], check=True)


def run_local_install(json_payload: str, hosts_payload: str, ssh_payload: str) -> None:
    tmp_json = Path("/tmp/rolemap.json")
    tmp_hosts = Path("/tmp/rolemap.hosts")
    tmp_ssh = Path("/tmp/rolemap.ssh_config")
    tmp_json.write_text(json_payload)
    tmp_hosts.write_text(hosts_payload)
    tmp_ssh.write_text(ssh_payload)
    subprocess.run(["sudo", "cp", str(tmp_json), "/etc/rolemap.json"], check=True)
    subprocess.run(["sudo", "cp", str(tmp_hosts), "/etc/rolemap.hosts"], check=True)
    subprocess.run(["sudo", "cp", str(tmp_ssh), "/etc/rolemap.ssh_config"], check=True)
    subprocess.run(
        ["sudo", "chmod", "644", "/etc/rolemap.json", "/etc/rolemap.hosts", "/etc/rolemap.ssh_config"],
        check=True,
    )
    update_local_ssh_config(ssh_payload)


def ssh_base_cmd(user: str, ip: str, cred: dict) -> list[str]:
    if cred.get("type") == "key_path":
        return [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=8",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-i",
            cred["secret"],
            f"{user}@{ip}",
        ]
    if cred.get("type") == "password":
        return [
            "sshpass",
            "-p",
            cred["secret"],
            "ssh",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "ConnectTimeout=8",
            f"{user}@{ip}",
        ]
    raise ValueError(f"Unsupported credential type: {cred.get('type')}")


def push_file(user: str, ip: str, cred: dict, dest: str, content: str) -> None:
    quoted_dest = shlex.quote(dest)
    cmd = ssh_base_cmd(user, ip, cred) + [f"cat > {quoted_dest}"]
    proc = subprocess.run(cmd, input=content, text=True, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout).strip() or f"write failed for {user}@{ip}:{dest}")


def remote_install(
    user: str,
    ip: str,
    cred: dict,
    platform: str,
    json_payload: str,
    hosts_payload: str,
    ssh_payload: str,
) -> None:
    push_file(user, ip, cred, "/tmp/rolemap.json", json_payload)
    push_file(user, ip, cred, "/tmp/rolemap.hosts", hosts_payload)
    push_file(user, ip, cred, "/tmp/rolemap.ssh_config", ssh_payload)

    if user == "root":
        install_cmd = (
            "cp /tmp/rolemap.json /etc/rolemap.json && "
            "cp /tmp/rolemap.hosts /etc/rolemap.hosts && "
            "cp /tmp/rolemap.ssh_config /etc/rolemap.ssh_config && "
            "chmod 644 /etc/rolemap.json /etc/rolemap.hosts /etc/rolemap.ssh_config"
        )
    elif platform == "darwin":
        # Use the login password as the sudo password.
        password = shlex.quote(cred["secret"])
        install_cmd = (
            f"echo {password} | sudo -S cp /tmp/rolemap.json /etc/rolemap.json && "
            f"echo {password} | sudo -S cp /tmp/rolemap.hosts /etc/rolemap.hosts && "
            f"echo {password} | sudo -S cp /tmp/rolemap.ssh_config /etc/rolemap.ssh_config && "
            f"echo {password} | sudo -S chmod 644 /etc/rolemap.json /etc/rolemap.hosts /etc/rolemap.ssh_config"
        )
    else:
        install_cmd = (
            "sudo cp /tmp/rolemap.json /etc/rolemap.json && "
            "sudo cp /tmp/rolemap.hosts /etc/rolemap.hosts && "
            "sudo cp /tmp/rolemap.ssh_config /etc/rolemap.ssh_config && "
            "sudo chmod 644 /etc/rolemap.json /etc/rolemap.hosts /etc/rolemap.ssh_config"
        )

    proc = subprocess.run(ssh_base_cmd(user, ip, cred) + [install_cmd], text=True, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout).strip() or f"install failed for {user}@{ip}")

    update_cmd = (
        "python3 - <<'INNER'\n"
        "from pathlib import Path\n"
        "import subprocess\n"
        "ssh_cfg = Path.home() / '.ssh' / 'config'\n"
        "ssh_cfg.parent.mkdir(parents=True, exist_ok=True)\n"
        "text = ssh_cfg.read_text() if ssh_cfg.exists() else ''\n"
        "payload = Path('/etc/rolemap.ssh_config').read_text()\n"
        "start = '# >>> rolemap\\n'\n"
        "end = '# <<< rolemap\\n'\n"
        "if start in text and end in text:\n"
        "    pre = text.split(start, 1)[0].rstrip('\\n')\n"
        "    post = text.split(end, 1)[1].lstrip('\\n')\n"
        "    merged = pre + ('\\n\\n' if pre else '') + payload.rstrip('\\n') + '\\n'\n"
        "    if post:\n"
        "        merged += '\\n' + post\n"
        "else:\n"
        "    merged = text.rstrip('\\n')\n"
        "    if merged:\n"
        "        merged += '\\n\\n'\n"
        "    merged += payload\n"
        "ssh_cfg.write_text(merged if merged.endswith('\\n') else merged + '\\n')\n"
        "subprocess.run(['chmod', '600', str(ssh_cfg)], check=True)\n"
        "print('ssh-config-updated')\n"
        "INNER"
    )
    proc = subprocess.run(ssh_base_cmd(user, ip, cred) + [update_cmd], text=True, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout).strip() or f"ssh config update failed for {user}@{ip}")


def pick_credential(vault: CredVault, ip: str, user: str) -> dict:
    creds = vault.get(ip, "ssh")
    for cred in creds:
        if cred.get("user") == user:
            return cred
    raise RuntimeError(f"No SSH credential found for {user}@{ip}")


def main() -> int:
    rolemap = load_rolemap()
    hosts_fragment = write_generated_hosts(rolemap)
    ssh_fragment = write_generated_ssh_config(rolemap)
    json_payload = json.dumps(rolemap, indent=2) + "\n"

    vault = CredVault()
    if not vault.unlock():
        print("vault unlock failed", file=sys.stderr)
        return 1

    try:
        run_local_install(json_payload, hosts_fragment, ssh_fragment)
        print("[local] ok -> /etc/rolemap.json /etc/rolemap.hosts /etc/rolemap.ssh_config / ~/.ssh/config")

        for host in rolemap["hosts"]:
            user = host["ssh_user"]
            ip = host["ip"]
            platform = host["platform"]
            cred = pick_credential(vault, ip, user)
            remote_install(user, ip, cred, platform, json_payload, hosts_fragment, ssh_fragment)
            print(f'[{host["name"]}] ok -> /etc/rolemap.json /etc/rolemap.hosts /etc/rolemap.ssh_config / ~/.ssh/config')
    finally:
        vault.lock()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
