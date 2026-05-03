"""
System information collector.

Gathers real system state into a CheckContext by running read-only OS
commands.  All collection is non-destructive and requires no elevated
privileges.  Falls back gracefully when commands are unavailable.

This module is deliberately NOT imported in tests — tests supply synthetic
CheckContext objects directly to avoid requiring a Linux environment.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

from .techniques import CheckContext


def _run(cmd: list[str], timeout: int = 5) -> str:
    """Run a command and return stdout; empty string on any error."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout
    except Exception:
        return ""


def _is_writable(path: str) -> bool:
    return os.access(path, os.W_OK)


def collect() -> CheckContext:
    """Collect live system data into a CheckContext."""
    ctx = CheckContext()

    # --- Identity ---
    ctx.current_uid = os.getuid()
    ctx.current_gid = os.getgid()
    ctx.current_user = os.environ.get("USER", _run(["whoami"]).strip())
    groups_out = _run(["id", "-Gn"])
    ctx.groups = groups_out.split() if groups_out else []

    # --- Environment ---
    ctx.env_vars = dict(os.environ)
    ctx.path_dirs = os.environ.get("PATH", "").split(":")

    # --- Writable PATH dirs ---
    ctx.writable_path_dirs = [d for d in ctx.path_dirs if d and _is_writable(d)]

    # --- SUID/SGID files ---
    suid_raw = _run(["find", "/", "-perm", "-u=s", "-type", "f", "2>/dev/null"])
    ctx.suid_files = [l.strip() for l in suid_raw.splitlines() if l.strip()]

    sgid_raw = _run(["find", "/", "-perm", "-g=s", "-type", "f", "2>/dev/null"])
    ctx.sgid_files = [l.strip() for l in sgid_raw.splitlines() if l.strip()]

    # --- World-writable ---
    ww_raw = _run([
        "find", "/etc", "/usr/local", "/opt", "/srv",
        "-writable", "-type", "f", "2>/dev/null"
    ])
    ctx.world_writable_files = [l.strip() for l in ww_raw.splitlines() if l.strip()]

    wwd_raw = _run([
        "find", "/usr/local", "/opt", "/srv", "/var/www",
        "-writable", "-type", "d", "2>/dev/null"
    ])
    ctx.world_writable_dirs = [l.strip() for l in wwd_raw.splitlines() if l.strip()]

    # --- Sudo ---
    sudo_out = _run(["sudo", "-l", "-n"])  # -n = non-interactive (no password prompt)
    ctx.sudo_entries = [l.strip() for l in sudo_out.splitlines() if l.strip()]
    ctx.sudo_nopasswd = []
    for line in ctx.sudo_entries:
        if "NOPASSWD" in line:
            # extract command part after NOPASSWD:
            m = re.search(r"NOPASSWD:\s*(.+)", line)
            if m:
                ctx.sudo_nopasswd.append(m.group(1).strip())
    ctx.sudo_ld_preload = "LD_PRELOAD" in sudo_out

    # --- Cron ---
    cron_raw = _run(["crontab", "-l"])
    ctx.cron_jobs = [l for l in cron_raw.splitlines() if l.strip() and not l.startswith("#")]
    ctx.cron_dirs_writable = [
        d for d in ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
                    "/etc/cron.weekly", "/etc/cron.monthly"]
        if Path(d).exists() and _is_writable(d)
    ]
    # Writable scripts referenced in cron jobs
    ctx.cron_scripts_writable = []
    for job in ctx.cron_jobs:
        parts = job.split()
        if len(parts) >= 6:
            script = parts[5]
            if Path(script).exists() and _is_writable(script):
                ctx.cron_scripts_writable.append(script)

    # --- Capabilities ---
    caps_raw = _run(["getcap", "-r", "/", "2>/dev/null"])
    ctx.files_with_caps = []
    for line in caps_raw.splitlines():
        parts = line.strip().rsplit(" = ", 1)
        if len(parts) == 2:
            ctx.files_with_caps.append((parts[0].strip(), parts[1].strip()))

    # --- NFS ---
    if Path("/etc/exports").exists():
        try:
            exports = Path("/etc/exports").read_text(errors="replace")
            ctx.nfs_exports = exports.splitlines()
            ctx.nfs_no_root_squash = [
                l for l in ctx.nfs_exports
                if l.strip() and not l.startswith("#") and "no_root_squash" in l
            ]
        except PermissionError:
            pass

    # --- Kernel ---
    ctx.kernel_version = _run(["uname", "-r"]).strip()
    try:
        ctx.os_release = Path("/etc/os-release").read_text(errors="replace")
    except Exception:
        ctx.os_release = ""

    # --- Docker socket ---
    sock = Path("/var/run/docker.sock")
    ctx.docker_socket_readable = sock.exists() and os.access(str(sock), os.R_OK)

    # --- Container detection ---
    ctx.in_container = Path("/.dockerenv").exists() or Path("/run/.containerenv").exists()
    if ctx.in_container:
        # Check if privileged by attempting to read /proc/1/status
        try:
            status = Path("/proc/1/status").read_text(errors="replace")
            cap_bnd = re.search(r"CapBnd:\s+([0-9a-f]+)", status)
            if cap_bnd:
                # All caps = ffffffffffffffff in privileged container
                ctx.privileged_container = cap_bnd.group(1).lower() == "ffffffffffffffff"
        except Exception:
            pass

    # --- /etc/passwd and shadow ---
    ctx.passwd_writable = _is_writable("/etc/passwd")
    shadow = Path("/etc/shadow")
    ctx.shadow_readable = shadow.exists() and os.access(str(shadow), os.R_OK)
    ctx.shadow_writable = shadow.exists() and _is_writable(str(shadow))

    # --- systemd user services ---
    service_dirs = [
        "/etc/systemd/system",
        "/usr/lib/systemd/system",
        f"/home/{ctx.current_user}/.config/systemd/user",
    ]
    ctx.systemd_user_services = []
    for d in service_dirs:
        p = Path(d)
        if not p.exists():
            continue
        for sf in p.glob("*.service"):
            if _is_writable(str(sf)):
                ctx.systemd_user_services.append(f"{sf} (writable)")

    return ctx
