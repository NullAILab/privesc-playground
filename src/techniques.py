"""
Privilege escalation technique definitions.

Each technique describes a Linux privesc vector: what condition to check,
MITRE ATT&CK mapping, severity, blue-team detection notes, and a simulated
exploit demonstration string.  No real exploitation is performed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable


class Severity(str, Enum):
    CRITICAL = "CRITICAL"  # direct root without password
    HIGH = "HIGH"          # likely root with minor pre-condition
    MEDIUM = "MEDIUM"      # root possible under specific circumstances
    LOW = "LOW"            # limited impact or hard to exploit


class Category(str, Enum):
    SUID_SGID = "SUID/SGID"
    SUDO = "Sudo Misconfiguration"
    CAPABILITIES = "Linux Capabilities"
    CRON = "Cron Job Abuse"
    PATH = "PATH / Environment Hijacking"
    WRITABLE = "Writable File / Directory"
    GROUP = "Dangerous Group Membership"
    KERNEL = "Kernel / OS Exploit"
    CONTAINER = "Container Escape"
    SERVICE = "Service Misconfiguration"
    NFS = "NFS Misconfiguration"


@dataclass
class Finding:
    """A discovered privilege escalation opportunity."""

    technique_id: str
    name: str
    category: Category
    severity: Severity
    description: str
    evidence: list[str] = field(default_factory=list)
    exploit_demo: str = ""
    mitigation: str = ""
    mitre_technique: str = ""
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "category": self.category.value,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "exploit_demo": self.exploit_demo,
            "mitigation": self.mitigation,
            "mitre_technique": self.mitre_technique,
            "references": self.references,
        }


@dataclass
class Technique:
    """A registered technique with its check function."""

    technique_id: str
    name: str
    category: Category
    severity: Severity
    description: str
    check: Callable[["CheckContext"], list[str]]  # returns evidence items
    exploit_demo: str
    mitigation: str
    mitre_technique: str = ""
    references: list[str] = field(default_factory=list)

    def run(self, ctx: "CheckContext") -> Finding | None:
        """Run check; return Finding if evidence found, else None."""
        evidence = self.check(ctx)
        if not evidence:
            return None
        return Finding(
            technique_id=self.technique_id,
            name=self.name,
            category=self.category,
            severity=self.severity,
            description=self.description,
            evidence=evidence,
            exploit_demo=self.exploit_demo,
            mitigation=self.mitigation,
            mitre_technique=self.mitre_technique,
            references=self.references,
        )


@dataclass
class CheckContext:
    """
    Snapshot of the system state passed to each technique check.

    All fields are plain data (lists, dicts, strings) so the checker can
    be tested with synthetic data without touching a real filesystem.
    """

    # --- identity ---
    current_user: str = ""
    current_uid: int = 1000
    current_gid: int = 1000
    groups: list[str] = field(default_factory=list)

    # --- filesystem snapshots ---
    suid_files: list[str] = field(default_factory=list)      # paths with SUID bit
    sgid_files: list[str] = field(default_factory=list)      # paths with SGID bit
    world_writable_dirs: list[str] = field(default_factory=list)
    world_writable_files: list[str] = field(default_factory=list)
    path_dirs: list[str] = field(default_factory=list)       # entries in $PATH
    writable_path_dirs: list[str] = field(default_factory=list)

    # --- sudo ---
    sudo_entries: list[str] = field(default_factory=list)    # raw sudoers lines for user
    sudo_nopasswd: list[str] = field(default_factory=list)   # NOPASSWD commands
    sudo_env_keep: list[str] = field(default_factory=list)   # env_keep vars
    sudo_ld_preload: bool = False

    # --- cron ---
    cron_jobs: list[str] = field(default_factory=list)       # crontab -l lines
    cron_dirs_writable: list[str] = field(default_factory=list)
    cron_scripts_writable: list[str] = field(default_factory=list)

    # --- capabilities ---
    files_with_caps: list[tuple[str, str]] = field(default_factory=list)  # (path, caps)

    # --- special groups ---
    # Checked via self.groups against known dangerous groups
    # docker, lxd, disk, adm, shadow, sudo, wheel, etc.

    # --- NFS ---
    nfs_exports: list[str] = field(default_factory=list)     # /etc/exports lines
    nfs_no_root_squash: list[str] = field(default_factory=list)

    # --- kernel ---
    kernel_version: str = ""
    os_release: str = ""

    # --- docker / container ---
    docker_socket_readable: bool = False
    in_container: bool = False
    privileged_container: bool = False

    # --- /etc/passwd / shadow ---
    passwd_writable: bool = False
    shadow_readable: bool = False
    shadow_writable: bool = False

    # --- services ---
    systemd_user_services: list[str] = field(default_factory=list)

    # --- environment ---
    env_vars: dict[str, str] = field(default_factory=dict)
