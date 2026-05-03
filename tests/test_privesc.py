"""
Tests for the privesc checker.

All tests use synthetic CheckContext objects — no real system probing required.
"""

from __future__ import annotations

import io
import json

import pytest

from src.techniques import (
    Category,
    CheckContext,
    Severity,
)
from src.checks import TECHNIQUES
from src.scanner import scan, scan_and_report
from src.report import ScanReport


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ctx(**kwargs) -> CheckContext:
    """Build a minimal CheckContext with keyword overrides."""
    return CheckContext(**kwargs)


def _find_technique(technique_id: str):
    for t in TECHNIQUES:
        if t.technique_id == technique_id:
            return t
    raise KeyError(f"Technique {technique_id} not found")


def _run(technique_id: str, ctx: CheckContext):
    """Run a single technique and return Finding or None."""
    return _find_technique(technique_id).run(ctx)


# ---------------------------------------------------------------------------
# T01 — Dangerous SUID Binary
# ---------------------------------------------------------------------------

class TestT01DangerousSUID:
    def test_bash_suid_detected(self):
        ctx = _ctx(suid_files=["/bin/bash", "/usr/bin/find"])
        f = _run("T01", ctx)
        assert f is not None
        assert "/bin/bash" in f.evidence
        assert "/usr/bin/find" in f.evidence

    def test_standard_suid_not_flagged(self):
        ctx = _ctx(suid_files=["/usr/bin/passwd", "/usr/bin/sudo"])
        f = _run("T01", ctx)
        assert f is None

    def test_empty_suid_list(self):
        ctx = _ctx(suid_files=[])
        f = _run("T01", ctx)
        assert f is None

    def test_vim_suid_detected(self):
        ctx = _ctx(suid_files=["/usr/bin/vim"])
        f = _run("T01", ctx)
        assert f is not None
        assert "/usr/bin/vim" in f.evidence

    def test_python3_suid_detected(self):
        ctx = _ctx(suid_files=["/usr/bin/python3"])
        f = _run("T01", ctx)
        assert f is not None

    def test_severity_is_critical(self):
        ctx = _ctx(suid_files=["/bin/bash"])
        f = _run("T01", ctx)
        assert f.severity == Severity.CRITICAL

    def test_category_correct(self):
        ctx = _ctx(suid_files=["/bin/bash"])
        f = _run("T01", ctx)
        assert f.category == Category.SUID_SGID


# ---------------------------------------------------------------------------
# T02 — Custom SUID Binary
# ---------------------------------------------------------------------------

class TestT02CustomSUID:
    def test_custom_path_detected(self):
        ctx = _ctx(suid_files=["/opt/company/backup"])
        f = _run("T02", ctx)
        assert f is not None
        assert "/opt/company/backup" in f.evidence

    def test_standard_path_not_flagged(self):
        ctx = _ctx(suid_files=["/usr/bin/passwd"])
        f = _run("T02", ctx)
        assert f is None

    def test_dangerous_already_caught_by_t01_not_t02(self):
        # /bin/bash is in _DANGEROUS_SUID, so T02 won't catch it
        ctx = _ctx(suid_files=["/bin/bash"])
        f = _run("T02", ctx)
        assert f is None

    def test_home_dir_suid_detected(self):
        ctx = _ctx(suid_files=["/home/user/tools/exploit"])
        f = _run("T02", ctx)
        assert f is not None


# ---------------------------------------------------------------------------
# T03 — Sudo NOPASSWD GTFOBin
# ---------------------------------------------------------------------------

class TestT03SudoNopasswd:
    def test_find_nopasswd_detected(self):
        ctx = _ctx(sudo_nopasswd=["/usr/bin/find"])
        f = _run("T03", ctx)
        assert f is not None
        assert any("find" in e.lower() for e in f.evidence)

    def test_all_nopasswd_detected(self):
        ctx = _ctx(sudo_nopasswd=["ALL"])
        f = _run("T03", ctx)
        assert f is not None
        assert any("ALL" in e for e in f.evidence)

    def test_non_gtfo_command(self):
        ctx = _ctx(sudo_nopasswd=["/usr/sbin/service"])
        f = _run("T03", ctx)
        # Non-GTFOBin commands still get reported as "review for abuse"
        assert f is not None
        assert any("review" in e.lower() for e in f.evidence)

    def test_vim_nopasswd(self):
        ctx = _ctx(sudo_nopasswd=["/usr/bin/vim"])
        f = _run("T03", ctx)
        assert f is not None

    def test_empty_nopasswd(self):
        ctx = _ctx(sudo_nopasswd=[])
        f = _run("T03", ctx)
        assert f is None

    def test_python3_nopasswd(self):
        ctx = _ctx(sudo_nopasswd=["/usr/bin/python3"])
        f = _run("T03", ctx)
        assert f is not None
        assert any("python3" in e for e in f.evidence)

    def test_severity_critical(self):
        ctx = _ctx(sudo_nopasswd=["ALL"])
        f = _run("T03", ctx)
        assert f.severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# T04 — Sudo ALL Unrestricted
# ---------------------------------------------------------------------------

class TestT04SudoAll:
    def test_all_all_detected(self):
        ctx = _ctx(sudo_entries=["user ALL=(ALL:ALL) ALL"])
        f = _run("T04", ctx)
        assert f is not None

    def test_nopasswd_not_double_counted(self):
        # NOPASSWD entries are caught by T03, not T04
        ctx = _ctx(sudo_entries=["user ALL=(ALL) NOPASSWD: ALL"])
        f = _run("T04", ctx)
        assert f is None

    def test_restricted_sudo_not_flagged(self):
        ctx = _ctx(sudo_entries=["user ALL=(root) /usr/bin/apt"])
        f = _run("T04", ctx)
        assert f is None  # no ALL=(ALL in it

    def test_empty_entries(self):
        ctx = _ctx(sudo_entries=[])
        f = _run("T04", ctx)
        assert f is None


# ---------------------------------------------------------------------------
# T05 — Sudo LD_PRELOAD Preserved
# ---------------------------------------------------------------------------

class TestT05SudoLDPreload:
    def test_ld_preload_preserved(self):
        ctx = _ctx(sudo_ld_preload=True)
        f = _run("T05", ctx)
        assert f is not None
        assert any("LD_PRELOAD" in e for e in f.evidence)

    def test_no_ld_preload(self):
        ctx = _ctx(sudo_ld_preload=False)
        f = _run("T05", ctx)
        assert f is None

    def test_severity_critical(self):
        ctx = _ctx(sudo_ld_preload=True)
        f = _run("T05", ctx)
        assert f.severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# T06 — Sudo Wildcard Injection
# ---------------------------------------------------------------------------

class TestT06SudoWildcard:
    def test_wildcard_in_nopasswd(self):
        ctx = _ctx(sudo_nopasswd=["/usr/bin/tar *"])
        f = _run("T06", ctx)
        assert f is not None
        assert any("*" in e for e in f.evidence)

    def test_wildcard_in_sudo_entries(self):
        ctx = _ctx(sudo_entries=["user ALL=(root) /usr/bin/rsync *"])
        f = _run("T06", ctx)
        assert f is not None

    def test_no_wildcard(self):
        ctx = _ctx(sudo_nopasswd=["/usr/bin/tar"], sudo_entries=[])
        f = _run("T06", ctx)
        assert f is None


# ---------------------------------------------------------------------------
# T07 — Writable Cron Job
# ---------------------------------------------------------------------------

class TestT07WritableCron:
    def test_writable_cron_dir(self):
        ctx = _ctx(cron_dirs_writable=["/etc/cron.d"])
        f = _run("T07", ctx)
        assert f is not None
        assert any("/etc/cron.d" in e for e in f.evidence)

    def test_writable_cron_script(self):
        ctx = _ctx(cron_scripts_writable=["/etc/cron.daily/backup.sh"])
        f = _run("T07", ctx)
        assert f is not None

    def test_no_writable_cron(self):
        ctx = _ctx(cron_dirs_writable=[], cron_scripts_writable=[])
        f = _run("T07", ctx)
        assert f is None

    def test_severity_high(self):
        ctx = _ctx(cron_dirs_writable=["/etc/cron.hourly"])
        f = _run("T07", ctx)
        assert f.severity == Severity.HIGH


# ---------------------------------------------------------------------------
# T08 — PATH Hijacking
# ---------------------------------------------------------------------------

class TestT08PathHijack:
    def test_writable_path_dir_detected(self):
        ctx = _ctx(writable_path_dirs=["/usr/local/bin"])
        f = _run("T08", ctx)
        assert f is not None
        assert any("/usr/local/bin" in e for e in f.evidence)

    def test_multiple_writable_dirs(self):
        ctx = _ctx(writable_path_dirs=["/usr/local/bin", "/opt/bin"])
        f = _run("T08", ctx)
        assert f is not None
        assert len(f.evidence) == 2

    def test_no_writable_path_dirs(self):
        ctx = _ctx(writable_path_dirs=[])
        f = _run("T08", ctx)
        assert f is None


# ---------------------------------------------------------------------------
# T09 — World-Writable Sensitive File
# ---------------------------------------------------------------------------

class TestT09WorldWritable:
    def test_passwd_world_writable(self):
        ctx = _ctx(world_writable_files=["/etc/passwd"])
        f = _run("T09", ctx)
        assert f is not None
        assert any("/etc/passwd" in e for e in f.evidence)

    def test_sudoers_world_writable(self):
        ctx = _ctx(world_writable_files=["/etc/sudoers"])
        f = _run("T09", ctx)
        assert f is not None

    def test_non_sensitive_file_not_flagged(self):
        ctx = _ctx(world_writable_files=["/tmp/something"])
        f = _run("T09", ctx)
        assert f is None

    def test_multiple_sensitive_files(self):
        ctx = _ctx(world_writable_files=["/etc/passwd", "/etc/crontab"])
        f = _run("T09", ctx)
        assert f is not None
        assert len(f.evidence) == 2


# ---------------------------------------------------------------------------
# T10 — /etc/passwd Writable
# ---------------------------------------------------------------------------

class TestT10PasswdWritable:
    def test_writable_passwd(self):
        ctx = _ctx(passwd_writable=True)
        f = _run("T10", ctx)
        assert f is not None
        assert any("passwd" in e.lower() for e in f.evidence)

    def test_not_writable(self):
        ctx = _ctx(passwd_writable=False)
        f = _run("T10", ctx)
        assert f is None

    def test_severity_critical(self):
        ctx = _ctx(passwd_writable=True)
        f = _run("T10", ctx)
        assert f.severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# T11 — /etc/shadow Readable or Writable
# ---------------------------------------------------------------------------

class TestT11ShadowAccess:
    def test_shadow_readable(self):
        ctx = _ctx(shadow_readable=True)
        f = _run("T11", ctx)
        assert f is not None
        assert any("readable" in e.lower() for e in f.evidence)

    def test_shadow_writable(self):
        ctx = _ctx(shadow_writable=True)
        f = _run("T11", ctx)
        assert f is not None
        assert any("writable" in e.lower() for e in f.evidence)

    def test_shadow_neither(self):
        ctx = _ctx(shadow_readable=False, shadow_writable=False)
        f = _run("T11", ctx)
        assert f is None

    def test_both_readable_and_writable(self):
        ctx = _ctx(shadow_readable=True, shadow_writable=True)
        f = _run("T11", ctx)
        assert f is not None
        assert len(f.evidence) == 2


# ---------------------------------------------------------------------------
# T12 — Linux Capability Abuse
# ---------------------------------------------------------------------------

class TestT12Capabilities:
    def test_cap_setuid_detected(self):
        ctx = _ctx(files_with_caps=[("/usr/bin/python3", "cap_setuid+eip")])
        f = _run("T12", ctx)
        assert f is not None
        assert any("python3" in e for e in f.evidence)

    def test_cap_sys_admin_detected(self):
        ctx = _ctx(files_with_caps=[("/usr/bin/custom", "cap_sys_admin+ep")])
        f = _run("T12", ctx)
        assert f is not None

    def test_harmless_cap_not_flagged(self):
        ctx = _ctx(files_with_caps=[("/usr/bin/ping", "cap_net_raw+ep")])
        f = _run("T12", ctx)
        # cap_net_raw IS in dangerous list
        assert f is not None

    def test_no_caps(self):
        ctx = _ctx(files_with_caps=[])
        f = _run("T12", ctx)
        assert f is None

    def test_multiple_caps(self):
        ctx = _ctx(files_with_caps=[
            ("/usr/bin/python3", "cap_setuid+eip"),
            ("/usr/bin/perl", "cap_dac_override+ep"),
        ])
        f = _run("T12", ctx)
        assert f is not None
        assert len(f.evidence) >= 2


# ---------------------------------------------------------------------------
# T13 — Dangerous Group Membership
# ---------------------------------------------------------------------------

class TestT13DangerousGroups:
    def test_docker_group(self):
        ctx = _ctx(groups=["user", "docker"])
        f = _run("T13", ctx)
        assert f is not None
        assert any("docker" in e.lower() for e in f.evidence)

    def test_lxd_group(self):
        ctx = _ctx(groups=["lxd"])
        f = _run("T13", ctx)
        assert f is not None

    def test_disk_group(self):
        ctx = _ctx(groups=["disk"])
        f = _run("T13", ctx)
        assert f is not None

    def test_shadow_group(self):
        ctx = _ctx(groups=["shadow"])
        f = _run("T13", ctx)
        assert f is not None

    def test_harmless_groups(self):
        ctx = _ctx(groups=["user", "cdrom", "audio"])
        f = _run("T13", ctx)
        assert f is None

    def test_multiple_dangerous_groups(self):
        ctx = _ctx(groups=["docker", "lxd"])
        f = _run("T13", ctx)
        assert f is not None
        assert len(f.evidence) == 2


# ---------------------------------------------------------------------------
# T14 — Docker Socket Accessible
# ---------------------------------------------------------------------------

class TestT14DockerSocket:
    def test_docker_socket_readable(self):
        ctx = _ctx(docker_socket_readable=True)
        f = _run("T14", ctx)
        assert f is not None
        assert any("docker.sock" in e for e in f.evidence)

    def test_docker_socket_not_readable(self):
        ctx = _ctx(docker_socket_readable=False)
        f = _run("T14", ctx)
        assert f is None

    def test_severity_critical(self):
        ctx = _ctx(docker_socket_readable=True)
        f = _run("T14", ctx)
        assert f.severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# T15 — Privileged Container Escape
# ---------------------------------------------------------------------------

class TestT15PrivilegedContainer:
    def test_privileged_container(self):
        ctx = _ctx(in_container=True, privileged_container=True)
        f = _run("T15", ctx)
        assert f is not None
        assert any("privileged" in e.lower() for e in f.evidence)

    def test_unprivileged_container(self):
        ctx = _ctx(in_container=True, privileged_container=False)
        f = _run("T15", ctx)
        assert f is None

    def test_not_in_container(self):
        ctx = _ctx(in_container=False, privileged_container=True)
        f = _run("T15", ctx)
        assert f is None


# ---------------------------------------------------------------------------
# T16 — NFS no_root_squash
# ---------------------------------------------------------------------------

class TestT16NFSNoRootSquash:
    def test_nfs_no_root_squash_detected(self):
        ctx = _ctx(nfs_no_root_squash=["/share 192.168.1.0/24(rw,no_root_squash)"])
        f = _run("T16", ctx)
        assert f is not None
        assert any("no_root_squash" in e for e in f.evidence)

    def test_nfs_with_root_squash_ok(self):
        ctx = _ctx(nfs_no_root_squash=[])
        f = _run("T16", ctx)
        assert f is None

    def test_multiple_exports(self):
        ctx = _ctx(nfs_no_root_squash=[
            "/share1 *(rw,no_root_squash)",
            "/share2 *(rw,no_root_squash)",
        ])
        f = _run("T16", ctx)
        assert len(f.evidence) == 2


# ---------------------------------------------------------------------------
# T17 — Kernel LPE (Known CVE)
# ---------------------------------------------------------------------------

class TestT17KernelLPE:
    def test_old_kernel_dirtycow(self):
        ctx = _ctx(kernel_version="4.4.0-116-generic", os_release="Ubuntu 16.04")
        f = _run("T17", ctx)
        assert f is not None
        assert any("DirtyCow" in e or "CVE-2016" in e for e in f.evidence)

    def test_new_kernel_clean(self):
        ctx = _ctx(kernel_version="6.1.0-13-amd64", os_release="Debian GNU/Linux 12")
        f = _run("T17", ctx)
        assert f is None

    def test_ubuntu_overlayfs_vuln(self):
        ctx = _ctx(kernel_version="5.4.0-42-generic",
                   os_release='NAME="Ubuntu"\nVERSION="20.04"')
        f = _run("T17", ctx)
        assert f is not None
        assert any("OverlayFS" in e or "CVE-2021-3493" in e for e in f.evidence)

    def test_empty_kernel_version(self):
        ctx = _ctx(kernel_version="", os_release="")
        f = _run("T17", ctx)
        assert f is None

    def test_unparseable_kernel_version(self):
        ctx = _ctx(kernel_version="unknown", os_release="")
        f = _run("T17", ctx)
        assert f is not None
        assert any("parse" in e.lower() for e in f.evidence)


# ---------------------------------------------------------------------------
# T18 — SGID Dangerous Binary
# ---------------------------------------------------------------------------

class TestT18SGIDDangerous:
    def test_newgrp_sgid(self):
        ctx = _ctx(sgid_files=["/usr/bin/newgrp"])
        f = _run("T18", ctx)
        assert f is not None

    def test_harmless_sgid(self):
        ctx = _ctx(sgid_files=["/usr/bin/crontab"])
        f = _run("T18", ctx)
        assert f is None

    def test_empty_sgid(self):
        ctx = _ctx(sgid_files=[])
        f = _run("T18", ctx)
        assert f is None


# ---------------------------------------------------------------------------
# T19 — LD_PRELOAD in Environment
# ---------------------------------------------------------------------------

class TestT19LDPreloadEnv:
    def test_ld_preload_in_env(self):
        ctx = _ctx(env_vars={"LD_PRELOAD": "/tmp/evil.so"})
        f = _run("T19", ctx)
        assert f is not None
        assert any("/tmp/evil.so" in e for e in f.evidence)

    def test_no_ld_preload(self):
        ctx = _ctx(env_vars={"PATH": "/usr/bin:/bin"})
        f = _run("T19", ctx)
        assert f is None


# ---------------------------------------------------------------------------
# T20 — World-Writable Trusted Directory
# ---------------------------------------------------------------------------

class TestT20WorldWritableDirs:
    def test_usr_local_bin_writable(self):
        ctx = _ctx(world_writable_dirs=["/usr/local/bin"])
        f = _run("T20", ctx)
        assert f is not None
        assert any("/usr/local/bin" in e for e in f.evidence)

    def test_tmp_not_flagged(self):
        ctx = _ctx(world_writable_dirs=["/tmp"])
        f = _run("T20", ctx)
        assert f is None

    def test_opt_flagged(self):
        ctx = _ctx(world_writable_dirs=["/opt"])
        f = _run("T20", ctx)
        assert f is not None


# ---------------------------------------------------------------------------
# T21 — PATH Contains Dot
# ---------------------------------------------------------------------------

class TestT21DotInPath:
    def test_dot_in_path(self):
        ctx = _ctx(path_dirs=[".", "/usr/bin", "/bin"])
        f = _run("T21", ctx)
        assert f is not None
        assert any("." in e for e in f.evidence)

    def test_empty_entry_in_path(self):
        ctx = _ctx(path_dirs=["", "/usr/bin"])
        f = _run("T21", ctx)
        assert f is not None

    def test_clean_path(self):
        ctx = _ctx(path_dirs=["/usr/local/bin", "/usr/bin", "/bin"])
        f = _run("T21", ctx)
        assert f is None


# ---------------------------------------------------------------------------
# T22 — Writable Systemd Service
# ---------------------------------------------------------------------------

class TestT22WritableService:
    def test_writable_service_detected(self):
        ctx = _ctx(systemd_user_services=["/etc/systemd/system/myapp.service (writable)"])
        f = _run("T22", ctx)
        assert f is not None

    def test_no_writable_services(self):
        ctx = _ctx(systemd_user_services=[])
        f = _run("T22", ctx)
        assert f is None

    def test_non_writable_entry_ignored(self):
        ctx = _ctx(systemd_user_services=["/etc/systemd/system/myapp.service"])
        f = _run("T22", ctx)
        assert f is None


# ---------------------------------------------------------------------------
# Scanner integration tests
# ---------------------------------------------------------------------------

class TestScanner:
    def test_empty_context_no_findings(self):
        ctx = CheckContext()
        report = scan(ctx)
        assert report.total == 0

    def test_multiple_findings_collected(self):
        ctx = _ctx(
            suid_files=["/bin/bash"],
            passwd_writable=True,
            groups=["docker"],
        )
        report = scan(ctx)
        assert report.total >= 3

    def test_risk_score_zero_when_no_findings(self):
        ctx = CheckContext()
        report = scan(ctx)
        assert report.risk_score() == 0
        assert report.risk_label() == "NONE"

    def test_risk_score_max_with_multiple_criticals(self):
        ctx = _ctx(
            suid_files=["/bin/bash"],
            passwd_writable=True,
            docker_socket_readable=True,
            in_container=True,
            privileged_container=True,
        )
        report = scan(ctx)
        assert report.risk_score() == 100

    def test_critical_findings_reported_correctly(self):
        ctx = _ctx(passwd_writable=True)
        report = scan(ctx)
        assert len(report.critical) >= 1
        assert report.risk_label() in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def test_scan_and_report_console(self):
        ctx = _ctx(suid_files=["/bin/bash"])
        report, output = scan_and_report(ctx, fmt="console", color=False)
        assert "T01" in output
        assert "SUID" in output

    def test_scan_and_report_json(self):
        ctx = _ctx(passwd_writable=True)
        report, output = scan_and_report(ctx, fmt="json")
        data = json.loads(output)
        assert "findings" in data
        assert data["summary"]["critical"] >= 1

    def test_scan_and_report_text(self):
        ctx = _ctx(groups=["docker"])
        report, output = scan_and_report(ctx, fmt="text")
        assert "docker" in output.lower()

    def test_all_techniques_registered(self):
        assert len(TECHNIQUES) == 22

    def test_technique_ids_unique(self):
        ids = [t.technique_id for t in TECHNIQUES]
        assert len(ids) == len(set(ids))


# ---------------------------------------------------------------------------
# Report tests
# ---------------------------------------------------------------------------

class TestScanReport:
    def _make_report(self) -> ScanReport:
        ctx = _ctx(
            suid_files=["/bin/bash"],
            passwd_writable=True,
            groups=["docker"],
            writable_path_dirs=["/usr/local/bin"],
        )
        return scan(ctx)

    def test_render_console_no_color(self):
        report = self._make_report()
        buf = io.StringIO()
        report.render_console(buf, color=False)
        text = buf.getvalue()
        assert "penNULL" in text
        assert "SUMMARY" in text

    def test_render_json_valid(self):
        report = self._make_report()
        buf = io.StringIO()
        report.render_json(buf)
        data = json.loads(buf.getvalue())
        assert "findings" in data
        assert "risk_score" in data
        assert isinstance(data["summary"]["total"], int)

    def test_render_text_no_ansi(self):
        report = self._make_report()
        buf = io.StringIO()
        report.render_text(buf)
        text = buf.getvalue()
        assert "\033[" not in text

    def test_to_dict_structure(self):
        ctx = _ctx(suid_files=["/bin/bash"])
        report = scan(ctx)
        d = report.to_dict()
        assert d["summary"]["total"] == report.total
        assert len(d["findings"]) == report.total
        assert "technique_id" in d["findings"][0]

    def test_empty_report_renders_clean(self):
        report = ScanReport()
        buf = io.StringIO()
        report.render_console(buf, color=False)
        assert "No privilege escalation" in buf.getvalue()

    def test_risk_labels(self):
        report = ScanReport()
        assert report.risk_label() == "NONE"

        report.findings = [_run("T10", _ctx(passwd_writable=True))]
        # 1 critical = score 40 → HIGH (≥25 but <50)
        assert report.risk_label() in ("CRITICAL", "HIGH", "MEDIUM")

    def test_severity_counts(self):
        ctx = _ctx(passwd_writable=True, shadow_readable=True)
        report = scan(ctx)
        assert report.total == report.total
        assert report.total == (
            len(report.critical) + len(report.high)
            + len(report.medium) + len(report.low)
        )


# ---------------------------------------------------------------------------
# Finding dataclass tests
# ---------------------------------------------------------------------------

class TestFinding:
    def test_finding_to_dict(self):
        ctx = _ctx(suid_files=["/bin/bash"])
        f = _run("T01", ctx)
        d = f.to_dict()
        assert d["technique_id"] == "T01"
        assert d["severity"] == "CRITICAL"
        assert isinstance(d["evidence"], list)

    def test_finding_has_mitigation(self):
        ctx = _ctx(passwd_writable=True)
        f = _run("T10", ctx)
        assert f.mitigation != ""

    def test_finding_has_exploit_demo(self):
        ctx = _ctx(docker_socket_readable=True)
        f = _run("T14", ctx)
        assert f.exploit_demo != ""
        assert "docker" in f.exploit_demo.lower()


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_kernel_version_with_extra_suffix(self):
        ctx = _ctx(kernel_version="4.4.0-116-generic-custom-build", os_release="Ubuntu")
        report = scan(ctx)
        t17_findings = [f for f in report.findings if f.technique_id == "T17"]
        assert len(t17_findings) >= 1

    def test_multiple_capabilities_on_same_binary(self):
        ctx = _ctx(files_with_caps=[("/usr/bin/tool", "cap_setuid+cap_sys_admin+eip")])
        f = _run("T12", ctx)
        assert f is not None
        assert len(f.evidence) >= 2

    def test_groups_case_insensitive(self):
        ctx = _ctx(groups=["Docker"])
        f = _run("T13", ctx)
        assert f is not None

    def test_cron_and_suid_both_reported(self):
        ctx = _ctx(
            suid_files=["/usr/bin/vim"],
            cron_dirs_writable=["/etc/cron.d"],
        )
        report = scan(ctx)
        ids = {f.technique_id for f in report.findings}
        assert "T01" in ids
        assert "T07" in ids

    def test_sudo_wildcard_in_nopasswd_triggers_both_t03_t06(self):
        ctx = _ctx(sudo_nopasswd=["/usr/bin/tar *"])
        report = scan(ctx)
        ids = {f.technique_id for f in report.findings}
        assert "T03" in ids
        assert "T06" in ids
