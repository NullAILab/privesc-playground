# Privesc Playground

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)
![Tests](https://img.shields.io/badge/Tests-110%20passing-brightgreen)
![License](https://img.shields.io/badge/License-MIT-green)

Linux privilege escalation checker. Scans a live system for 22 escalation vectors — SUID/SGID abuse, sudo misconfigurations, dangerous Linux capabilities, Docker socket exposure, NFS no_root_squash, kernel CVEs, and more. Produces a prioritized report with exploit demos and remediation steps. No exploitation is performed — all checks are read-only.

---

## Example Output

```
════════════════════════════════════════════════════════════
  penNULL Privesc Checker — Scan Report
════════════════════════════════════════════════════════════
  Host   : prod-server-01
  User   : deploy
  Kernel : 5.4.0-42-generic

SUMMARY
  Total findings : 4
  Critical : 2
  High     : 1
  Medium   : 1
  Risk score     : 100 / 100 (CRITICAL)

[T13] 🔴 Dangerous Group Membership
  Severity : CRITICAL
  Category : Dangerous Group Membership
  Evidence :
    • Member of 'docker' group → docker run -v /:/host --rm -it alpine chroot /host /bin/bash
  Mitigation : Remove users from docker/lxd/disk groups unless strictly necessary.

[T03] 🔴 Sudo NOPASSWD GTFOBin
  Severity : CRITICAL
  Evidence :
    • NOPASSWD: /usr/bin/find — GTFOBins exploit: sudo find / -exec /bin/bash \;
  Mitigation : Remove NOPASSWD entries. Restrict sudo to specific commands.
```

---

## The 22 Techniques

| ID  | Technique | Severity |
|-----|-----------|----------|
| T01 | Dangerous SUID binary (GTFOBins) | CRITICAL |
| T02 | Custom SUID binary | HIGH |
| T03 | Sudo NOPASSWD + GTFOBin | CRITICAL |
| T04 | Unrestricted sudo (ALL) | HIGH |
| T05 | Sudo LD_PRELOAD preserved | CRITICAL |
| T06 | Wildcard in sudo rule | HIGH |
| T07 | Writable cron job / directory | HIGH |
| T08 | Writable directory in PATH | HIGH |
| T09 | World-writable sensitive file | CRITICAL |
| T10 | /etc/passwd writable | CRITICAL |
| T11 | /etc/shadow readable or writable | HIGH |
| T12 | Linux capability abuse (cap_setuid, cap_sys_admin…) | HIGH |
| T13 | Dangerous group membership (docker, lxd, disk…) | CRITICAL |
| T14 | Docker socket accessible | CRITICAL |
| T15 | Privileged container escape | CRITICAL |
| T16 | NFS no_root_squash | HIGH |
| T17 | Kernel LPE — known CVE signatures (DirtyCow, OverlayFS) | CRITICAL |
| T18 | SGID dangerous binary | MEDIUM |
| T19 | LD_PRELOAD in environment | MEDIUM |
| T20 | World-writable trusted directory | HIGH |
| T21 | Dot (.) in PATH | MEDIUM |
| T22 | Writable systemd service unit | HIGH |

Each finding includes: MITRE ATT&CK mapping, evidence from the live system, exploit demo (educational), and remediation command.

---

## Usage

```bash
pip install -r requirements.txt

# Scan the current system
python -m src

# JSON output (for SIEM integration)
python -m src --format json

# Save report to file
python -m src --format text --output report.txt

# No ANSI colors (for logging)
python -m src --no-color
```

---

## How It Works

```
Live System
    │
    ▼
collector.py  ─── read-only OS probes ──→  CheckContext
    │                                        (suid_files, sudo_entries,
    │                                         groups, capabilities, ...)
    ▼
scanner.py    ─── runs all 22 checks ──→  ScanReport
    │
    ▼
report.py     ─── console / text / JSON
```

Tests supply synthetic `CheckContext` objects directly — no real system needed.

---

## Tests

```bash
pytest tests/ -v
# 110 tests — all 22 techniques, scanner integration, report rendering
```

---

## Project Structure

```
src/
├── techniques.py   ← CheckContext + Finding + Technique dataclasses
├── checks.py       ← 22 check functions + technique registry
├── collector.py    ← Live system data collector (read-only)
├── scanner.py      ← Orchestrator
├── report.py       ← Console / text / JSON renderer
└── __main__.py     ← CLI entry point
tests/
└── test_privesc.py ← 110 tests
```

---

## References

- [GTFOBins](https://gtfobins.github.io/)
- [LinPEAS](https://github.com/carlospolop/PEASS-ng)
- [HackTricks — Linux Privesc](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
- MITRE ATT&CK: [T1548](https://attack.mitre.org/techniques/T1548/)

---

## License

MIT
