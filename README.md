# Privesc Playground

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Tests](https://img.shields.io/badge/Tests-110%20passing-brightgreen)

A Linux privilege escalation checker — detects 22 escalation vectors including SUID/SGID abuse, sudo misconfigurations, dangerous Linux capabilities, Docker socket exposure, NFS no_root_squash, kernel CVEs, and more.

---

## How It Works

The tool builds a snapshot of the system state (SUID files, sudo rules, group memberships, writable paths, capabilities, etc.) and runs every technique check against it. No exploitation is performed — checks are read-only and produce a prioritized finding report.

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
| T17 | Kernel LPE — known CVE signatures | CRITICAL |
| T18 | SGID dangerous binary | MEDIUM |
| T19 | LD_PRELOAD in environment | MEDIUM |
| T20 | World-writable trusted directory | HIGH |
| T21 | Dot (.) in PATH | MEDIUM |
| T22 | Writable systemd service unit | HIGH |

---

## Usage

```bash
pip install -r requirements.txt

# Scan the current system
python -m src

# JSON output
python -m src --format json

# Save report to file
python -m src --format text --output report.txt

# No color
python -m src --no-color
```

---

## Output Formats

| Format | Description |
|--------|-------------|
| `console` | ANSI-colored terminal output (default) |
| `text` | Plain text, no ANSI codes |
| `json` | Machine-readable structured findings |

---

## Tests

```bash
pytest tests/ -v
# 110 tests covering all 22 techniques
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
└── test_privesc.py ← 110 tests (synthetic contexts, no real system calls)
```

---

## References

- [GTFOBins](https://gtfobins.github.io/)
- [LinPEAS](https://github.com/carlospolop/PEASS-ng)
- [HackTricks — Linux Privesc](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
- MITRE ATT&CK: [T1548 — Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/)

---

## License

MIT
