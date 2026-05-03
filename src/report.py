"""
Report generation for privesc checker results.

Produces console (ANSI), plain-text, and JSON output formats.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import IO

from .techniques import Finding, Severity

# ANSI color codes
_RESET = "\033[0m"
_BOLD = "\033[1m"
_RED = "\033[91m"
_YELLOW = "\033[93m"
_CYAN = "\033[96m"
_GREEN = "\033[92m"
_DIM = "\033[2m"

_SEVERITY_COLOR = {
    Severity.CRITICAL: _RED,
    Severity.HIGH: _YELLOW,
    Severity.MEDIUM: _CYAN,
    Severity.LOW: _GREEN,
}

_SEVERITY_ICON = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🟢",
}


@dataclass
class ScanReport:
    """Container for all findings from a scan."""

    findings: list[Finding] = field(default_factory=list)
    scanned_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    host: str = "localhost"
    kernel_version: str = ""
    current_user: str = ""

    # ------------------------------------------------------------------ stats

    @property
    def critical(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.CRITICAL]

    @property
    def high(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.HIGH]

    @property
    def medium(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.MEDIUM]

    @property
    def low(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.LOW]

    @property
    def total(self) -> int:
        return len(self.findings)

    def risk_score(self) -> int:
        """Simple weighted risk score (0–100)."""
        score = (
            len(self.critical) * 40
            + len(self.high) * 20
            + len(self.medium) * 8
            + len(self.low) * 2
        )
        return min(score, 100)

    def risk_label(self) -> str:
        s = self.risk_score()
        if s >= 80:
            return "CRITICAL"
        if s >= 50:
            return "HIGH"
        if s >= 25:
            return "MEDIUM"
        if s > 0:
            return "LOW"
        return "NONE"

    # ------------------------------------------------------------------ output

    def render_console(self, out: IO[str], color: bool = True) -> None:
        """Write a human-readable console report."""

        def c(code: str, text: str) -> str:
            return f"{code}{text}{_RESET}" if color else text

        banner = "=" * 60
        out.write(c(_BOLD, banner) + "\n")
        out.write(c(_BOLD, "  penNULL Privesc Checker — Scan Report") + "\n")
        out.write(c(_BOLD, banner) + "\n")
        out.write(f"  Host   : {self.host}\n")
        out.write(f"  User   : {self.current_user}\n")
        out.write(f"  Kernel : {self.kernel_version}\n")
        out.write(f"  Time   : {self.scanned_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
        out.write(c(_BOLD, banner) + "\n\n")

        if not self.findings:
            out.write(c(_GREEN, "  No privilege escalation vectors detected.\n"))
            return

        # Summary
        out.write(c(_BOLD, "SUMMARY\n"))
        out.write(f"  Total findings : {self.total}\n")
        out.write(f"  {c(_RED, 'Critical')} : {len(self.critical)}\n")
        out.write(f"  {c(_YELLOW, 'High')}     : {len(self.high)}\n")
        out.write(f"  {c(_CYAN, 'Medium')}   : {len(self.medium)}\n")
        out.write(f"  {c(_GREEN, 'Low')}      : {len(self.low)}\n")
        out.write(
            f"  Risk score     : {c(_BOLD, str(self.risk_score()))} / 100 "
            f"({c(_BOLD, self.risk_label())})\n\n"
        )

        # Findings — sort by severity
        _order = {Severity.CRITICAL: 0, Severity.HIGH: 1,
                  Severity.MEDIUM: 2, Severity.LOW: 3}
        sorted_findings = sorted(self.findings, key=lambda f: _order[f.severity])

        for finding in sorted_findings:
            sev_color = _SEVERITY_COLOR[finding.severity]
            icon = _SEVERITY_ICON[finding.severity]
            out.write(
                c(_BOLD, f"[{finding.technique_id}] {icon} {finding.name}") + "\n"
            )
            out.write(
                f"  Severity : {c(sev_color, finding.severity.value)}\n"
            )
            out.write(f"  Category : {finding.category.value}\n")
            out.write(f"  MITRE    : {finding.mitre_technique or 'N/A'}\n")
            out.write(f"  Detail   : {finding.description}\n")

            if finding.evidence:
                out.write("  Evidence :\n")
                for ev in finding.evidence:
                    out.write(f"    • {ev}\n")

            if finding.exploit_demo:
                out.write(c(_DIM, "  Exploit Demo (educational):\n"))
                for line in finding.exploit_demo.splitlines():
                    out.write(c(_DIM, f"    {line}\n"))

            if finding.mitigation:
                out.write(c(_GREEN, f"  Mitigation : {finding.mitigation}\n"))

            if finding.references:
                out.write("  References :\n")
                for ref in finding.references:
                    out.write(f"    → {ref}\n")

            out.write("\n")

        out.write(c(_BOLD, "=" * 60) + "\n")

    def render_text(self, out: IO[str]) -> None:
        """Plain-text (no ANSI) version."""
        self.render_console(out, color=False)

    def to_dict(self) -> dict:
        return {
            "scanned_at": self.scanned_at.isoformat(),
            "host": self.host,
            "kernel_version": self.kernel_version,
            "current_user": self.current_user,
            "risk_score": self.risk_score(),
            "risk_label": self.risk_label(),
            "summary": {
                "total": self.total,
                "critical": len(self.critical),
                "high": len(self.high),
                "medium": len(self.medium),
                "low": len(self.low),
            },
            "findings": [f.to_dict() for f in self.findings],
        }

    def render_json(self, out: IO[str], indent: int = 2) -> None:
        json.dump(self.to_dict(), out, indent=indent)
        out.write("\n")
