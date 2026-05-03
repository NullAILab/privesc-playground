"""
Main scanner orchestrator.

Runs all registered techniques against a CheckContext and returns a ScanReport.
"""

from __future__ import annotations

import socket
from datetime import datetime, timezone

from .checks import TECHNIQUES
from .report import ScanReport
from .techniques import CheckContext, Finding


def scan(ctx: CheckContext) -> ScanReport:
    """
    Run all technique checks against the provided context.

    Returns a ScanReport with all findings.
    """
    findings: list[Finding] = []

    for technique in TECHNIQUES:
        finding = technique.run(ctx)
        if finding is not None:
            findings.append(finding)

    try:
        host = socket.gethostname()
    except Exception:
        host = "unknown"

    return ScanReport(
        findings=findings,
        scanned_at=datetime.now(timezone.utc),
        host=host,
        kernel_version=ctx.kernel_version,
        current_user=ctx.current_user,
    )


def scan_and_report(ctx: CheckContext, fmt: str = "console",
                    color: bool = True) -> tuple[ScanReport, str]:
    """
    Convenience: scan + render to string.

    fmt: 'console' | 'text' | 'json'
    Returns (report, rendered_string)
    """
    import io
    report = scan(ctx)
    buf = io.StringIO()
    if fmt == "json":
        report.render_json(buf)
    elif fmt == "text":
        report.render_text(buf)
    else:
        report.render_console(buf, color=color)
    return report, buf.getvalue()
