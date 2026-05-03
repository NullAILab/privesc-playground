"""privesc_playground — Linux privilege escalation checker."""
from .scanner import scan, scan_and_report
from .techniques import CheckContext, Finding, Severity, Category

__all__ = ["scan", "scan_and_report", "CheckContext", "Finding", "Severity", "Category"]
