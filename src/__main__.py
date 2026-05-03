"""
CLI entry point.

Usage:
    python -m src [--format console|text|json] [--no-color]
    python -m src --help
"""

from __future__ import annotations

import argparse
import sys


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="privesc-checker",
        description="penNULL Privesc Checker — detect Linux privilege escalation vectors",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["console", "text", "json"],
        default="console",
        help="Output format (default: console)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in console output",
    )
    parser.add_argument(
        "--output", "-o",
        help="Write report to file instead of stdout",
    )
    args = parser.parse_args()

    # Import here so tests can import __main__ without triggering collection
    from .collector import collect
    from .scanner import scan

    ctx = collect()
    report = scan(ctx)

    import io
    buf = io.StringIO()
    if args.format == "json":
        report.render_json(buf)
    elif args.format == "text":
        report.render_text(buf)
    else:
        report.render_console(buf, color=not args.no_color)

    output = buf.getvalue()

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(output)
            print(f"Report written to: {args.output}", file=sys.stderr)
        except OSError as e:
            print(f"Error writing file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        sys.stdout.write(output)

    # Exit 1 if critical findings
    if report.critical:
        sys.exit(1)


if __name__ == "__main__":
    main()
