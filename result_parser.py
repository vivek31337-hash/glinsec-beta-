"""
result_parser.py - Parse a garak JSONL report and display results in a
Rich-formatted terminal table.

Usage:
    python result_parser.py <path_to_report.jsonl>
"""

import json
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich import box


def parse_jsonl_report(report_path: Path) -> list[dict]:
    """
    Read every JSON line in the garak report and return a list of records
    with keys: probe, detector, passed.
    """
    if not report_path.exists():
        raise FileNotFoundError(f"Report file not found: {report_path}")

    records = []
    with report_path.open("r", encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, start=1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                entry = json.loads(raw)
            except json.JSONDecodeError as exc:
                print(f"[warn] Skipping malformed JSON on line {lineno}: {exc}")
                continue

            probe = entry.get("probe", entry.get("probe_classname", "unknown"))
            detector = entry.get("detector", entry.get("detector_name", "unknown"))
            passed = bool(entry.get("passed", entry.get("status") == "passed"))
            records.append({"probe": probe, "detector": detector, "passed": passed})

    return records


def display_rich_table(records: list[dict]) -> None:
    """Render the parsed records in a Rich-formatted terminal table."""
    console = Console()

    table = Table(
        title="GLinSec - Garak Security Scan Results",
        box=box.ROUNDED,
        show_lines=True,
        highlight=True,
    )
    table.add_column("Probe", style="cyan", no_wrap=True)
    table.add_column("Detector", style="magenta")
    table.add_column("Result", justify="center")

    vuln_count = 0
    for rec in records:
        if rec["passed"]:
            result_text = "[green]PASSED[/green]"
        else:
            result_text = "[red bold]VULNERABLE[/red bold]"
            vuln_count += 1
        table.add_row(rec["probe"], rec["detector"], result_text)

    console.print(table)

    total = len(records)
    passed = total - vuln_count
    console.print(f"\n[bold]Summary:[/bold] {total} tests — "
                  f"[green]{passed} passed[/green], "
                  f"[red]{vuln_count} vulnerabilities found[/red]\n")


def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <report.jsonl>")
        sys.exit(1)

    report_path = Path(sys.argv[1])
    try:
        records = parse_jsonl_report(report_path)
    except FileNotFoundError as exc:
        print(f"[ERROR] {exc}")
        sys.exit(1)

    if not records:
        print("No test records found in the report.")
        sys.exit(0)

    display_rich_table(records)


if __name__ == "__main__":
    main()
