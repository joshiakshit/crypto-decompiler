from __future__ import annotations

import sys
from pathlib import Path

import click

from . import __version__
from .analyzer import scan as run_scan
from .corpus.batch import scan_dir
from .findings import Finding, Report, Severity
from .report.html_report import render_html
from .report.json_report import render_json
from .rules import ALL_RULES

_COLOR = {
    Severity.CRITICAL: "red",
    Severity.HIGH: "yellow",
    Severity.MEDIUM: "cyan",
    Severity.LOW: "blue",
}
_LEVELS = ["low", "medium", "high", "critical"]


@click.group()
@click.version_option(__version__, prog_name="cryptscan")
def main() -> None:
    """Static analysis for cryptographic misuse in Android APKs."""


@main.command()
@click.argument("apk", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--json", "json_out", type=click.Path(path_type=Path), help="Write a JSON report here.")
@click.option("--html", "html_out", type=click.Path(path_type=Path), help="Write an HTML report here.")
@click.option("--rules", "rules_csv", help="Comma-separated rule ids (default: all).")
@click.option(
    "--min-severity",
    type=click.Choice(_LEVELS, case_sensitive=False),
    default="low",
    show_default=True,
    help="Drop findings below this severity.",
)
@click.option(
    "--fail-on",
    type=click.Choice(_LEVELS, case_sensitive=False),
    help="Exit non-zero if a finding at or above this severity remains.",
)
def scan(apk, json_out, html_out, rules_csv, min_severity, fail_on) -> None:
    """Scan a single APK."""
    rule_ids = [r.strip() for r in rules_csv.split(",")] if rules_csv else None
    report = run_scan(apk, rule_ids)
    report.findings = [f for f in report.findings if f.severity >= Severity.parse(min_severity)]

    if json_out:
        json_out.write_text(render_json(report))
    if html_out:
        html_out.write_text(render_html(report))

    _print_report(report)

    if fail_on and any(f.severity >= Severity.parse(fail_on) for f in report.findings):
        sys.exit(2)


@main.command()
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--csv", "csv_out", type=click.Path(path_type=Path), help="Write the summary CSV here.")
@click.option("--json-dir", type=click.Path(path_type=Path), help="Write per-APK JSON reports here.")
@click.option("--jobs", type=int, default=None, help="Parallel workers (default: CPU count).")
def corpus(directory, csv_out, json_dir, jobs) -> None:
    """Batch-scan every APK in a directory."""
    rows = scan_dir(directory, csv_path=csv_out, json_dir=json_dir, jobs=jobs)
    if not rows:
        click.echo("No APKs found.")
        return
    for row in rows:
        status = row["error"] or f"{row['total']} findings"
        click.echo(f"{Path(row['path']).name:40} {row['package']:32} {status}")
    click.echo(f"\nScanned {len(rows)} APK(s).")


@main.command(name="rules")
def rules_cmd() -> None:
    """List the detection rules."""
    for rule in ALL_RULES:
        click.echo(f"{rule.id}  {str(rule.severity):8}  {rule.name}")


@main.command()
@click.option("--package", required=True, help="App package to spawn and hook.")
@click.option("--device", help="Frida device id (default: USB).")
def verify(package, device) -> None:
    """Confirm findings at runtime with Frida (experimental, needs a device)."""
    from .frida.runner import verify as run_verify

    run_verify(package, device)


def _print_report(report: Report) -> None:
    s = report.summary
    click.echo(
        f"{report.target.get('package') or report.target['path']}  -  "
        f"{len(report.findings)} findings "
        f"({s['Critical']} critical, {s['High']} high, {s['Medium']} medium, {s['Low']} low)  "
        f"in {report.scan_seconds:.2f}s"
    )
    for f in report.sorted_findings():
        click.echo(_format_finding(f))


def _format_finding(f: Finding) -> str:
    tag = click.style(f"[{str(f.severity).upper()}]", fg=_COLOR[f.severity], bold=True)
    loc = f"{f.class_name} -> {f.method}" if f.method else f.class_name
    return f"{tag} {f.rule_id} {f.title}\n    {loc}  |  {f.evidence}"
