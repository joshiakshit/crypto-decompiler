from pathlib import Path

from cryptscan.analyzer import scan
from cryptscan.report.html_report import render_html

FIX = Path(__file__).parent / "fixtures"


def test_html_renders_findings_and_badges():
    report = scan(FIX / "samples.apk")
    html = render_html(report)
    assert "<html" in html
    assert "com.cryptscan.samples" in html
    assert "badge sev" in html
    assert "CWE-" in html
    assert html.count('class="finding ') == len(report.findings)


def test_html_escapes_evidence():
    report = scan(FIX / "samples.apk")
    html = render_html(report)
    assert "<script>" not in html
