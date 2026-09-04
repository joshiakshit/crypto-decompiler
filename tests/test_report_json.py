import json
from pathlib import Path

from cryptscan.analyzer import scan
from cryptscan.report.json_report import render_json

FIX = Path(__file__).parent / "fixtures"


def test_json_report_shape():
    report = scan(FIX / "samples.apk")
    data = json.loads(render_json(report))
    assert data["tool"] == "cryptscan"
    assert set(data["summary"]) == {"Critical", "High", "Medium", "Low"}
    assert data["findings"]
    first = data["findings"][0]
    assert {"rule_id", "severity", "location", "remediation"} <= set(first)


def test_json_findings_sorted_by_severity():
    report = scan(FIX / "samples.apk")
    data = json.loads(render_json(report))
    order = ["Critical", "High", "Medium", "Low"]
    ranks = [order.index(f["severity"]) for f in data["findings"]]
    assert ranks == sorted(ranks)
