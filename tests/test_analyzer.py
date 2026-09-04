from pathlib import Path

from cryptscan.analyzer import scan

FIX = Path(__file__).parent / "fixtures"


def test_scan_finds_multiple_rules():
    report = scan(FIX / "samples.apk")
    rule_ids = {f.rule_id for f in report.findings}
    assert {"CS001", "CS002", "CS003", "CS006"} <= rule_ids
    assert report.target["package"] == "com.cryptscan.samples"


def test_scan_rule_filter():
    report = scan(FIX / "samples.apk", rule_ids=["CS002"])
    assert {f.rule_id for f in report.findings} == {"CS002"}
