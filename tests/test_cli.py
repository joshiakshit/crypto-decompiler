from pathlib import Path

from click.testing import CliRunner

from cryptscan.cli import main

FIX = Path(__file__).parent / "fixtures"
APK = str(FIX / "samples.apk")


def test_rules_command_lists_all():
    result = CliRunner().invoke(main, ["rules"])
    assert result.exit_code == 0
    for rid in ("CS001", "CS002", "CS008"):
        assert rid in result.output


def test_scan_writes_json(tmp_path):
    out = tmp_path / "r.json"
    result = CliRunner().invoke(main, ["scan", APK, "--json", str(out)])
    assert result.exit_code == 0
    assert out.exists()
    assert '"rule_id"' in out.read_text()


def test_scan_fail_on_critical_exits_nonzero():
    result = CliRunner().invoke(main, ["scan", APK, "--fail-on", "critical"])
    assert result.exit_code == 2


def test_scan_min_severity_filters(tmp_path):
    import json

    out = tmp_path / "r.json"
    result = CliRunner().invoke(main, ["scan", APK, "--min-severity", "high", "--json", str(out)])
    assert result.exit_code == 0
    severities = {f["severity"] for f in json.loads(out.read_text())["findings"]}
    assert severities <= {"Critical", "High"}
