from pathlib import Path

from click.testing import CliRunner

from cryptscan.cli import main
from cryptscan.findings import Confidence, Finding, Report, Severity

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


def test_benchmark_command_prints_all_row(tmp_path, monkeypatch):
    import json

    target = tmp_path / "target.apk"
    target.write_text("")
    manifest = {
        "targets": [
            {
                "file": "target.apk",
                "scope": ["Lcom/x/"],
                "expected": [{"rule_id": "CS001", "class": "Lcom/x/Vuln;"}],
            }
        ]
    }
    (tmp_path / "ground_truth.json").write_text(json.dumps(manifest))

    finding = Finding(
        rule_id="CS001",
        title="t",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe="CWE-321",
        class_name="Lcom/x/Vuln;",
        method="m",
        descriptor="()V",
        offset=0,
        evidence="e",
        remediation="r",
    )
    report = Report("cryptscan", "0.1.0", {"path": str(target)}, 0.0, [finding])
    monkeypatch.setattr("cryptscan.benchmark.score.scan", lambda path, rule_ids=None: report)

    result = CliRunner().invoke(main, ["benchmark", str(tmp_path)])

    assert result.exit_code == 0
    assert "| ALL |" in result.output
