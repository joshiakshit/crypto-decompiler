from cryptscan.findings import Confidence, Finding, Report, Severity


def make_finding(rule_id, severity, cls="Lcom/x/A;", offset=0):
    return Finding(
        rule_id=rule_id,
        title="t",
        severity=severity,
        confidence=Confidence.HIGH,
        cwe="CWE-327",
        class_name=cls,
        method="m",
        descriptor="()V",
        offset=offset,
        evidence="e",
        remediation="r",
    )


def test_severity_parse_and_str():
    assert Severity.parse("high") is Severity.HIGH
    assert str(Severity.CRITICAL) == "Critical"
    assert Severity.CRITICAL > Severity.LOW


def test_report_summary_counts():
    findings = [
        make_finding("CS002", Severity.HIGH),
        make_finding("CS003", Severity.MEDIUM),
        make_finding("CS001", Severity.CRITICAL),
    ]
    report = Report("cryptscan", "0.1.0", {"path": "a.apk"}, 1.234, findings)
    assert report.summary == {"Critical": 1, "High": 1, "Medium": 1, "Low": 0}


def test_report_sorted_by_severity_then_rule():
    findings = [
        make_finding("CS003", Severity.MEDIUM),
        make_finding("CS002", Severity.HIGH),
        make_finding("CS001", Severity.HIGH),
    ]
    report = Report("cryptscan", "0.1.0", {}, 0.0, findings)
    order = [(f.severity, f.rule_id) for f in report.sorted_findings()]
    assert order == [
        (Severity.HIGH, "CS001"),
        (Severity.HIGH, "CS002"),
        (Severity.MEDIUM, "CS003"),
    ]


def test_finding_to_dict_shape():
    d = make_finding("CS001", Severity.CRITICAL, offset=8).to_dict()
    assert d["rule_id"] == "CS001"
    assert d["severity"] == "Critical"
    assert d["location"] == {"class": "Lcom/x/A;", "method": "m", "descriptor": "()V", "offset": 8}
