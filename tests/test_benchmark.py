import json

import pytest

from cryptscan.benchmark.corpus import Target, load_corpus
from cryptscan.benchmark.score import RuleScore, score_corpus
from cryptscan.findings import Confidence, Finding, Report, Severity


def test_rule_score_metrics():
    score = RuleScore("CS001", tp=8, fp=2, fn=2)
    assert score.precision == pytest.approx(0.8)
    assert score.recall == pytest.approx(0.8)
    assert score.f1 == pytest.approx(0.8)


def test_rule_score_zero_division():
    assert RuleScore("X", 0, 0, 0).precision == 0.0
    assert RuleScore("X", 0, 0, 0).recall == 0.0
    assert RuleScore("X", 0, 0, 0).f1 == 0.0
    assert RuleScore("X", 0, 5, 0).precision == 0.0
    assert RuleScore("X", 0, 0, 5).recall == 0.0


def _write_manifest(corpus_dir, targets):
    (corpus_dir / "ground_truth.json").write_text(json.dumps({"targets": targets}))


def test_load_corpus(tmp_path):
    (tmp_path / "target.dex").write_text("dummy")
    _write_manifest(
        tmp_path,
        [
            {
                "file": "target.dex",
                "scope": ["Lcom/example/"],
                "expected": [{"rule_id": "CS001", "class": "Lcom/example/Vuln;"}],
            }
        ],
    )

    targets = load_corpus(tmp_path)

    assert len(targets) == 1
    target = targets[0]
    assert target.scope == ["Lcom/example/"]
    assert target.expected == {("CS001", "Lcom/example/Vuln;")}
    assert target.file == (tmp_path / "target.dex").resolve()


def test_load_corpus_rejects_out_of_scope_label(tmp_path):
    _write_manifest(
        tmp_path,
        [
            {
                "file": "target.dex",
                "scope": ["Lcom/example/"],
                "expected": [{"rule_id": "CS001", "class": "Lcom/other/Vuln;"}],
            }
        ],
    )

    with pytest.raises(ValueError):
        load_corpus(tmp_path)


def _finding(rule_id, class_name):
    return Finding(
        rule_id=rule_id,
        title="t",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe="CWE-000",
        class_name=class_name,
        method="m",
        descriptor="()V",
        offset=0,
        evidence="e",
        remediation="r",
    )


def _report(findings):
    return Report("cryptscan", "0.1.0", {"path": "x"}, 0.0, findings)


def test_score_corpus(tmp_path, monkeypatch):
    file_a = tmp_path / "a.dex"
    file_a.write_text("")
    file_b = tmp_path / "b.dex"
    file_b.write_text("")

    target_a = Target(
        file=file_a,
        scope=["Lcom/a/"],
        expected={("CS001", "Lcom/a/Vuln1;"), ("CS002", "Lcom/a/Vuln2;")},
    )
    target_b = Target(
        file=file_b,
        scope=["Lcom/b/"],
        expected={("CS001", "Lcom/b/Vuln1;")},
    )

    reports = {
        file_a: _report(
            [
                _finding("CS001", "Lcom/a/Vuln1;"),  # TP
                _finding("CS001", "Lcom/a/Safe;"),  # FP
                # CS002/Lcom/a/Vuln2; not found -> FN
            ]
        ),
        file_b: _report(
            [
                _finding("CS001", "Lcom/b/Vuln1;"),  # TP
                _finding("CS002", "Lcom/b/Other;"),  # FP, rule absent from expected
            ]
        ),
    }

    monkeypatch.setattr("cryptscan.benchmark.score.scan", lambda path, rule_ids=None: reports[path])

    result = score_corpus([target_a, target_b])

    assert result.per_rule["CS001"] == RuleScore("CS001", tp=2, fp=1, fn=0)
    assert result.per_rule["CS002"] == RuleScore("CS002", tp=0, fp=1, fn=1)
    assert result.overall == RuleScore("ALL", tp=2, fp=2, fn=1)
    assert result.skipped == []
    assert result.scored == 2


def test_scope_filtering(tmp_path, monkeypatch):
    file_a = tmp_path / "a.dex"
    file_a.write_text("")
    target = Target(file=file_a, scope=["Lcom/a/"], expected={("CS001", "Lcom/a/Vuln;")})

    report = _report(
        [
            _finding("CS001", "Lcom/a/Vuln;"),  # in scope -> TP
            _finding("CS001", "Lcom/other/Cls;"),  # out of scope -> ignored
        ]
    )
    monkeypatch.setattr("cryptscan.benchmark.score.scan", lambda path, rule_ids=None: report)

    result = score_corpus([target])

    assert result.per_rule["CS001"] == RuleScore("CS001", tp=1, fp=0, fn=0)


def test_missing_target_skipped(tmp_path, monkeypatch):
    def fail_scan(path, rule_ids=None):
        raise AssertionError("scan should not run for a missing target")

    monkeypatch.setattr("cryptscan.benchmark.score.scan", fail_scan)

    target = Target(file=tmp_path / "missing.apk", scope=["Lcom/a/"], expected=set())
    result = score_corpus([target])

    assert result.skipped == ["missing.apk"]
    assert result.per_rule == {}
    assert result.scored == 0
