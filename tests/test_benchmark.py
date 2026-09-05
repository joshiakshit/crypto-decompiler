import json

import pytest

from cryptscan.benchmark.corpus import load_corpus
from cryptscan.benchmark.score import RuleScore


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
