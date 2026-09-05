import pytest

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
