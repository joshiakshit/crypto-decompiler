"""Scores scanner findings against a labeled corpus.

Matching uses (rule_id, class_name) pairs, not offsets. Offsets are imprecise.
Class-level matching is stable. It answers whether the right rule flagged the
right class. Findings from one rule in one class collapse to one pair.
Duplicate findings in the same class do not count as extra false positives.

`overall` is a micro-average: it sums tp/fp/fn across all rules, then computes
precision/recall/f1 once. This is not a macro-average of per-rule scores.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..analyzer import scan  # module-level import so tests can monkeypatch it
from .corpus import Target


@dataclass
class RuleScore:
    rule_id: str
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


@dataclass
class BenchmarkResult:
    per_rule: dict[str, RuleScore]  # keyed by rule_id, sorted keys when rendered
    overall: RuleScore  # micro-average: summed tp/fp/fn across all rules
    skipped: list[str]  # target file names whose file was missing
    scored: int  # count of targets successfully scanned (not skipped)


def score_corpus(targets: list[Target]) -> BenchmarkResult:
    per_rule: dict[str, RuleScore] = {}
    skipped: list[str] = []
    scored = 0

    for target in targets:
        if not target.file.exists():
            skipped.append(target.file.name)
            continue
        scored += 1

        report = scan(target.file)
        actual = {
            (f.rule_id, f.class_name)
            for f in report.findings
            if any(f.class_name.startswith(prefix) for prefix in target.scope)
        }

        for rule_id in {r for r, _ in actual} | {r for r, _ in target.expected}:
            actual_r = {c for r, c in actual if r == rule_id}
            expected_r = {c for r, c in target.expected if r == rule_id}
            rule_score = per_rule.setdefault(rule_id, RuleScore(rule_id))
            rule_score.tp += len(actual_r & expected_r)
            rule_score.fp += len(actual_r - expected_r)
            rule_score.fn += len(expected_r - actual_r)

    overall = RuleScore(
        "ALL",
        tp=sum(s.tp for s in per_rule.values()),
        fp=sum(s.fp for s in per_rule.values()),
        fn=sum(s.fn for s in per_rule.values()),
    )
    return BenchmarkResult(per_rule=per_rule, overall=overall, skipped=skipped, scored=scored)
