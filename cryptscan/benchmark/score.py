from __future__ import annotations

from dataclasses import dataclass


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
