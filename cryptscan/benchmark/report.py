from __future__ import annotations

import json

from .score import BenchmarkResult, RuleScore


def render_json(result: BenchmarkResult) -> str:
    payload = {
        "overall": _score_dict(result.overall),
        "per_rule": {rid: _score_dict(result.per_rule[rid]) for rid in sorted(result.per_rule)},
        "skipped": result.skipped,
    }
    return json.dumps(payload, indent=2)


def render_markdown(result: BenchmarkResult) -> str:
    lines = [
        f"{result.scored} targets scored, {len(result.skipped)} skipped",
        "",
        "| Rule | TP | FP | FN | Precision | Recall | F1 |",
        "|------|----|----|----|-----------|--------|----|",
    ]
    for rule_id in sorted(result.per_rule):
        lines.append(_row(result.per_rule[rule_id]))
    lines.append(_row(result.overall))
    if result.skipped:
        lines.append("")
        lines.append(f"Skipped (file missing): {', '.join(result.skipped)}")
    return "\n".join(lines) + "\n"


def _score_dict(score: RuleScore) -> dict:
    return {
        "tp": score.tp,
        "fp": score.fp,
        "fn": score.fn,
        "precision": round(score.precision, 3),
        "recall": round(score.recall, 3),
        "f1": round(score.f1, 3),
    }


def _row(score: RuleScore) -> str:
    return (
        f"| {score.rule_id} | {score.tp} | {score.fp} | {score.fn} | "
        f"{score.precision:.3f} | {score.recall:.3f} | {score.f1:.3f} |"
    )
