from __future__ import annotations

import time
from collections.abc import Iterable
from pathlib import Path

from . import __version__
from .findings import Finding, Report
from .loader import load
from .rules import get_rules


def scan(path: str | Path, rule_ids: Iterable[str] | None = None) -> Report:
    start = time.perf_counter()
    ctx = load(path)
    findings: list[Finding] = []
    for rule in get_rules(rule_ids):
        findings.extend(rule.analyze(ctx))
    return Report(
        tool="cryptscan",
        version=__version__,
        target=ctx.target,
        scan_seconds=time.perf_counter() - start,
        findings=findings,
    )
