from __future__ import annotations

from abc import ABC, abstractmethod

from ..context import AnalysisContext
from ..findings import Confidence, Finding, Severity


class Rule(ABC):
    id: str
    name: str
    severity: Severity
    cwe: str
    remediation: str

    @abstractmethod
    def analyze(self, ctx: AnalysisContext) -> list[Finding]: ...

    def finding(
        self,
        *,
        title: str,
        class_name: str,
        evidence: str,
        confidence: Confidence,
        severity: Severity | None = None,
        method: str = "",
        descriptor: str = "",
        offset: int = 0,
    ) -> Finding:
        return Finding(
            rule_id=self.id,
            title=title,
            severity=severity or self.severity,
            confidence=confidence,
            cwe=self.cwe,
            class_name=class_name,
            method=method,
            descriptor=descriptor,
            offset=offset,
            evidence=evidence,
            remediation=self.remediation,
        )
