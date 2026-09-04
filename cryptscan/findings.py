from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        return self.name.capitalize()

    @classmethod
    def parse(cls, name: str) -> Severity:
        return cls[name.strip().upper()]


class Confidence(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    def __str__(self) -> str:
        return self.name.capitalize()


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    cwe: str
    class_name: str
    method: str
    descriptor: str
    offset: int
    evidence: str
    remediation: str

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": str(self.severity),
            "confidence": str(self.confidence),
            "cwe": self.cwe,
            "location": {
                "class": self.class_name,
                "method": self.method,
                "descriptor": self.descriptor,
                "offset": self.offset,
            },
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass
class Report:
    tool: str
    version: str
    target: dict
    scan_seconds: float
    findings: list[Finding]

    @property
    def summary(self) -> dict[str, int]:
        counts = {str(s): 0 for s in reversed(Severity)}
        for f in self.findings:
            counts[str(f.severity)] += 1
        return counts

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-f.severity, f.rule_id, f.class_name, f.offset))

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "version": self.version,
            "target": self.target,
            "scan_seconds": round(self.scan_seconds, 2),
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }
