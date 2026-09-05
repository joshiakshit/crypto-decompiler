from __future__ import annotations

import re

from ..analysis.xref import app_methods, invoke_arg_literals
from ..context import AnalysisContext
from ..findings import Confidence, Finding
from ..findings import Severity as S
from .base import Rule

_PUTSTRING = r"Landroid/content/SharedPreferences\$Editor;->putString"
_SECRET_NAME = re.compile(
    r"(?i)(secret|password|passwd|private[_-]?key|api[_-]?key|token|credential)"
)


class InsecureStorageRule(Rule):
    id = "CS005"
    name = "Secret in SharedPreferences"
    severity = S.MEDIUM
    cwe = "CWE-312"
    remediation = (
        "Use the Android Keystore or EncryptedSharedPreferences, not plain SharedPreferences."
    )

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for ma in app_methods(ctx.dx):
            em = ma.get_method()
            seen: set[str] = set()
            for off, literal in invoke_arg_literals(em, _PUTSTRING):
                if literal in seen or not _SECRET_NAME.search(literal):
                    continue
                seen.add(literal)
                findings.append(
                    self.finding(
                        title=f"Secret stored in SharedPreferences ({literal})",
                        class_name=ma.class_name,
                        method=ma.name,
                        descriptor=str(ma.descriptor),
                        offset=off,
                        evidence=literal,
                        confidence=Confidence.HIGH,
                    )
                )
        return findings
