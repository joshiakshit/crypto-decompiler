from __future__ import annotations

import re

from ..analysis.xref import app_methods, const_strings, method_invokes
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
    remediation = "Store secrets in the Android Keystore or EncryptedSharedPreferences, not plain preferences."

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for ma in app_methods(ctx.dx):
            em = ma.get_method()
            if not method_invokes(em, _PUTSTRING):
                continue
            for off, name in const_strings(em):
                if _SECRET_NAME.search(name):
                    findings.append(
                        self.finding(
                            title=f"Secret stored in SharedPreferences ({name})",
                            class_name=ma.class_name,
                            method=ma.name,
                            descriptor=str(ma.descriptor),
                            offset=off,
                            evidence=name,
                            confidence=Confidence.MEDIUM,
                        )
                    )
                    break
        return findings
