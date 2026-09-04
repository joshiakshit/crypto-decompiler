from __future__ import annotations

import re

from ..analysis.xref import method_invokes, strings_matching
from ..context import AnalysisContext
from ..findings import Confidence, Finding
from ..findings import Severity as S
from .base import Rule

_EXPLICIT_ECB = re.compile(r"/ECB/")
_MATCH = r"(/ECB/|^(AES|DES|DESede|Blowfish|RC2)$)"
_CIPHER_GET = r"Ljavax/crypto/Cipher;->getInstance"


class EcbModeRule(Rule):
    id = "CS002"
    name = "ECB mode cipher"
    severity = S.HIGH
    cwe = "CWE-327"
    remediation = "Use an authenticated mode such as AES/GCM/NoPadding. Never use ECB."

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for value, refs in strings_matching(ctx.dx, _MATCH):
            explicit = bool(_EXPLICIT_ECB.search(value))
            for cls_name, meth, off in refs:
                if not explicit:
                    em = meth.get_method()
                    if em is None or not method_invokes(em, _CIPHER_GET):
                        continue
                findings.append(
                    self.finding(
                        title=f"Cipher uses ECB mode ({value})",
                        class_name=cls_name,
                        method=meth.name,
                        descriptor=str(meth.descriptor),
                        offset=off,
                        evidence=value,
                        confidence=Confidence.HIGH if explicit else Confidence.MEDIUM,
                    )
                )
        return findings
