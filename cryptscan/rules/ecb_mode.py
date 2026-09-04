from __future__ import annotations

import re

from ..analysis.xref import app_methods, getinstance_args
from ..context import AnalysisContext
from ..findings import Confidence, Finding
from ..findings import Severity as S
from .base import Rule

_CIPHER_GET = r"Ljavax/crypto/Cipher;->getInstance"
_EXPLICIT_ECB = re.compile(r"/ECB/")
_MODELESS = re.compile(r"^(AES|DES|DESede|Blowfish|RC2)$")


class EcbModeRule(Rule):
    id = "CS002"
    name = "ECB mode cipher"
    severity = S.HIGH
    cwe = "CWE-327"
    remediation = "Use an authenticated mode such as AES/GCM/NoPadding. Never use ECB."

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for ma in app_methods(ctx.dx):
            em = ma.get_method()
            for off, transform in getinstance_args(em, _CIPHER_GET):
                if not (_EXPLICIT_ECB.search(transform) or _MODELESS.match(transform)):
                    continue
                findings.append(
                    self.finding(
                        title=f"Cipher uses ECB mode ({transform})",
                        class_name=ma.class_name,
                        method=ma.name,
                        descriptor=str(ma.descriptor),
                        offset=off,
                        evidence=transform,
                        confidence=Confidence.HIGH,
                    )
                )
        return findings
