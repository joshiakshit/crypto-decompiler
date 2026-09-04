from __future__ import annotations

import re

from ..analysis.xref import app_methods, has_opcode, method_invokes
from ..context import AnalysisContext
from ..findings import Confidence, Finding
from ..findings import Severity as S
from .base import Rule

_NAME = re.compile(r"(?i)(encrypt|decrypt|crypt|cipher|obfuscat)")
_JAVAX_CRYPTO = r"Ljavax/crypto/"
_BITOPS = ("xor-", "shl-", "shr-", "ushr-")


class HomegrownCryptoRule(Rule):
    id = "CS008"
    name = "Home-grown crypto"
    severity = S.MEDIUM
    cwe = "CWE-327"
    remediation = "Replace custom byte manipulation with a vetted javax.crypto primitive."

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for ma in app_methods(ctx.dx):
            if not _NAME.search(ma.name):
                continue
            em = ma.get_method()
            if method_invokes(em, _JAVAX_CRYPTO):
                continue
            if has_opcode(em, _BITOPS) and has_opcode(em, ("aget", "aput")):
                findings.append(
                    self.finding(
                        title=f"Custom byte-level crypto in {ma.name}()",
                        class_name=ma.class_name,
                        method=ma.name,
                        descriptor=str(ma.descriptor),
                        evidence="bitwise operations on byte arrays, no javax.crypto call",
                        confidence=Confidence.LOW,
                    )
                )
        return findings
