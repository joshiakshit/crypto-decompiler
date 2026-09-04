from __future__ import annotations

from ..analysis.entropy import is_high_entropy_secret
from ..analysis.xref import const_offset, method_invokes
from ..context import AnalysisContext
from ..findings import Confidence, Finding
from ..findings import Severity as S
from .base import Rule

_SINK = (
    r"L(javax/crypto/spec/SecretKeySpec|javax/crypto/spec/IvParameterSpec"
    r"|javax/crypto/Cipher|javax/crypto/Mac);"
)


def _redact(value: str) -> str:
    return f"{value[:4]}...[{len(value)} chars]"


class HardcodedKeysRule(Rule):
    id = "CS001"
    name = "Hardcoded cryptographic key"
    severity = S.CRITICAL
    cwe = "CWE-321"
    remediation = "Derive keys at runtime or load them from the Android Keystore. Never embed key material."

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for sa in ctx.dx.get_strings():
            value = sa.get_value()
            if not is_high_entropy_secret(value):
                continue
            for cls, meth in sa.get_xref_from():
                em = meth.get_method()
                if em is None or not method_invokes(em, _SINK):
                    continue
                findings.append(
                    self.finding(
                        title="Hardcoded cryptographic key or secret",
                        class_name=cls.name,
                        method=meth.name,
                        descriptor=str(meth.descriptor),
                        offset=const_offset(meth, value),
                        evidence=_redact(value),
                        confidence=Confidence.HIGH,
                    )
                )
        return findings
