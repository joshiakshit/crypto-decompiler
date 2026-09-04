from __future__ import annotations

from ..analysis.xref import classes_implementing, has_opcode
from ..context import AnalysisContext
from ..findings import Confidence, Finding
from ..findings import Severity as S
from .base import Rule

_TRUST_MANAGER = r"Ljavax/net/ssl/X509TrustManager;"
_CHECK_METHODS = ("checkServerTrusted", "checkClientTrusted")


class CertValidationRule(Rule):
    id = "CS006"
    name = "Missing certificate validation"
    severity = S.CRITICAL
    cwe = "CWE-295"
    remediation = "Validate the server certificate chain. Do not ship an empty TrustManager."

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for ca in classes_implementing(ctx.dx, _TRUST_MANAGER):
            for ma in ca.get_methods():
                if ma.name not in _CHECK_METHODS:
                    continue
                em = ma.get_method()
                if em is None or has_opcode(em, ("throw",)):
                    continue
                findings.append(
                    self.finding(
                        title="TrustManager accepts all certificates",
                        class_name=ca.name,
                        method=ma.name,
                        descriptor=str(ma.descriptor),
                        evidence=f"{ma.name} performs no certificate validation",
                        confidence=Confidence.HIGH,
                    )
                )
        return findings
