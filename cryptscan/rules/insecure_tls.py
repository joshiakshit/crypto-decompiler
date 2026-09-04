from __future__ import annotations

from ..analysis.xref import method_invokes, strings_matching
from ..context import AnalysisContext
from ..findings import Confidence, Finding
from ..findings import Severity as S
from .base import Rule

_PROTOCOL = r"^(SSL|SSLv2|SSLv3|TLSv1|TLSv1\.0|TLSv1\.1)$"
_TLS_API = r"Ljavax/net/ssl/SSL(Context|Socket|Engine|Parameters);|->setEnabledProtocols"


class InsecureTlsRule(Rule):
    id = "CS007"
    name = "Insecure TLS version"
    severity = S.HIGH
    cwe = "CWE-326"
    remediation = "Require TLS 1.2 or higher. Do not request SSLv3, TLS 1.0 or TLS 1.1."

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for value, refs in strings_matching(ctx.dx, _PROTOCOL):
            for cls_name, meth, off in refs:
                em = meth.get_method()
                if em is None or not method_invokes(em, _TLS_API):
                    continue
                findings.append(
                    self.finding(
                        title=f"Insecure TLS protocol requested ({value})",
                        class_name=cls_name,
                        method=meth.name,
                        descriptor=str(meth.descriptor),
                        offset=off,
                        evidence=value,
                        confidence=Confidence.HIGH,
                    )
                )
        return findings
