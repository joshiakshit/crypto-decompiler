from __future__ import annotations

import re

from ..analysis.xref import app_methods, invoke_arg_literals
from ..context import AnalysisContext
from ..findings import Confidence, Finding
from ..findings import Severity as S
from .base import Rule

_PROTOCOL = r"^(SSL|SSLv2|SSLv3|TLSv1|TLSv1\.0|TLSv1\.1)$"
_SSL_GET = r"Ljavax/net/ssl/SSLContext;->getInstance"


class InsecureTlsRule(Rule):
    id = "CS007"
    name = "Insecure TLS version"
    severity = S.HIGH
    cwe = "CWE-326"
    remediation = "Require TLS 1.2 or higher. Do not request SSLv3, TLS 1.0 or TLS 1.1."

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for ma in app_methods(ctx.dx):
            em = ma.get_method()
            for off, proto in invoke_arg_literals(em, _SSL_GET):
                if not re.match(_PROTOCOL, proto):
                    continue
                findings.append(
                    self.finding(
                        title=f"Insecure TLS protocol requested ({proto})",
                        class_name=ma.class_name,
                        method=ma.name,
                        descriptor=str(ma.descriptor),
                        offset=off,
                        evidence=proto,
                        confidence=Confidence.HIGH,
                    )
                )
        return findings
