from __future__ import annotations

import re

from ..analysis.xref import app_methods, invoke_targets
from ..context import AnalysisContext
from ..findings import Confidence, Finding
from ..findings import Severity as S
from .base import Rule

_WEAK = re.compile(r"Ljava/util/Random;|Ljava/lang/Math;->random")
_CRYPTO = re.compile(
    r"Ljavax/crypto/(Cipher|Mac|KeyGenerator|spec/SecretKeySpec|spec/IvParameterSpec);"
    r"|Ljava/security/KeyPairGenerator;"
)


class WeakRandomnessRule(Rule):
    id = "CS004"
    name = "Weak randomness feeding crypto"
    severity = S.HIGH
    cwe = "CWE-330"
    remediation = "Use java.security.SecureRandom for keys, IVs, nonces and salts."

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for ma in app_methods(ctx.dx):
            em = ma.get_method()
            targets = list(invoke_targets(em))
            weak = [(off, t) for off, t in targets if _WEAK.search(t)]
            if not weak or not any(_CRYPTO.search(t) for _, t in targets):
                continue
            off, target = weak[0]
            findings.append(
                self.finding(
                    title="Insecure java.util.Random used for crypto material",
                    class_name=ma.class_name,
                    method=ma.name,
                    descriptor=str(ma.descriptor),
                    offset=off,
                    evidence=target,
                    confidence=Confidence.MEDIUM,
                )
            )
        return findings
