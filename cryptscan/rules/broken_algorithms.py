from __future__ import annotations

import re

from ..analysis.xref import app_methods, invoke_arg_literals
from ..context import AnalysisContext
from ..findings import Confidence, Finding
from ..findings import Severity as S
from .base import Rule

_HASH = r"^(MD5|SHA-1|SHA1)$"
_CIPHER = r"^(DESede|DES|RC4|ARCFOUR|RC2|Blowfish)(/.*)?$"
_MD_GET = r"L(java/security/MessageDigest|javax/crypto/Mac);->getInstance"
_CIPHER_GET = r"Ljavax/crypto/Cipher;->getInstance"


class BrokenAlgorithmsRule(Rule):
    id = "CS003"
    name = "Broken or deprecated algorithm"
    severity = S.HIGH
    cwe = "CWE-327"
    remediation = "Use SHA-256+ for hashing and AES-GCM for encryption. Avoid MD5, SHA-1, DES, RC4."

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for ma in app_methods(ctx.dx):
            em = ma.get_method()
            for off, algo in invoke_arg_literals(em, _MD_GET):
                if re.match(_HASH, algo):
                    findings.append(self._make(ma, off, "Weak hash algorithm", algo, S.MEDIUM))
            for off, algo in invoke_arg_literals(em, _CIPHER_GET):
                if re.match(_CIPHER, algo):
                    findings.append(self._make(ma, off, "Broken cipher algorithm", algo, S.HIGH))
        return findings

    def _make(self, ma, off: int, title: str, algo: str, severity: S) -> Finding:
        return self.finding(
            title=f"{title} ({algo})",
            class_name=ma.class_name,
            method=ma.name,
            descriptor=str(ma.descriptor),
            offset=off,
            evidence=algo,
            severity=severity,
            confidence=Confidence.HIGH,
        )
