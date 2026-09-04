from cryptscan.findings import Severity
from cryptscan.rules.cert_validation import CertValidationRule


def test_trust_all_positive(samples_ctx):
    findings = CertValidationRule().analyze(samples_ctx)
    vuln = [f for f in findings if "VulnTrustAll" in f.class_name]
    assert vuln
    assert vuln[0].severity is Severity.CRITICAL


def test_trust_manager_negative(samples_ctx):
    findings = CertValidationRule().analyze(samples_ctx)
    assert not [f for f in findings if "SafeTrust" in f.class_name]
