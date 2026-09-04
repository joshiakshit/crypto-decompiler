from cryptscan.rules.ecb_mode import EcbModeRule


def test_ecb_positive(samples_ctx):
    findings = EcbModeRule().analyze(samples_ctx)
    vuln = [f for f in findings if "VulnEcb" in f.class_name]
    assert vuln
    assert "ECB" in vuln[0].evidence


def test_ecb_negative(samples_ctx):
    findings = EcbModeRule().analyze(samples_ctx)
    assert not [f for f in findings if "SafeGcm" in f.class_name]
