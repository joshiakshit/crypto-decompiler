from cryptscan.rules.ecb_mode import EcbModeRule


def test_ecb_explicit_positive(samples_ctx):
    findings = EcbModeRule().analyze(samples_ctx)
    assert any(
        f.class_name.endswith("VulnEcb;") and f.evidence == "AES/ECB/PKCS5Padding"
        for f in findings
    )


def test_ecb_modeless_positive(samples_ctx):
    findings = EcbModeRule().analyze(samples_ctx)
    assert any(
        f.class_name.endswith("VulnEcbDefault;") and f.evidence == "AES" for f in findings
    )


def test_ecb_negative(samples_ctx):
    findings = EcbModeRule().analyze(samples_ctx)
    flagged = {f.class_name for f in findings}
    assert not any(c.endswith("SafeGcm;") for c in flagged)
    # AES/CBC key wrapper must not be mistaken for ECB
    assert not any(c.endswith("VulnHardcodedKey;") for c in flagged)
