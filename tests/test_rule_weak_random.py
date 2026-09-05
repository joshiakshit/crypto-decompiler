from cryptscan.rules.weak_random import WeakRandomnessRule


def test_weak_random_positive(samples_ctx):
    findings = WeakRandomnessRule().analyze(samples_ctx)
    vuln = [f for f in findings if "VulnWeakRandom" in f.class_name]
    assert vuln
    assert "Random" in vuln[0].evidence


def test_weak_random_negative(samples_ctx):
    findings = WeakRandomnessRule().analyze(samples_ctx)
    assert not [f for f in findings if "SafeSecureRandom" in f.class_name]


def test_weak_random_decoy_negative(samples_ctx):
    findings = WeakRandomnessRule().analyze(samples_ctx)
    assert not [f for f in findings if "DecoyJitterRandom" in f.class_name]
