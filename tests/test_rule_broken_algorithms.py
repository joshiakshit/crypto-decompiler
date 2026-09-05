from cryptscan.findings import Severity
from cryptscan.rules.broken_algorithms import BrokenAlgorithmsRule


def test_broken_hash_positive(samples_ctx):
    findings = BrokenAlgorithmsRule().analyze(samples_ctx)
    md5 = [f for f in findings if "VulnBrokenHash" in f.class_name]
    assert md5
    assert md5[0].evidence == "MD5"
    assert md5[0].severity is Severity.MEDIUM


def test_broken_cipher_positive(samples_ctx):
    findings = BrokenAlgorithmsRule().analyze(samples_ctx)
    des = [f for f in findings if "VulnDesCipher" in f.class_name]
    assert des
    assert des[0].evidence.startswith("DES")
    assert des[0].severity is Severity.HIGH


def test_broken_algorithms_negative(samples_ctx):
    findings = BrokenAlgorithmsRule().analyze(samples_ctx)
    assert not [f for f in findings if "Safe" in f.class_name]


def test_broken_algorithms_decoy_negative(samples_ctx):
    findings = BrokenAlgorithmsRule().analyze(samples_ctx)
    assert not [f for f in findings if "DecoyWeakAlgoLog" in f.class_name]
