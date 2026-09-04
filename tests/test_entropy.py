from cryptscan.analysis.entropy import (
    is_high_entropy_secret,
    looks_base64,
    looks_hex,
    shannon_entropy,
)

HEX_KEY = "a3f5c9d21e4b7a8c0f6d2e9b1a4c7f80"
B64_KEY = "Zm9vYmFyYmF6cXV4d2liYmxld29iYmxlZmxvYmJsZQ=="


def test_entropy_bounds():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaaaaaa") == 0.0
    assert shannon_entropy(HEX_KEY) > 3.5


def test_charset_detection():
    assert looks_hex(HEX_KEY)
    assert not looks_hex("nothex-string-here!!")
    assert looks_base64(B64_KEY)
    assert not looks_base64("not base64!!")


def test_secret_heuristic():
    assert is_high_entropy_secret(HEX_KEY)
    assert is_high_entropy_secret(B64_KEY)
    assert not is_high_entropy_secret("password")
    assert not is_high_entropy_secret("AAAAAAAAAAAAAAAA")
