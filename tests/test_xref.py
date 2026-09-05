from cryptscan.analysis.xref import app_methods, invoke_arg_literals, weak_random_material

_PUTSTRING = r"Landroid/content/SharedPreferences\$Editor;->putString"
_CIPHER_GET = r"Ljavax/crypto/Cipher;->getInstance"
_WEAK = r"Ljava/util/Random;->|Ljava/lang/Math;->random"
_MATERIAL = r"Ljavax/crypto/spec/(SecretKeySpec|IvParameterSpec);-><init>"


def _method(dx, class_suffix, name):
    for ma in app_methods(dx):
        if ma.class_name.endswith(class_suffix) and ma.name == name:
            return ma
    raise LookupError(class_suffix)


def test_invoke_arg_literals_putstring_regs1(samples_ctx):
    em = _method(samples_ctx.dx, "VulnPrefsKey;", "save").get_method()
    assert list(invoke_arg_literals(em, _PUTSTRING)) == [(8, "secret_key")]


def test_invoke_arg_literals_getinstance_regs0(samples_ctx):
    em = _method(samples_ctx.dx, "VulnEcb;", "enc").get_method()
    literals = list(invoke_arg_literals(em, _CIPHER_GET))
    assert literals == [(0, "AES/ECB/PKCS5Padding")]


def test_weak_random_material_positive(samples_ctx):
    em = _method(samples_ctx.dx, "VulnWeakRandom;", "enc").get_method()
    found = list(weak_random_material(em, _WEAK, _MATERIAL))
    assert found
    assert "Random" in found[0][1]


def test_weak_random_material_safe_negative(samples_ctx):
    em = _method(samples_ctx.dx, "SafeSecureRandom;", "enc").get_method()
    assert list(weak_random_material(em, _WEAK, _MATERIAL)) == []


def test_weak_random_material_decoy_negative(samples_ctx):
    em = _method(samples_ctx.dx, "DecoyJitterRandom;", "iv").get_method()
    assert list(weak_random_material(em, _WEAK, _MATERIAL)) == []
