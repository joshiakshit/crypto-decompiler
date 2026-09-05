from androguard.core.dex import Operand

from cryptscan.analysis.xref import app_methods, invoke_arg_literals, weak_random_material

_REG = int(Operand.REGISTER)


class _Ins:
    def __init__(self, name, operands):
        self._name = name
        self._operands = operands

    def get_name(self):
        return self._name

    def get_operands(self):
        return self._operands


class _Em:
    def __init__(self, instructions):
        self._instructions = instructions

    def get_instructions_idx(self):
        return list(enumerate(self._instructions))


def _reg(r):
    return (_REG, r)


def _lit(s):
    return (_REG + 999, s)


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


def test_invoke_arg_literals_excludes_receiver():
    # a secret in the receiver register is not read as a putString argument
    em = _Em(
        [
            _Ins("const-string", [_reg(1), _lit("password")]),
            _Ins("invoke-interface", [_reg(1), _reg(2), _reg(3), _lit(_PUTSTRING + "(...)")]),
        ]
    )
    assert list(invoke_arg_literals(em, _PUTSTRING)) == []


def test_invoke_arg_literals_receiver_excludes_charset():
    # "x".getBytes("UTF-8") in receiver mode yields the receiver, not the charset arg
    em = _Em(
        [
            _Ins("const-string", [_reg(0), _lit("passphrase")]),
            _Ins("const-string", [_reg(1), _lit("UTF-8")]),
            _Ins("invoke-virtual", [_reg(0), _reg(1), _lit("Ljava/lang/String;->getBytes(...)")]),
        ]
    )
    got = [v for _, v in invoke_arg_literals(em, r"Ljava/lang/String;->getBytes", receiver=True)]
    assert got == ["passphrase"]


def test_invoke_arg_literals_invalidates_overwritten_register():
    # a tracked literal whose register is reused is not read back (stale mapping)
    em = _Em(
        [
            _Ins("const-string", [_reg(1), _lit("password")]),
            _Ins("move-result-object", [_reg(1)]),
            _Ins("invoke-static", [_reg(1), _lit(_CIPHER_GET + "(...)")]),
        ]
    )
    assert list(invoke_arg_literals(em, _CIPHER_GET)) == []
