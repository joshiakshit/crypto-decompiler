from __future__ import annotations

import re
from collections.abc import Iterator

from androguard.core.dex import Operand


def _reg_operands(ins) -> list[int]:
    return [
        int(op[1])
        for op in ins.get_operands()
        if isinstance(op, tuple) and int(op[0]) == int(Operand.REGISTER)
    ]


def _str_operands(ins) -> list[str]:
    values = []
    for op in ins.get_operands():
        last = op[-1] if isinstance(op, tuple) else op
        if isinstance(last, str):
            values.append(last)
    return values


def const_strings(em) -> Iterator[tuple[int, str]]:
    for off, ins in em.get_instructions_idx():
        if ins.get_name().startswith("const-string"):
            for value in _str_operands(ins):
                yield off, value


def invoke_targets(em) -> Iterator[tuple[int, str]]:
    for off, ins in em.get_instructions_idx():
        if ins.get_name().startswith("invoke"):
            for value in _str_operands(ins):
                if "->" in value:
                    yield off, value


def getinstance_args(em, api_pattern: str) -> Iterator[tuple[int, str]]:
    rx = re.compile(api_pattern)
    reg_value: dict[int, tuple[int, str]] = {}
    for off, ins in em.get_instructions_idx():
        name = ins.get_name()
        if name.startswith("const-string"):
            regs = _reg_operands(ins)
            literals = [s for s in _str_operands(ins) if "->" not in s]
            if regs and literals:
                reg_value[regs[0]] = (off, literals[0])
        elif name.startswith("invoke"):
            targets = [t for t in _str_operands(ins) if "->" in t]
            if targets and rx.search(targets[0]):
                for reg in _reg_operands(ins):
                    if reg in reg_value:
                        yield reg_value[reg]
                        break


def method_invokes(em, pattern: str) -> bool:
    rx = re.compile(pattern)
    return any(rx.search(target) for _, target in invoke_targets(em))


def has_opcode(em, prefixes: tuple[str, ...]) -> bool:
    return any(ins.get_name().startswith(prefixes) for _, ins in em.get_instructions_idx())


def app_methods(dx) -> Iterator:
    for ma in dx.get_methods():
        if ma.is_external():
            continue
        em = ma.get_method()
        if em is not None and em.get_code() is not None:
            yield ma


def const_offset(meth, value: str) -> int:
    em = meth.get_method()
    if em is None:
        return 0
    for off, s in const_strings(em):
        if s == value:
            return off
    return 0


def strings_matching(dx, pattern: str) -> Iterator[tuple[str, list[tuple[str, object, int]]]]:
    rx = re.compile(pattern)
    for sa in dx.get_strings():
        value = sa.get_value()
        if rx.search(value):
            refs = [(cls.name, meth, const_offset(meth, value)) for cls, meth in sa.get_xref_from()]
            yield value, refs


def classes_implementing(dx, iface_pattern: str) -> Iterator:
    rx = re.compile(iface_pattern)
    for ca in dx.get_classes():
        if ca.is_external():
            continue
        if any(rx.search(str(iface)) for iface in (ca.implements or [])):
            yield ca
