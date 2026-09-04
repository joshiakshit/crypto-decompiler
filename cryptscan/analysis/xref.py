from __future__ import annotations

import re
from collections.abc import Iterator


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


def _const_offset(meth, value: str) -> int:
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
            refs = [(cls.name, meth, _const_offset(meth, value)) for cls, meth in sa.get_xref_from()]
            yield value, refs


def classes_implementing(dx, iface_pattern: str) -> Iterator:
    rx = re.compile(iface_pattern)
    for ca in dx.get_classes():
        if ca.is_external():
            continue
        if any(rx.search(str(iface)) for iface in (ca.implements or [])):
            yield ca
