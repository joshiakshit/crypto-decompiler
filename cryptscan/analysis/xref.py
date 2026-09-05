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


_REG_WRITE = ("move", "new-instance", "new-array", "const", "aget", "iget", "sget")


def _clears_reg(name: str) -> bool:
    return name.startswith(_REG_WRITE)


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


def invoke_arg_literals(
    em, api_pattern: str, *, receiver: bool = False
) -> Iterator[tuple[int, str]]:
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
            if not targets or not rx.search(targets[0]):
                continue
            regs = _reg_operands(ins)
            if receiver:
                wanted = regs[:1]
            elif "static" in name:
                wanted = regs
            else:
                wanted = regs[1:]
            for r in wanted:
                if r in reg_value:
                    yield reg_value[r]
        elif _clears_reg(name):
            regs = _reg_operands(ins)
            if regs:
                reg_value.pop(regs[0], None)


def weak_random_material(em, weak_pattern: str, sink_pattern: str) -> Iterator[tuple[int, str]]:
    weak_rx = re.compile(weak_pattern)
    sink_rx = re.compile(sink_pattern)
    tainted: dict[int, tuple[int, str]] = {}
    last_weak: tuple[int, str] | None = None  # awaiting a following move-result
    for off, ins in em.get_instructions_idx():
        name = ins.get_name()
        if name.startswith("move-result") and last_weak is not None:
            for r in _reg_operands(ins):
                tainted[r] = last_weak
            last_weak = None
            continue
        last_weak = None
        if _clears_reg(name):
            for r in _reg_operands(ins)[:1]:  # dest reg is first operand; clear stale taint
                tainted.pop(r, None)
            continue
        if not name.startswith("invoke"):
            continue
        targets = [t for t in _str_operands(ins) if "->" in t]
        if not targets:
            continue
        regs = _reg_operands(ins)
        if weak_rx.search(targets[0]):
            for r in regs:
                tainted[r] = (off, targets[0])
            last_weak = (off, targets[0])
        elif sink_rx.search(targets[0]):
            for r in regs:
                if r in tainted:
                    yield tainted[r]
                    break


def field_store_strings(em) -> Iterator[tuple[int, str, str]]:
    reg_value: dict[int, tuple[int, str]] = {}
    for off, ins in em.get_instructions_idx():
        name = ins.get_name()
        if name.startswith("const-string"):
            regs = _reg_operands(ins)
            literals = [s for s in _str_operands(ins) if "->" not in s]
            if regs and literals:
                reg_value[regs[0]] = (off, literals[0])
        elif "put-object" in name:
            regs = _reg_operands(ins)
            fields = [s for s in _str_operands(ins) if "->" in s]
            if regs and fields and regs[0] in reg_value:
                off_value, value = reg_value[regs[0]]
                yield off_value, value, fields[0]
        elif _clears_reg(name):
            regs = _reg_operands(ins)
            if regs:
                reg_value.pop(regs[0], None)


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


def classes_implementing(dx, iface_pattern: str) -> Iterator:
    rx = re.compile(iface_pattern)
    for ca in dx.get_classes():
        if ca.is_external():
            continue
        if any(rx.search(str(iface)) for iface in (ca.implements or [])):
            yield ca
