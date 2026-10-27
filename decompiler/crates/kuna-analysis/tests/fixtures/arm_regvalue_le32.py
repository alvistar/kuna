#!/usr/bin/env python3
"""Authored, Apache-2.0 A32 ELF; no compiler or binary inputs.

Generate with: python3 arm_regvalue_le32.py OUTPUT

A fixed-address `-fPIC`-style image: `.text` at 0x10000, `.rodata` strings at
0x10800 and a `.got` at 0x11000 whose slots hold the strings' addresses (as the
linker writes a local datum's slot with no relocation). The entry calls each
function below. Each keeps a pool-loaded value in a register far from, or
across a branch from, the instruction that uses it:

    far_pair   0x10100  GOT base `ldr r4,[pc]` 11 instructions before its
                        `add r4,pc,r4`, then `ldr r3,[pc]; ldr r0,[r4,r3]` reads
                        slot 0x11000
    far_offset 0x10200  the GOT offset `ldr r3,[pc]` 25 instructions before
                        `ldr r1,[r5,r3]`, base pair adjacent; reads slot 0x11004
    far_branch 0x10300  `ldr r0,[pc]; b 1f; ...; 1: add r0,pc,r0` forms the
                        string at 0x10820
    spill      0x10400  base made in r3, `str r3,[sp,#4]`, a call clobbers r3,
                        `sub sp,sp,#8`, `ldr r2,[sp,#12]` reloads it, then
                        `ldr r1,[pc]; ldr r0,[r2,r1]` reads slot 0x11008
    pushpop    0x10500  base in r4, `push {r4}`, r4 overwritten, `pop {r4}`,
                        then reads slot 0x1100c through r4
    overwrite  0x10600  as `spill`, but `str r0,[sp,#4]` overwrites the slot
                        before the reload: no slot read may be filed
"""
import pathlib
import struct
import sys

TEXT = 0x10000
RODATA = 0x10800
GOT = 0x11000
STRINGS = [b'far pair\0', b'far offset\0', b'far branch\0', b'spill\0', b'pushpop\0', b'overwrite\0']


def image():
    code = bytearray(0x800)
    rodata = bytearray()
    addrs = []
    for s in STRINGS:
        while len(rodata) % 0x10:
            rodata += b'\0'
        addrs.append(RODATA + len(rodata))
        rodata += s
    rodata = bytes(rodata)
    got = b''.join(struct.pack('<I', a) for a in addrs[:2] + addrs[3:6]) + bytes(12)

    def word(at, value):
        code[at - TEXT:at - TEXT + 4] = struct.pack('<I', value)

    def branch(at, target, opcode=0xEA000000):
        word(at, opcode | (((target - at - 8) // 4) & 0xFFFFFF))

    def ldr_pc(at, rt, pool):
        word(at, 0xE59F0000 | rt << 12 | (pool - at - 8))

    def add_pc(at, rd, rm):
        word(at, 0xE08F0000 | rd << 12 | rm)

    def ldr_reg(at, rt, rn, rm):
        word(at, 0xE7900000 | rn << 16 | rt << 12 | rm)

    def filler(at, n):
        for i in range(n):
            word(at + 4 * i, 0xE28CC001)
        return at + 4 * n

    for at in range(TEXT, TEXT + len(code), 4):
        word(at, 0xE12FFF1E)
    funcs = [0x10100, 0x10200, 0x10300, 0x10400, 0x10500, 0x10600]
    word(TEXT, 0xE92D4000)
    for i, f in enumerate(funcs):
        branch(TEXT + 4 + 4 * i, f, 0xEB000000)
    word(TEXT + 4 + 4 * len(funcs), 0xE8BD8000)
    leaf = 0x10080
    word(leaf, 0xE3A03000)
    word(leaf + 4, 0xE12FFF1E)

    def frame(f, body, pool_words):
        """push {r4,r5,lr}; body; pop {r4,r5,pc}; pool after it."""
        word(f, 0xE92D4030)
        at = body(f + 4)
        word(at, 0xE8BD8030)
        pool = at + 4
        for k, w in enumerate(pool_words):
            word(pool + 4 * k, w)
        return pool

    def far_pair(at):
        p = at + 4 * 16
        ldr_pc(at, 4, p)
        at = filler(at + 4, 10)
        add = at
        add_pc(at, 4, 4)
        ldr_pc(at + 4, 3, p + 4)
        ldr_reg(at + 8, 0, 4, 3)
        word(p, GOT - (add + 8))
        word(p + 4, 0)
        return at + 12
    frame(0x10100, far_pair, [])

    def far_offset(at):
        p = at + 4 * 32
        ldr_pc(at, 3, p + 8)
        at = filler(at + 4, 21)
        ldr_pc(at, 5, p)
        add_pc(at + 4, 5, 5)
        ldr_reg(at + 8, 1, 5, 3)
        word(p, GOT - (at + 4 + 8))
        word(p + 8, 4)
        return at + 12
    frame(0x10200, far_offset, [])

    def far_branch(at):
        p = at + 4 * 16
        ldr_pc(at, 0, p)
        target = at + 4 * 8
        branch(at + 4, target)
        add_pc(target, 0, 0)
        word(p, addrs[2] - (target + 8))
        return target + 4
    frame(0x10300, far_branch, [])

    def spill(at, overwrite=False, slot_off=8):
        p = at + 4 * 16
        ldr_pc(at, 3, p)
        add_pc(at + 4, 3, 3)
        word(at + 8, 0xE58D3004)
        branch(at + 12, leaf, 0xEB000000)
        at += 16
        if overwrite:
            word(at, 0xE58D0004)
            at += 4
        word(at, 0xE24DD008)
        word(at + 4, 0xE59D200C)
        ldr_pc(at + 8, 1, p + 4)
        ldr_reg(at + 12, 0, 2, 1)
        word(at + 16, 0xE28DD008)
        return at + 20, p
    def spill_body(at):
        end, p = spill(at)
        word(p, GOT - (at + 4 + 8))
        word(p + 4, 8)
        return end
    frame(0x10400, spill_body, [])

    def pushpop(at):
        p = at + 4 * 16
        ldr_pc(at, 4, p)
        add_pc(at + 4, 4, 4)
        word(at + 8, 0xE52D4004)
        word(at + 12, 0xE3A04007)
        word(at + 16, 0xE49D4004)
        ldr_pc(at + 20, 3, p + 4)
        ldr_reg(at + 24, 0, 4, 3)
        word(p, GOT - (at + 4 + 8))
        word(p + 4, 0xC)
        return at + 28
    frame(0x10500, pushpop, [])

    def overwrite_body(at):
        end, p = spill(at, overwrite=True)
        word(p, GOT - (at + 4 + 8))
        word(p + 4, 0x10)
        return end
    frame(0x10600, overwrite_body, [])

    return elf(bytes(code), rodata, got)


def elf(code, rodata, got):
    textoff, rooff, gotoff = 0x1000, 0x1800, 0x2000
    shstr = b'\0.text\0.rodata\0.got\0.shstrtab\0'
    content = bytearray(textoff) + code
    content += bytes(rooff - len(content)) + rodata
    content += bytes(gotoff - len(content)) + got
    shstroff = len(content)
    content += shstr
    while len(content) % 4:
        content += b'\0'
    sections = [(0,) * 10,
                (1, 1, 6, TEXT, textoff, len(code), 0, 0, 4, 0),
                (7, 1, 2, RODATA, rooff, len(rodata), 0, 0, 4, 0),
                (15, 1, 3, GOT, gotoff, len(got), 0, 0, 4, 4),
                (20, 3, 0, 0, shstroff, len(shstr), 0, 0, 1, 0)]
    shoff = len(content)
    content += b''.join(struct.pack('<10I', *s) for s in sections)
    ident = b'\x7fELF' + bytes([1, 1, 1]) + bytes(9)
    content[:52] = ident + struct.pack('<HHIIIIIHHHHHH', 2, 40, 1, TEXT, 52, shoff,
                                       0x05000000, 52, 32, 2, 40, len(sections), 4)
    rx = rooff + len(rodata) - textoff
    content[52:84] = struct.pack('<8I', 1, textoff, TEXT, TEXT, rx, rx, 5, 0x1000)
    content[84:116] = struct.pack('<8I', 1, gotoff, GOT, GOT, len(got), len(got), 6, 0x1000)
    return content


if __name__ == '__main__':
    pathlib.Path(sys.argv[1]).write_bytes(image())
