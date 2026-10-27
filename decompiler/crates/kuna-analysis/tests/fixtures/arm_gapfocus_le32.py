#!/usr/bin/env python3
"""Authored, Apache-2.0 stripped A32 ELF; no compiler or binary inputs.

Generate with: python3 arm_gapfocus_le32.py OUTPUT

The entry calls twenty leaves (`mov r0,#i; mov r1,#i; bx lr`), which stocks the
gap walk's fingerprint. `found` at 0x1400 opens with the same fingerprint, sits
behind a four-word literal pool and has no inbound reference, so only the gap
walk finds it. It calls a leaf, branches to a block that jumps back into its
body, then dispatches through a guarded `addls pc,pc,r0,lsl #2` table:

    0x1400 mov r0,#7; mov r1,#0; bl leaf_0; cmp r0,#0
    0x1410 bne 0x1450
    0x1414 cmp r0,#3
    0x1418 addls pc,pc,r0,lsl #2
    0x141c b 0x1448        default
    0x1420 b 0x1430        case 0
    0x1424 b 0x1438        case 1
    0x1428 b 0x1448        case 2, the default's target again
    0x142c b 0x1440        case 3
    0x1430.. 0x144c        four `mov r0,#k; bx lr` bodies
    0x1450 mov r0,#5; b 0x1414
"""
import pathlib
import struct
import sys

BASE = 0x1000


def image():
    code = bytearray(0x800)

    def word(at, value):
        code[at - BASE:at - BASE + 4] = struct.pack('<I', value)

    def branch(at, target, opcode=0xEA000000):
        word(at, opcode | (((target - at - 8) // 4) & 0xFFFFFF))

    for at in range(BASE, BASE + len(code), 4):
        word(at, 0xE12FFF1E)
    word(BASE, 0xE92D4000)
    for i in range(20):
        target = 0x1100 + 16 * i
        branch(BASE + 4 + 4 * i, target, 0xEB000000)
        word(target, 0xE3A00000 | i)
        word(target + 4, 0xE3A01000 | i)
    word(BASE + 84, 0xE8BD8000)

    for k, at in enumerate(range(0x13F0, 0x1400, 4)):
        word(at, 0x00000570 + 0x10 * k)
    word(0x1400, 0xE3A00007)
    word(0x1404, 0xE3A01000)
    branch(0x1408, 0x1100, 0xEB000000)
    word(0x140C, 0xE3500000)
    branch(0x1410, 0x1450, 0x1A000000)
    word(0x1414, 0xE3500003)
    word(0x1418, 0x908FF100)
    for at, to in [(0x141C, 0x1448), (0x1420, 0x1430), (0x1424, 0x1438),
                   (0x1428, 0x1448), (0x142C, 0x1440)]:
        branch(at, to)
    for k, at in enumerate([0x1430, 0x1438, 0x1440, 0x1448]):
        word(at, 0xE3A00000 | (k + 1))
        word(at + 4, 0xE12FFF1E)
    word(0x1450, 0xE3A00005)
    branch(0x1454, 0x1414)

    textoff = 0x100
    shstr = b'\0.text\0.shstrtab\0'
    content = bytearray(textoff) + code
    shstroff = len(content)
    content += shstr
    while len(content) % 4:
        content += b'\0'
    sections = [(0,) * 10,
                (1, 1, 6, BASE, textoff, len(code), 0, 0, 4, 0),
                (7, 3, 0, 0, shstroff, len(shstr), 0, 0, 1, 0)]
    shoff = len(content)
    content += b''.join(struct.pack('<10I', *s) for s in sections)
    ident = b'\x7fELF' + bytes([1, 1, 1]) + bytes(9)
    content[:52] = ident + struct.pack('<HHIIIIIHHHHHH', 2, 40, 1, BASE, 52, shoff,
                                       0x05000000, 52, 32, 1, 40, len(sections), 2)
    content[52:84] = struct.pack('<8I', 1, textoff, BASE, BASE, len(code), len(code), 5, 4)
    return content


if __name__ == '__main__':
    pathlib.Path(sys.argv[1]).write_bytes(image())
