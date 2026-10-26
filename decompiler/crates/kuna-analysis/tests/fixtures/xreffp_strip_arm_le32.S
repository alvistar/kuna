/* Fixture source for `xreffp_strip_arm_le32`: a stripped static ARM ELF
   (A32 and one Thumb-2 function) mapped at 0x10000, whose only symbol-free
   seed is `_start`. Every other function is found from a call.

   `falls_in` ends in a predicated `moveq` whose condition skip runs into
   `found_by_call`. `dispatch_last` is an A32 table dispatch whose skip runs
   into `after_dispatch`, the next function's entry. `it_branch` holds a real
   conditional branch to the next instruction inside an `it eq` block
   (`beq.w`), which lifts to the condition skip and the branch, both to the
   next instruction.

   Built with GCC 14.2 for armhf musl (homebrew `musl-cross` 0.9.11); the
   SHA-256 below is that toolchain's output:

       arm-linux-musleabihf-gcc -march=armv7-a+fp -nostdlib -static \
           -Wl,--build-id=none -s \
           -o xreffp_strip_arm_le32 xreffp_strip_arm_le32.S

   SHA-256 95c02f85431a4167cdb9ae4060e2dd9ef559f7024fe386b517415ff9e32d22ad. */

    .syntax unified
    .text
    .arm
    .global _start
_start:
    bl      found_by_call
    bl      falls_in
    bl      dispatch_last
    blx     it_branch
    bl      after_dispatch
    mov     r7, #1
    svc     #0

falls_in:
    cmp     r0, #1
    moveq   r0, #2
found_by_call:
    add     r0, r0, #1
    bx      lr

dispatch_last:
    cmp     r0, #1
    addls   pc, pc, r0, lsl #2
after_dispatch:
    bx      lr
    b       1f
    b       2f
1:  mov     r0, #1
    bx      lr
2:  mov     r0, #2
    bx      lr

    .thumb
    .thumb_func
it_branch:
    cmp     r0, #0
    it      eq
    beq.w   3f
3:  adds    r0, #1
    bx      lr
