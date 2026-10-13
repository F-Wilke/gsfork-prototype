/* Hand-written stand-in for the eventual REP MOVSB binary rewrite.
 * SysV x86-64: RDI=dst, RSI=src, RDX=bytes. Neither routine touches RSP.
 * The wrapper uses FS-relative per-thread scratch, preserving RAX and all
 * arithmetic flags. Signal entry must save/swap scratch and normalize the
 * translated RSI/RDI if interrupted inside the wrapper.
 */
.text
.p2align 4
.globl rep_movsb_copy_native
.type rep_movsb_copy_native, @function
rep_movsb_copy_native:
    movq %rdx, %rcx
    rep movsb
    ret
.size rep_movsb_copy_native, .-rep_movsb_copy_native

.p2align 4
.globl rep_movsb_copy_wrapped
.type rep_movsb_copy_wrapped, @function
rep_movsb_copy_wrapped:
    movq %rax, %fs:rep_scratch_rax@TPOFF
    lahf
    seto %al
    addq %fs:rep_sandbox_offset@TPOFF, %rdi
    addq %fs:rep_sandbox_offset@TPOFF, %rsi
    movq %rdx, %rcx
    rep movsb
    subq %fs:rep_sandbox_offset@TPOFF, %rdi
    subq %fs:rep_sandbox_offset@TPOFF, %rsi
    addb $0x7f, %al   /* reconstruct saved OF; SAHF leaves OF untouched */
    sahf
    movq %fs:rep_scratch_rax@TPOFF, %rax
    ret
.size rep_movsb_copy_wrapped, .-rep_movsb_copy_wrapped
.section .note.GNU-stack,"",@progbits
