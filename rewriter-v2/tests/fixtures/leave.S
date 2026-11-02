.text
.globl parent_frame_exit
.type parent_frame_exit,@function
parent_frame_exit:
    .cfi_startproc
    .ifdef LEAVE_RSP_CFA
    .cfi_def_cfa %rsp, 8
    .else
    .cfi_def_cfa %rbp, 16
    .endif
    .cfi_offset %rbp, -16
    leave
    .cfi_def_cfa %rsp, 8
    .cfi_restore %rbp
    ret
    .cfi_endproc
.size parent_frame_exit,.-parent_frame_exit
.section .note.GNU-stack,"",@progbits
