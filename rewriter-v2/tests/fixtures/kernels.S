.text
.globl gs_probe
.type gs_probe,@function
gs_probe:
    .cfi_startproc
    pushq %rbp
    .cfi_def_cfa_offset 16
    .cfi_offset %rbp,-16
    movq %rsp,%rbp
    .cfi_def_cfa_register %rbp
    subq $32,%rsp
    movq (%rdi),%rax
    addq gs_global(%rip),%rax
    pushq (%rdi)
    popq %rcx
    addq %rcx,%rax
    movq %rax,-8(%rbp)
    call *gs_function_slot(%rip)
    movq %rax,-16(%rbp)
    movq -16(%rbp),%rax
    leave
    .cfi_def_cfa %rsp,8
    .cfi_restore %rbp
    ret
    .cfi_endproc
.size gs_probe,.-gs_probe

.globl gs_copy
.type gs_copy,@function
gs_copy:
    .cfi_startproc
    rep movsb
    ret
    .cfi_endproc
.size gs_copy,.-gs_copy

.macro string_function name, operation
.globl \name
.type \name,@function
\name:
    .cfi_startproc
    \operation
    ret
    .cfi_endproc
.size \name,.-\name
.endm

string_function gs_movsw, "rep movsw"
string_function gs_movsd, "rep movsl"
string_function gs_movsq, "rep movsq"
string_function gs_stosb, "rep stosb"
string_function gs_stosw, "rep stosw"
string_function gs_stosd, "rep stosl"
string_function gs_stosq, "rep stosq"
string_function gs_one_movsb, "movsb"
string_function gs_one_movsw, "movsw"
string_function gs_one_movsd, "movsl"
string_function gs_one_movsq, "movsq"
string_function gs_one_stosb, "stosb"
string_function gs_one_stosw, "stosw"
string_function gs_one_stosd, "stosl"
string_function gs_one_stosq, "stosq"

.globl gs_lock
.type gs_lock,@function
gs_lock:
    .cfi_startproc
    testq %rsi,%rsi
    je .L_lock+1
.L_lock:
    lock addq $1,(%rdi)
    ret
    .cfi_endproc
.size gs_lock,.-gs_lock

.globl gs_masked_table
.type gs_masked_table,@function
gs_masked_table:
    .cfi_startproc
    pushq %rbx
    .cfi_def_cfa_offset 16
    .cfi_offset %rbx,-16
    pushq %r12
    .cfi_def_cfa_offset 24
    .cfi_offset %r12,-24
    leaq masked_table+62*9(%rip),%rbx
    movl $63,%r12d
    xorl %eax,%eax
    jmp .L_mask_count
.L_mask_step:
    subq $9,%rbx
.L_mask_count:
    subl $1,%r12d
    jb .L_mask_done
    movl $1,%edx
    movl %r12d,%ecx
    shlq %cl,%rdx
    testb $6,%dl
    je .L_mask_step
    movzbl (%rbx),%edx
    addl %edx,%eax
    jmp .L_mask_step
.L_mask_done:
    popq %r12
    .cfi_def_cfa_offset 16
    .cfi_restore %r12
    popq %rbx
    .cfi_def_cfa_offset 8
    .cfi_restore %rbx
    ret
    .cfi_endproc
.size gs_masked_table,.-gs_masked_table

.globl gs_address
.type gs_address,@function
gs_address:
    .cfi_startproc
    leaq gs_global(%rip),%rax
    ret
    .cfi_endproc
.size gs_address,.-gs_address

.globl gs_jump
.type gs_jump,@function
gs_jump:
    .cfi_startproc
    jmp *gs_function_slot(%rip)
    .cfi_endproc
.size gs_jump,.-gs_jump

.globl gs_plt
.type gs_plt,@function
gs_plt:
    .cfi_startproc
    subq $8,%rsp
    .cfi_def_cfa_offset 16
    call getpid@PLT
    addq $8,%rsp
    .cfi_def_cfa_offset 8
    ret
    .cfi_endproc
.size gs_plt,.-gs_plt

.globl gs_tls
.type gs_tls,@function
gs_tls:
    .cfi_startproc
    movq %fs:-8,%rax
    ret
    .cfi_endproc
.size gs_tls,.-gs_tls

.type gs_target,@function
gs_target:
    .cfi_startproc
    leaq 1(%rax),%rax
    ret
    .cfi_endproc
.size gs_target,.-gs_target

.data
.type masked_table,@object
masked_table:
    .zero 9
    .byte 34
    .zero 8
    .byte 51
    .zero 8
.size masked_table,.-masked_table
.hidden gs_global
.type gs_global,@object
gs_global:
    .quad 11
.size gs_global,8
.type gs_function_slot,@object
gs_function_slot:
    .quad gs_target
.size gs_function_slot,8
.section .note.GNU-stack,"",@progbits
