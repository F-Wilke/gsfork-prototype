.text

.section .gsfork.fork_memory,"ax",@progbits
.globl fork_memory_probe
.type fork_memory_probe,@function
fork_memory_probe:
    push %rbp
    mov %rsi, %rbp
    sub $16, %rsp
    mov %rdx, (%rsp)
    mov %rsp, fork_observed_rsp(%rip)
    mov %rdx, 8(%rdi)
    mov (%rdi), %rax
    add 8(%rdi), %rax
    add (%rbp), %rax
    add (%rsp), %rax
    add $16, %rsp
    pop %rbp
    ret
.size fork_memory_probe, .-fork_memory_probe

.section .gsfork.fork_call,"ax",@progbits
.globl fork_indirect_call
.type fork_indirect_call,@function
fork_indirect_call:
    sub $8, %rsp
    call *(%rdi)
    add $8, %rsp
    ret
.size fork_indirect_call, .-fork_indirect_call

.section .gsfork.fork_jump,"ax",@progbits
.globl fork_indirect_jump
.type fork_indirect_jump,@function
fork_indirect_jump:
    jmp *(%rdi)
.size fork_indirect_jump, .-fork_indirect_jump

.section .gsfork.fork_rip,"ax",@progbits
.globl fork_rip_probe
.type fork_rip_probe,@function
fork_rip_probe:
    mov fork_native_global(%rip), %rax
    ret
.size fork_rip_probe, .-fork_rip_probe

.text
.globl fork_jump_target
.type fork_jump_target,@function
fork_jump_target:
    lea 5(%rsi), %rax
    ret
.size fork_jump_target, .-fork_jump_target

.globl fork_call_on_stack
.type fork_call_on_stack,@function
fork_call_on_stack:
    push %r12
    mov %rsp, %r12
    mov %rsi, %r10
    mov %rdi, %rsp
    and $-16, %rsp
    mov %rdx, %rdi
    mov %rcx, %rsi
    mov %r8, %rdx
    call *%r10
    mov %r12, %rsp
    pop %r12
    ret
.size fork_call_on_stack, .-fork_call_on_stack

.globl fork_raw_to_child_stack
.type fork_raw_to_child_stack,@function
fork_raw_to_child_stack:
    mov %rsi, %r10
    mov %rcx, %r9
    mov $57, %eax
    syscall
    test %rax, %rax
    jne 1f
    mov %rdi, %rsp
    and $-16, %rsp
    mov %rdx, %rdi
    mov %r9, %rsi
    mov %r8, %rdx
    call *%r10
    mov %rax, %rdi
    mov $60, %eax
    syscall
    ud2
1:
    ret
.size fork_raw_to_child_stack, .-fork_raw_to_child_stack

.section .note.GNU-stack,"",@progbits
