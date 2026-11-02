.text
.globl invoke_parent_leave
.type invoke_parent_leave,@function
invoke_parent_leave:
    pushq %rbp
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    subq $80, %rsp
    movq %rsp, %r12
    movq %rdi, %r14
    movq %rsi, %r13
    movq $158, %rax
    movq $0x1003, %rdi
    movq %r12, %rsi
    syscall
    testq %rax, %rax
    jne .Ldone

    # A private fake TCB: FS:16 holds the signed parent-frame delta.
    movq %r13, 32(%r12)
    movq $0x1234, 48(%r12)
    leaq .Lreturned(%rip), %rax
    movq %rax, 56(%r12)
    leaq 48(%r12), %rbp
    subq %r13, %rbp
    movq $158, %rax
    movq $0x1002, %rdi
    leaq 16(%r12), %rsi
    syscall
    testq %rax, %rax
    jne .Ldone
    pushq $0xad7
    popfq
    movq $0x5678, %rax
    jmp *%r14

.Lreturned:
    pushfq
    popq %r10
    movq %r10, 8(%r12)
    movq %rax, 24(%r12)
    movq %rsp, %r13
    movq %rbp, %r15
    movq %r12, %rsp
    movq $158, %rax
    movq $0x1002, %rdi
    movq (%r12), %rsi
    syscall
    testq %rax, %rax
    jne .Ldone
    leaq 64(%r12), %rax
    cmpq %rax, %r13
    jne .Lbad
    cmpq $0x1234, %r15
    jne .Lbad
    cmpq $0x5678, 24(%r12)
    jne .Lbad
    movq 8(%r12), %rax
    andq $0x8d5, %rax
    cmpq $0x8d5, %rax
    jne .Lbad
    xorl %eax, %eax
    jmp .Ldone
.Lbad:
    movl $1, %eax
.Ldone:
    movq %r12, %rsp
    addq $80, %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbp
    ret
.size invoke_parent_leave,.-invoke_parent_leave
.section .note.GNU-stack,"",@progbits
