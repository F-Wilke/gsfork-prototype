.text
.globl run_kernel
.type run_kernel,@function
run_kernel:
    pushq %rbx
    pushq %rbp
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    movq %rdi,%r12
    movq %rsp,%r13
    movq $158,%rax
    movq $0x1001,%rdi
    movq 0(%r12),%rsi
    syscall
    testq %rax,%rax
    jne .Ldone
    movq 24(%r12),%rsp
    pushq 64(%r12)
    popfq
    movq 32(%r12),%rax
    movq 40(%r12),%rdi
    movq 48(%r12),%rsi
    movq 56(%r12),%rcx
    movq 72(%r12),%rdx
    call *16(%r12)
    movq %rdx,72(%r12)
    movq %rax,32(%r12)
    movq %rdi,40(%r12)
    movq %rsi,48(%r12)
    movq %rcx,56(%r12)
    pushfq
    popq %rax
    movq %rax,64(%r12)
    cld
    movq %r13,%rsp
    movq $158,%rax
    movq $0x1001,%rdi
    movq 8(%r12),%rsi
    syscall
.Ldone:
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbp
    popq %rbx
    ret
.size run_kernel,.-run_kernel
.section .note.GNU-stack,"",@progbits
