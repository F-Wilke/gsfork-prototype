.text
.globl _start
.type _start,@function
_start:
    .cfi_startproc
    leaq __ehdr_start(%rip),%rbx
    xorl %edi,%edi
    cmpl $0x464c457f,(%rbx)
    jne 2f
    cmpw $64,__ehdr_start+52(%rip)
    jne 2f
    cmpw $56,__ehdr_start+54(%rip)
    je 1f
2:
    movl $1,%edi
1:
    movl $60,%eax
    syscall
    .cfi_endproc
.size _start,.-_start

.globl unused_fsbase
.type unused_fsbase,@function
unused_fsbase:
    .cfi_startproc
    rdfsbase %rax
    wrfsbase %rax
    ret
    .cfi_endproc
.size unused_fsbase,.-unused_fsbase
.section .note.GNU-stack,"",@progbits
