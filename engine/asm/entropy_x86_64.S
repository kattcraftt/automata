/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
.global mem_diff_count_asm
.text
mem_diff_count_asm:
    /* rdi = a, rsi = b, rdx = size */
    xor %rax, %rax
    test %rdx, %rdx
    jz .Lend
.Lloop:
    movzbq (%rdi), %rcx
    movzbq (%rsi), %r8
    cmp %rcx, %r8
    je .Lnext
    inc %rax
.Lnext:
    inc %rdi
    inc %rsi
    dec %rdx
    jnz .Lloop
.Lend:
    ret
