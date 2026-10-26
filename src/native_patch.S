gak_patch_source:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rsi
    push rdi
__SHADOW_ENTER__
    mov rbx, rax
    mov r12, rdx
    mov r13, r10
    mov r14, QWORD PTR [rbx+24]
    sub r14, QWORD PTR [rbx+16]
    mov rax, r14
    call gak_alloc_source_backing
    mov r15, rax
    lea rdi, [r15+8]
    mov rsi, QWORD PTR [rbx]
    add rsi, QWORD PTR [rbx+16]
    add rsi, 8
    mov rcx, r14
    rep movsb
    lea rdi, [r15+r12+8]
    lea rsi, [r13+8]
    mov rcx, QWORD PTR [r13]
    rep movsb
    mov rax, r15
    mov rdx, rbx
    xor r10d, r10d
    mov r11, r14
    mov r8, QWORD PTR [rbx+32]
    inc r8
    call gak_alloc_source
    mov QWORD PTR [rax+48], 2
    mov QWORD PTR [rax+56], r12
    mov r10, r12
    add r10, QWORD PTR [r13]
    mov QWORD PTR [rax+64], r10
__SHADOW_LEAVE__
    pop rdi
    pop rsi
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
