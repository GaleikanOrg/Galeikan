gak_splice_source:
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
    mov r14, r11
    mov r15, QWORD PTR [rbx+24]
    sub r15, QWORD PTR [rbx+16]
    mov rax, r15
    sub rax, r13
    add rax, QWORD PTR [r14]
    call gak_alloc_source_backing
    mov r15, rax
    lea rdi, [r15+8]
    mov rsi, QWORD PTR [rbx]
    add rsi, QWORD PTR [rbx+16]
    add rsi, 8
    mov rcx, r12
    rep movsb
    lea rsi, [r14+8]
    mov rcx, QWORD PTR [r14]
    rep movsb
    mov rsi, QWORD PTR [rbx]
    add rsi, QWORD PTR [rbx+16]
    add rsi, r12
    add rsi, r13
    add rsi, 8
    mov rcx, QWORD PTR [rbx+24]
    sub rcx, QWORD PTR [rbx+16]
    sub rcx, r12
    sub rcx, r13
    rep movsb
    mov rax, r15
    mov rdx, rbx
    xor r10d, r10d
    mov r11, QWORD PTR [r15]
    mov r8, QWORD PTR [rbx+32]
    inc r8
    call gak_alloc_source
    mov QWORD PTR [rax+48], 3
    mov QWORD PTR [rax+56], r12
    mov r10, r12
    add r10, r13
    mov QWORD PTR [rax+64], r10
    mov r10, QWORD PTR [r14]
    mov QWORD PTR [rax+72], r10
__SHADOW_LEAVE__
    pop rdi
    pop rsi
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
