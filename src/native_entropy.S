gak_entropy_milli:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rsi
    push rdi
    sub rsp, __STACK_BYTES__
    mov rbx, rax
    mov r12, rdx
    test r12, r12
    jz gak_entropy_zero
    lea r14, [rsp+__COUNTS_OFFSET__]
    mov rdi, r14
    mov ecx, 256
    xor eax, eax
    rep stosq
    xor r13d, r13d
gak_entropy_count:
    cmp r13, r12
    jae gak_entropy_counted
    movzx eax, BYTE PTR [rbx+r13]
    inc QWORD PTR [r14+rax*8]
    inc r13
    jmp gak_entropy_count
gak_entropy_counted:
    mov rax, r12
    call gak_log2_q32
    mov r15, rax
    xor ebx, ebx
    xor esi, esi
gak_entropy_weight:
    cmp rsi, 256
    jae gak_entropy_divide
    mov rdi, QWORD PTR [r14+rsi*8]
    test rdi, rdi
    jz gak_entropy_next
    mov rax, rdi
    call gak_log2_q32
    mov r10, r15
    sub r10, rax
    mov rax, rdi
    mul r10
    add rbx, rax
gak_entropy_next:
    inc rsi
    jmp gak_entropy_weight
gak_entropy_divide:
    mov r13, r12
    shl r13, 32
    mov rax, rbx
    mov ecx, 1000
    mul rcx
    mov r10, r13
    shr r10, 1
    add rax, r10
    adc rdx, 0
    div r13
    jmp gak_entropy_exit
gak_entropy_zero:
    xor eax, eax
gak_entropy_exit:
    add rsp, __STACK_BYTES__
    pop rdi
    pop rsi
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

# Input and output: positive u64 in rax; Q32 log2 in rax.
gak_log2_q32:
    bsr rcx, rax
    mov r8, rcx
    mov edx, 63
    sub edx, ecx
    mov ecx, edx
    shl rax, cl
    mov r9, rax
    xor r11d, r11d
    mov ecx, 31
gak_log2_q32_bit:
    mov rax, r9
    mul r9
    test rdx, rdx
    js gak_log2_q32_upper
    shld rdx, rax, 1
    mov r9, rdx
    jmp gak_log2_q32_next
gak_log2_q32_upper:
    mov r9, rdx
    bts r11, rcx
gak_log2_q32_next:
    dec ecx
    jns gak_log2_q32_bit
    mov rax, r8
    shl rax, 32
    or rax, r11
    ret
