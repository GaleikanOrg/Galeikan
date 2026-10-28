gak_read_bits:
    push rbx
    push r12
    push r13
    mov rbx, rdx
    mov r12, r10
    mov r13, r11
    mov r11, QWORD PTR [rax]
    mov rdx, QWORD PTR [rax+16]
    lea r11, [r11+rdx+8]
    xor eax, eax
    xor r8d, r8d
gak_read_bits_loop:
    cmp r8, r12
    jae gak_read_bits_done
    mov r9, rbx
    add r9, r8
    mov rcx, r9
    shr r9, 3
    and ecx, 7
    movzx edx, BYTE PTR [r11+r9]
    test r13, r13
    jnz gak_read_bits_msb
    shr edx, cl
    and edx, 1
    mov ecx, r8d
    shl rdx, cl
    or rax, rdx
    jmp gak_read_bits_next
gak_read_bits_msb:
    mov r9d, 7
    sub r9d, ecx
    mov ecx, r9d
    shr edx, cl
    and edx, 1
    shl rax, 1
    or rax, rdx
gak_read_bits_next:
    inc r8
    jmp gak_read_bits_loop
gak_read_bits_done:
    pop r13
    pop r12
    pop rbx
    ret

gak_write_bits:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rax
    mov r12, rdx
    mov r13, r10
    mov r14, r11
    mov r15, r8
    mov r8, r9
    xor r9d, r9d
gak_write_bits_loop:
    cmp r9, r14
    jae gak_write_bits_done
    mov r10, r12
    add r10, r9
    mov rcx, r10
    shr r10, 3
    sub r10, r13
    and ecx, 7
    test r8, r8
    jz gak_write_bits_lsb
    mov r11d, 7
    sub r11d, ecx
    mov ecx, r11d
gak_write_bits_lsb:
    mov r11d, 1
    shl r11b, cl
    mov rdx, r15
    test r8, r8
    jz gak_write_bits_value_lsb
    mov rcx, r14
    dec rcx
    sub rcx, r9
    jmp gak_write_bits_shift
gak_write_bits_value_lsb:
    mov rcx, r9
gak_write_bits_shift:
    shr rdx, cl
    test dl, 1
    jz gak_write_bits_clear
    or BYTE PTR [rbx+r10+8], r11b
    jmp gak_write_bits_next
gak_write_bits_clear:
    not r11b
    and BYTE PTR [rbx+r10+8], r11b
gak_write_bits_next:
    inc r9
    jmp gak_write_bits_loop
gak_write_bits_done:
    mov rax, rbx
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
