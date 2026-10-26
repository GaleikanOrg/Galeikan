gak_parse_hunt_hex:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rsi
    push rdi
__SHADOW_ENTER__
    mov rbx, rax
    mov r12d, 4
    xor r13d, r13d
    xor r14d, r14d
gak_hunt_hex_validate:
    cmp r12, QWORD PTR [rbx]
    jae gak_hunt_hex_validated
    movzx eax, BYTE PTR [rbx+r12+8]
    cmp al, 32
    je gak_hunt_hex_validate_next
    cmp al, 9
    jb gak_hunt_hex_digit
    cmp al, 13
    jbe gak_hunt_hex_validate_next
gak_hunt_hex_digit:
    cmp al, '?'
    je gak_hunt_hex_wildcard
    cmp al, '0'
    jb gak_hunt_hex_invalid
    cmp al, '9'
    jbe gak_hunt_hex_nibble
    cmp al, 'A'
    jb gak_hunt_hex_invalid
    cmp al, 'F'
    jbe gak_hunt_hex_nibble
    cmp al, 'a'
    jb gak_hunt_hex_invalid
    cmp al, 'f'
    ja gak_hunt_hex_invalid
    jmp gak_hunt_hex_nibble
gak_hunt_hex_wildcard:
    mov r14d, 1
gak_hunt_hex_nibble:
    inc r13
    test r13, 1
    jnz gak_hunt_hex_validate_next
    cmp r13, 2097152
    ja gak_hunt_hex_too_long
gak_hunt_hex_validate_next:
    inc r12
    jmp gak_hunt_hex_validate
gak_hunt_hex_validated:
    test r13, 1
    jnz gak_hunt_hex_odd
    mov r15, r13
    shr r15, 1
    test r14, r14
    jz gak_hunt_hex_allocate
    cmp r15, 64
    ja gak_hunt_hex_mask_too_long
gak_hunt_hex_allocate:
    mov rax, r15
    call gak_alloc_bytes
    mov r12, rax
    mov rax, r15
    call gak_alloc_bytes
    mov r13, rax
    mov r15d, 4
    xor edi, edi
    mov r8d, -1
gak_hunt_hex_write:
    cmp r15, QWORD PTR [rbx]
    jae gak_hunt_hex_written
    movzx eax, BYTE PTR [rbx+r15+8]
    cmp al, 32
    je gak_hunt_hex_write_next
    cmp al, 9
    jb gak_hunt_hex_convert
    cmp al, 13
    jbe gak_hunt_hex_write_next
gak_hunt_hex_convert:
    mov ecx, 15
    cmp al, '?'
    je gak_hunt_hex_question
    cmp al, '9'
    jbe gak_hunt_hex_numeric
    cmp al, 'F'
    jbe gak_hunt_hex_upper
    sub eax, 87
    jmp gak_hunt_hex_store_nibble
gak_hunt_hex_upper:
    sub eax, 55
    jmp gak_hunt_hex_store_nibble
gak_hunt_hex_numeric:
    sub eax, 48
    jmp gak_hunt_hex_store_nibble
gak_hunt_hex_question:
    xor eax, eax
    xor ecx, ecx
gak_hunt_hex_store_nibble:
    cmp r8d, -1
    jne gak_hunt_hex_store_low
    shl eax, 4
    shl ecx, 4
    mov r8d, eax
    mov r9d, ecx
    jmp gak_hunt_hex_write_next
gak_hunt_hex_store_low:
    or eax, r8d
    or ecx, r9d
    mov BYTE PTR [r12+rdi+8], al
    mov BYTE PTR [r13+rdi+8], cl
    inc rdi
    mov r8d, -1
gak_hunt_hex_write_next:
    inc r15
    jmp gak_hunt_hex_write
gak_hunt_hex_written:
    mov rax, r12
    mov rdx, r13
    mov r10, r14
    xor r11d, r11d
    jmp gak_hunt_hex_exit
gak_hunt_hex_invalid:
    mov r11d, 1
    jmp gak_hunt_hex_failed
gak_hunt_hex_too_long:
    mov r11d, 2
    jmp gak_hunt_hex_failed
gak_hunt_hex_odd:
    mov r11d, 3
    jmp gak_hunt_hex_failed
gak_hunt_hex_mask_too_long:
    mov r11d, 4
gak_hunt_hex_failed:
    xor eax, eax
gak_hunt_hex_exit:
__SHADOW_LEAVE__
    pop rdi
    pop rsi
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

gak_hunt_search:
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
    test r8, r8
    jnz gak_hunt_mode_ready
    xor r14d, r14d
gak_hunt_mode_ready:
    xor r15d, r15d
    mov rax, QWORD PTR [r13]
    cmp rax, r12
    ja gak_hunt_no_possible_match
    test r14, r14
    jnz gak_hunt_count
    shl rax, 3
    mov __MALLOC_ARG__, rax
    call malloc
    test rax, rax
    jz gak_alloc_failure
    mov r15, rax
    mov QWORD PTR [r15], 0
    mov r8d, 1
    xor r9d, r9d
gak_hunt_prefix_next:
    cmp r8, QWORD PTR [r13]
    jae gak_hunt_count
    movzx r10d, BYTE PTR [r13+r8+8]
gak_hunt_prefix_retry:
    test r9, r9
    jz gak_hunt_prefix_compare
    movzx r11d, BYTE PTR [r13+r9+8]
    cmp r10b, r11b
    je gak_hunt_prefix_equal
    mov r9, QWORD PTR [r15+r9*8-8]
    jmp gak_hunt_prefix_retry
gak_hunt_prefix_compare:
    movzx r11d, BYTE PTR [r13+r9+8]
    cmp r10b, r11b
    jne gak_hunt_prefix_store
gak_hunt_prefix_equal:
    inc r9
gak_hunt_prefix_store:
    mov QWORD PTR [r15+r8*8], r9
    inc r8
    jmp gak_hunt_prefix_next
gak_hunt_count:
    xor edi, edi
    call gak_hunt_scan
    cmp rax, -1
    je gak_hunt_too_many
    call gak_alloc_list
    mov rsi, rax
    mov rdi, rax
    call gak_hunt_scan
    mov r12, rsi
    test r15, r15
    jz gak_hunt_return_list
    mov __FREE_ARG__, r15
    call free
gak_hunt_return_list:
    mov rax, r12
    jmp gak_hunt_search_exit
gak_hunt_too_many:
    test r15, r15
    jz gak_hunt_too_many_done
    mov __FREE_ARG__, r15
    call free
gak_hunt_too_many_done:
    mov rax, -1
    jmp gak_hunt_search_exit
gak_hunt_no_possible_match:
    xor eax, eax
    call gak_alloc_list
gak_hunt_search_exit:
__SHADOW_LEAVE__
    pop rdi
    pop rsi
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

gak_hunt_scan:
    xor r8d, r8d
    xor edx, edx
    test r14, r14
    jnz gak_hunt_masked_outer
    xor r9d, r9d
gak_hunt_kmp_outer:
    cmp r8, r12
    jae gak_hunt_scan_done
    movzx r10d, BYTE PTR [rbx+r8]
gak_hunt_kmp_retry:
    movzx r11d, BYTE PTR [r13+r9+8]
    cmp r10b, r11b
    je gak_hunt_kmp_match_byte
    test r9, r9
    jz gak_hunt_kmp_next
    mov r9, QWORD PTR [r15+r9*8-8]
    jmp gak_hunt_kmp_retry
gak_hunt_kmp_match_byte:
    inc r9
    cmp r9, QWORD PTR [r13]
    jne gak_hunt_kmp_next
    cmp rdx, 10000
    jae gak_hunt_scan_too_many
    test rdi, rdi
    jz gak_hunt_kmp_count
    mov rcx, r8
    inc rcx
    sub rcx, r9
    mov QWORD PTR [rdi+rdx*8+8], rcx
gak_hunt_kmp_count:
    inc rdx
    mov r9, QWORD PTR [r15+r9*8-8]
gak_hunt_kmp_next:
    inc r8
    jmp gak_hunt_kmp_outer
gak_hunt_masked_outer:
    mov rcx, r8
    add rcx, QWORD PTR [r13]
    cmp rcx, r12
    ja gak_hunt_scan_done
    xor r9d, r9d
gak_hunt_masked_inner:
    cmp r9, QWORD PTR [r13]
    jae gak_hunt_masked_hit
    mov rcx, r8
    add rcx, r9
    movzx r10d, BYTE PTR [rbx+rcx]
    movzx r11d, BYTE PTR [r14+r9+8]
    and r10d, r11d
    cmp r10b, BYTE PTR [r13+r9+8]
    jne gak_hunt_masked_next
    inc r9
    jmp gak_hunt_masked_inner
gak_hunt_masked_hit:
    cmp rdx, 10000
    jae gak_hunt_scan_too_many
    test rdi, rdi
    jz gak_hunt_masked_count
    mov QWORD PTR [rdi+rdx*8+8], r8
gak_hunt_masked_count:
    inc rdx
gak_hunt_masked_next:
    inc r8
    jmp gak_hunt_masked_outer
gak_hunt_scan_done:
    mov rax, rdx
    ret
gak_hunt_scan_too_many:
    mov rax, -1
    ret
