# Inputs: rax = left Source, rdx = right Source, r10 = maximum differences.
# Returns a Diff descriptor [left, right, offsets] or -1 when the limit is exceeded.
gak_diff_source:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rsi
__FRAME_ENTER__
    mov rbx, rax
    mov r12, rdx
    mov r13, r10
    xor r15d, r15d
    call gak_diff_scan
    cmp rax, -1
    je gak_diff_source_done
    call gak_alloc_list
    mov r15, rax
    call gak_diff_scan
    mov r10, QWORD PTR [rip+gak_diff_bytes]
    add r10, 24
    jc gak_diff_memory
    cmp r10, 67108864
    ja gak_diff_memory
    mov QWORD PTR [rip+gak_diff_bytes], r10
    mov __MALLOC_ARG__, 24
    call malloc
    test rax, rax
    jz gak_alloc_failure
    mov QWORD PTR [rax], rbx
    mov QWORD PTR [rax+8], r12
    mov QWORD PTR [rax+16], r15
gak_diff_source_done:
__FRAME_LEAVE__
    pop rsi
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

# Scan the visible byte ranges. With r15 = 0, count differences; otherwise
# write their offsets into the previously allocated list. rax = count or -1.
gak_diff_scan:
    mov r8, QWORD PTR [rbx]
    mov r9, QWORD PTR [rbx+16]
    lea r8, [r8+r9+8]
    mov r9, QWORD PTR [r12]
    mov r10, QWORD PTR [r12+16]
    lea r9, [r9+r10+8]
    mov r10, QWORD PTR [rbx+24]
    sub r10, QWORD PTR [rbx+16]
    mov r11, QWORD PTR [r12+24]
    sub r11, QWORD PTR [r12+16]
    mov rcx, r10
    cmp rcx, r11
    cmova rcx, r11
    mov rdx, r10
    cmp rdx, r11
    cmovb rdx, r11
    xor esi, esi
    xor eax, eax
gak_diff_common:
    cmp rsi, rcx
    jae gak_diff_tail
    movzx r10d, BYTE PTR [r8+rsi]
    cmp r10b, BYTE PTR [r9+rsi]
    je gak_diff_next
    cmp rax, r13
    jae gak_diff_scan_many
    test r15, r15
    jz gak_diff_count
    mov QWORD PTR [r15+rax*8+8], rsi
gak_diff_count:
    inc rax
gak_diff_next:
    inc rsi
    jmp gak_diff_common
gak_diff_tail:
    mov r8, rdx
    sub r8, rcx
    mov r9, r13
    sub r9, rax
    cmp r8, r9
    ja gak_diff_scan_many
    test r15, r15
    jz gak_diff_tail_count
gak_diff_tail_fill:
    cmp rsi, rdx
    jae gak_diff_tail_count
    mov QWORD PTR [r15+rax*8+8], rsi
    inc rax
    inc rsi
    jmp gak_diff_tail_fill
gak_diff_tail_count:
    test r15, r15
    jnz gak_diff_scan_done
    add rax, r8
gak_diff_scan_done:
    ret
gak_diff_scan_many:
    mov rax, -1
    ret
