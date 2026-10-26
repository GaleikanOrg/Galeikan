.intel_syntax noprefix

.section .rdata,"dr"
usage:       .asciz "Usage: galeikan-script.exe [--allow-read] <file.gak>"
allow_flag:  .asciz "--allow-read"
cap_error:   .asciz "observe requires --allow-read (line %llu).\n"
decl_error:  .asciz "observe requires { file.read } (line %llu).\n"
obs_error:   .asciz "Observation failed: %s @ %llu (file/range).\n"
obs_u8_fmt:  .asciz "%s @ %llu u8 = %llu\n"
obs_u16_fmt: .asciz "%s @ %llu u16le = %llu\n"
obs_u32_fmt: .asciz "%s @ %llu u32le = %llu\n"
open_error:  .asciz "Cannot open file: %s\n"
read_error:  .asciz "Cannot read file.\n"
syntax_error:.asciz "Syntax error on line %llu.\n"
number_fmt:  .asciz "%lld\n"
read_mode:   .asciz "rb"
print_kw:    .asciz "print"
observe_kw:  .asciz "observe"
requires_kw: .asciz "requires"
file_read_kw:.asciz "file.read"
at_kw:       .asciz "at"
as_kw:       .asciz "as"
u8_kw:       .asciz "u8"
u16_kw:      .asciz "u16le"
u32_kw:      .asciz "u32le"

.section .bss,"bw"
.align 16
line_buffer: .space 4096
read_buffer: .space 4
declared_read: .long 0
statement_seen:.long 0

.section .text,"xr"
.globl main
.def main; .scl 2; .type 32; .endef
main:
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 56                 # Win64 shadow space plus local end pointer

    xor r15d, r15d             # file-read capability disabled by default
    mov dword ptr [rip+declared_read], 0
    mov dword ptr [rip+statement_seen], 0
    cmp ecx, 2
    je plain_script
    cmp ecx, 3
    jne show_usage
    mov r12, rdx                # argv
    lea rcx, [rip+allow_flag]
    mov rdx, qword ptr [r12+8]
    call strcmp
    test eax, eax
    jne show_usage
    mov rdi, qword ptr [r12+16]
    mov r15d, 1
    jmp open_script
plain_script:
    mov rdi, qword ptr [rdx+8] # argv[1]
open_script:
    mov rcx, rdi
    lea rdx, [rip+read_mode]
    call fopen
    test rax, rax
    jz cannot_open
    mov rbx, rax                 # FILE *
    xor edi, edi                 # line number

read_line:
    lea rcx, [rip+line_buffer]
    mov edx, 4096
    mov r8, rbx
    call fgets
    test rax, rax
    jz end_of_file
    inc rdi
    lea rcx, [rip+line_buffer]
    call strlen
    cmp rax, 4095              # reject a line that might have been truncated
    jae bad_syntax
    lea rsi, [rip+line_buffer]

skip_leading:
    mov al, byte ptr [rsi]
    cmp al, ' '
    je advance_leading
    cmp al, 9
    je advance_leading
    cmp al, 13
    je read_line
    cmp al, 10
    je read_line
    test al, al
    jz read_line
    cmp al, '#'
    je read_line
    jmp dispatch_statement
advance_leading:
    inc rsi
    jmp skip_leading

dispatch_statement:
    mov rcx, rsi
    lea rdx, [rip+requires_kw]
    mov r8d, 8
    call strncmp
    test eax, eax
    je parse_requires
    mov rcx, rsi
    lea rdx, [rip+print_kw]
    mov r8d, 5
    call strncmp
    test eax, eax
    jne expect_observe
    mov dword ptr [rip+statement_seen], 1
    add rsi, 5
    mov al, byte ptr [rsi]
    cmp al, ' '
    je skip_after_print
    cmp al, 9
    jne bad_syntax

skip_after_print:
    mov al, byte ptr [rsi]
    cmp al, ' '
    je advance_after_print
    cmp al, 9
    je advance_after_print
    cmp al, '"'
    je parse_string
    jmp parse_integer
advance_after_print:
    inc rsi
    jmp skip_after_print

parse_string:
    inc rsi
    mov r12, rsi                 # first byte after opening quote
find_closing_quote:
    mov al, byte ptr [rsi]
    test al, al
    jz bad_syntax
    cmp al, 13
    je bad_syntax
    cmp al, 10
    je bad_syntax
    cmp al, '"'
    je close_string
    inc rsi
    jmp find_closing_quote
close_string:
    mov byte ptr [rsi], 0
    inc rsi
    call validate_tail
    test eax, eax
    jnz bad_syntax
    mov rcx, r12
    call puts
    jmp read_line

expect_observe:
    mov rcx, rsi
    lea rdx, [rip+observe_kw]
    mov r8d, 7
    call strncmp
    test eax, eax
    jne bad_syntax
    mov dword ptr [rip+statement_seen], 1
    add rsi, 7
    mov al, byte ptr [rsi]
    cmp al, ' '
    je observe_start
    cmp al, 9
    jne bad_syntax
observe_start:
    cmp dword ptr [rip+declared_read], 1
    jne declaration_missing
    test r15d, r15d
    jz capability_denied
    call skip_horizontal
    cmp byte ptr [rsi], '"'
    jne bad_syntax
    inc rsi
    mov r12, rsi                # observed file path
observe_path_end:
    mov al, byte ptr [rsi]
    test al, al
    jz bad_syntax
    cmp al, 13
    je bad_syntax
    cmp al, 10
    je bad_syntax
    cmp al, '"'
    je observe_after_path
    inc rsi
    jmp observe_path_end
observe_after_path:
    mov byte ptr [rsi], 0
    inc rsi
    call skip_horizontal
    mov rcx, rsi
    lea rdx, [rip+at_kw]
    mov r8d, 2
    call strncmp
    test eax, eax
    jne bad_syntax
    add rsi, 2
    mov al, byte ptr [rsi]
    cmp al, ' '
    je observe_offset
    cmp al, 9
    jne bad_syntax
observe_offset:
    call skip_horizontal
    mov qword ptr [rsp+40], rsi
    call _errno
    mov dword ptr [rax], 0
    mov rcx, rsi
    lea rdx, [rsp+32]
    mov r8d, 10
    call strtoll
    mov r13, rax                # file offset
    mov rsi, qword ptr [rsp+32]
    cmp rsi, qword ptr [rsp+40]
    je bad_syntax
    test r13, r13
    js bad_syntax
    call _errno
    cmp dword ptr [rax], 0
    jne bad_syntax
    call skip_horizontal
    mov rcx, rsi
    lea rdx, [rip+as_kw]
    mov r8d, 2
    call strncmp
    test eax, eax
    jne bad_syntax
    add rsi, 2
    mov al, byte ptr [rsi]
    cmp al, ' '
    je observe_type
    cmp al, 9
    jne bad_syntax
observe_type:
    call skip_horizontal
    mov rcx, rsi
    lea rdx, [rip+u8_kw]
    mov r8d, 2
    call strncmp
    test eax, eax
    je observe_u8
    mov rcx, rsi
    lea rdx, [rip+u16_kw]
    mov r8d, 5
    call strncmp
    test eax, eax
    je observe_u16_check
    mov rcx, rsi
    lea rdx, [rip+u32_kw]
    mov r8d, 5
    call strncmp
    test eax, eax
    je observe_u32_check
    jmp bad_syntax
observe_u8:
    mov r14d, 1
    add rsi, 2
    jmp observe_validate
observe_u16_check:
    mov r14d, 2
    add rsi, 5
    jmp observe_validate
observe_u32_check:
    mov r14d, 4
    add rsi, 5
observe_validate:
    call validate_tail
    test eax, eax
    jnz bad_syntax
    mov rcx, r12
    lea rdx, [rip+read_mode]
    call fopen
    test rax, rax
    jz observation_failed
    mov rsi, rax                # observed FILE *
    mov rcx, rsi
    mov rdx, r13
    xor r8d, r8d                # SEEK_SET
    call _fseeki64
    test eax, eax
    jnz observation_close_failed
    lea rcx, [rip+read_buffer]
    mov edx, 1
    mov r8, r14
    mov r9, rsi
    call fread
    cmp rax, r14
    jne observation_close_failed
    mov rcx, rsi
    call fclose
    cmp r14d, 1
    je print_observation_u8
    cmp r14d, 2
    je print_observation_u16
    mov eax, dword ptr [rip+read_buffer]
    lea rcx, [rip+obs_u32_fmt]
    jmp print_observation
print_observation_u8:
    movzx eax, byte ptr [rip+read_buffer]
    lea rcx, [rip+obs_u8_fmt]
    jmp print_observation
print_observation_u16:
    movzx eax, word ptr [rip+read_buffer]
    lea rcx, [rip+obs_u16_fmt]
print_observation:
    mov rdx, r12
    mov r8, r13
    mov r9, rax
    call printf
    jmp read_line
observation_close_failed:
    mov rcx, rsi
    call fclose
observation_failed:
    lea rcx, [rip+obs_error]
    mov rdx, r12
    mov r8, r13
    call printf
    mov rcx, rbx
    call fclose
    mov eax, 3
    jmp done

capability_denied:
    lea rcx, [rip+cap_error]
    mov rdx, rdi
    call printf
    mov rcx, rbx
    call fclose
    mov eax, 3
    jmp done

declaration_missing:
    lea rcx, [rip+decl_error]
    mov rdx, rdi
    call printf
    mov rcx, rbx
    call fclose
    mov eax, 3
    jmp done

parse_requires:
    cmp dword ptr [rip+statement_seen], 0
    jne bad_syntax
    cmp dword ptr [rip+declared_read], 0
    jne bad_syntax
    add rsi, 8
    mov al, byte ptr [rsi]
    cmp al, ' '
    je requires_body
    cmp al, 9
    jne bad_syntax
requires_body:
    call skip_horizontal
    cmp byte ptr [rsi], '{'
    jne bad_syntax
    inc rsi
    call skip_horizontal
    mov rcx, rsi
    lea rdx, [rip+file_read_kw]
    mov r8d, 9
    call strncmp
    test eax, eax
    jne bad_syntax
    add rsi, 9
    call skip_horizontal
    cmp byte ptr [rsi], '}'
    jne bad_syntax
    inc rsi
    call validate_tail
    test eax, eax
    jne bad_syntax
    mov dword ptr [rip+declared_read], 1
    jmp read_line

# Move past spaces and tabs only.
skip_horizontal:
    mov al, byte ptr [rsi]
    cmp al, ' '
    je horizontal_advance
    cmp al, 9
    je horizontal_advance
    ret
horizontal_advance:
    inc rsi
    jmp skip_horizontal

parse_integer:
    mov qword ptr [rsp+40], rsi  # starting position
    call _errno
    mov dword ptr [rax], 0
    mov rcx, rsi
    lea rdx, [rsp+32]
    mov r8d, 10
    call strtoll
    mov r12, rax                 # parsed value
    mov rsi, qword ptr [rsp+32]
    # A missing number leaves the end pointer at the original position.
    cmp rsi, qword ptr [rsp+40]
    je bad_syntax
    call _errno
    cmp dword ptr [rax], 0      # overflow or another conversion error
    jne bad_syntax
    call validate_tail
    test eax, eax
    jnz bad_syntax
    lea rcx, [rip+number_fmt]
    mov rdx, r12
    call printf
    jmp read_line

# Accept spaces/tabs, line ending, or a trailing comment. Returns 0 on success.
validate_tail:
    mov al, byte ptr [rsi]
    cmp al, ' '
    je tail_advance
    cmp al, 9
    je tail_advance
    cmp al, '#'
    je tail_ok
    cmp al, 13
    je tail_ok
    cmp al, 10
    je tail_ok
    test al, al
    jz tail_ok
    mov eax, 1
    ret
tail_advance:
    inc rsi
    jmp validate_tail
tail_ok:
    xor eax, eax
    ret

end_of_file:
    mov rcx, rbx
    call ferror
    mov esi, eax
    mov rcx, rbx
    call fclose
    test esi, esi
    jnz file_read_failed
    xor eax, eax
    jmp done

bad_syntax:
    lea rcx, [rip+syntax_error]
    mov rdx, rdi
    call printf
    mov rcx, rbx
    call fclose
    mov eax, 2
    jmp done

show_usage:
    lea rcx, [rip+usage]
    call puts
    mov eax, 2
    jmp done

cannot_open:
    lea rcx, [rip+open_error]
    mov rdx, rdi
    call printf
    mov eax, 1
    jmp done

file_read_failed:
    lea rcx, [rip+read_error]
    call puts
    mov eax, 1

done:
    add rsp, 56
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
