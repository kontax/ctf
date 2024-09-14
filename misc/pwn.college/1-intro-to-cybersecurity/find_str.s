.intel_syntax noprefix
.globl _start

.data
to_find: .ascii "Content-Length:\0"
in_str: .ascii "0123Con45678901234567890123456789Content-Length:\0"

.section .text

_start:
    lea rdi, to_find
    lea rsi, in_str
    call find_substring

_exit:

    mov rdi, 0
    mov rax, 60     # SYS_exit
    syscall


find_substring:
    # Input:
    #  - rsi (DWORD): Address of the first string (null-terminated)
    #  - rdi (DWORD): Address of the second string (null-terminated)
    # Output:
    #  - EAX: Index (0-based) of the first occurrence of str2 in str1,
    #        or -1 if str2 is not found.

    push rbp                # Save base pointer
    mov rbp, rsp            # Set up stack frame

    mov rbx, 0              # RBX will hold the index of the match

outer_loop:
    mov rax, rsi           # Copy str1 pointer for inner loop
    push rdi
    push rbx               # Save current index on the stack

inner_loop:
    cmp byte ptr [rax], 0  # Check for end of str1
    je not_found          # If end of str1, str2 not found

    mov cl, [rdi]
    cmp byte ptr [rax], cl # Compare characters from str1 and str2
    jne next_char          # If not equal, try next character

    inc rax                # Move to next character in str1
    inc rdi                # Move to next character in str2
    cmp byte ptr [rdi], 0  # Check for end of str2
    je found               # If end of str2, we have a match

    jmp inner_loop        # Continue inner loop

next_char:
    pop rbx                # Restore index
    inc rbx                # Move to next possible starting position in str1
    inc rsi                # Move to next character in str1
    pop rdi        # Reset str2 pointer
    jmp outer_loop         # Continue outer loop

found:
    mov rax, rbx           # Return index in RAX
    pop rbx
    pop rdi
    jmp find_substring_done

not_found:
    pop rbx
    pop rdi
    mov rax, -1           # Return -1 if not found

find_substring_done:
    pop rbp                # Restore base pointer
    ret                    # Return from procedure
