.intel_syntax noprefix
.globl _start

.data
sockaddr: .byte 0x2,0x0,0x0,0x50,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0
size: .byte 0x10
resp: .ascii "HTTP/1.0 200 OK\r\n\r\n"
#read: .space 0xffff
req_idx: .space 0x0f
len: .ascii "Content-Length:\0"
post: .ascii "POST\0"
filename: .space 0xff
file: .byte 0xff
read:
    .ascii "POST /tmp/tmpntwnru79 HTTP/1.1\n\0"
    .ascii "Host: localhost\n\0"
    .ascii "User-Agent: python-requests/2.32.3\n\0"
    .ascii "Accept-Encoding: gzip, deflate, zstd\n\0"
    .ascii "Accept: */*\n\0"
    .ascii "Connection: keep-alive\n\0"
    .ascii "Content-Length: 184\n\0"
    .ascii "\n\0"
    .ascii "Tmswpap2SrPR2CBBLmaI6ezPmlhYvmFut4bZefmh2VsWSvidTLrnkIKUJrhmESmmyodFKJDqg5rIGrcRSOK9c3FzsAzr8fNJ7V2acO5d466NXWOTYloveSXO2eO91ascMWVEXn2wUO2Tmf7ZVEhD4XI33ioZB4mxnZN0HFCkKLtvFXRw1CDsFnQi\n\0"

.section .text

_start:
    lea rsi, read

_process:

    # Process request
    push rsi            # Store read string
    xor rax, rax        # Next string idx
    xor rcx, rcx        # Request item count
    lea rbx, req_idx    # Index table
    mov [rbx+rcx], rax  # Push initial idx value
    mov rdi, 0          # String split

_parse_request_items:
    call find_next_string   # Next str idx is in rax
    add rsi, rax            # Start from new string
    add rax, [rbx+rcx]      # Add offset to previous
    inc rcx                 # Go to next string
    mov [rbx+rcx], rax      # Move idx to index table
    cmp rcx, 8              # We only have 8 request items
    jle _parse_request_items

    pop rsi             # Restore request value

    # RBX contains lookup table for request
    # rsi + rbx+0 = POST [filename] HTTP/1.1
    # rsi + rbx+1 = Host:
    # rsi + rbx+2 = User-Agent:
    # rsi + rbx+3 = Accept-Encoding:
    # rsi + rbx+4 = Accept:
    # rsi + rbx+5 = Connection:
    # rsi + rbx+6 = Content-Length:
    # rsi + rbx+7 = \n
    # rsi + rbx+8 = [text]

_test:
    xor rax, rax
    mov al, [rbx+0]
    lea rdi, [rsi+rax]
    mov al, [rbx+1]
    lea rdi, [rsi+rax]
    mov al, [rbx+2]
    lea rdi, [rsi+rax]
    mov al, [rbx+3]
    lea rdi, [rsi+rax]
    mov al, [rbx+4]
    lea rdi, [rsi+rax]
    mov al, [rbx+5]
    lea rdi, [rsi+rax]
    mov al, [rbx+6]
    lea rdi, [rsi+rax]
    mov al, [rbx+7]
    lea rdi, [rsi+rax]
    mov al, [rbx+8]
    lea rdi, [rsi+rax]

_get_filename:
    push rsi
    mov rdi, ' '
    call find_next_string
    add rsi, rax
    call find_next_string
    mov rcx, rax
    lea rdx, filename
    xor rax, rax

_get_filename_loop:
    dec rcx
    cmp rcx, 0
    je _get_filename_done
    movb al, [rsi]
    mov byte ptr [rdx], al
    inc rdx
    inc rsi
    jmp _get_filename_loop

_get_filename_done:
    pop rsi

_check_request_type:
    lea rdi, post
    call find_substring
    cmp rax, 0
    je _post

_get:

    # Open
    lea rax, read+20
    movb [rax], 0
    lea rdi, read+4 # filename
    mov rsi, 0      # flags
    mov rdx, 0      # mode
    mov rax, 2      # SYS_open
    syscall
    push rax

    # Read
    mov rdi, [rsp]  # fd
    lea rsi, file   # buf
    mov rdx, 256    # len
    mov rax, 0      # SYS_read
    syscall
    push rax

    # Close
    pop rdx
    pop rdi         # fd
    push rdx
    mov rax, 3      # SYS_close
    syscall

    # Write
    mov rdi, [rsp+8]  # fd
    lea rsi, resp   # buf
    mov rdx, 19     # count
    mov rax, 1      # SYS_write
    syscall

    # Write
    pop rdx         # count
    mov rdi, [rsp]  # fd
    lea rsi, file   # buf
    mov rax, 1      # SYS_write
    syscall

_post:

    # Open
    lea rdi, filename # filename
    mov rsi, 0x41   # flags
    mov rdx, 0x1ff  # mode
    mov rax, 2      # SYS_open
    syscall
    push rax

_get_content_length:
    lea rbx, req_idx
    lea rsi, read
    mov al, [rbx+6]
    lea rsi, [rsi+rax]
    add rsi, 16
    mov rdi, rsi
    call str_to_int

_write_to_file:
    # Write
    lea rbx, req_idx
    lea rsi, read
    mov al, [rbx+8]
    lea rsi, [rsi+rax]  # buf
    mov rdi, [rsp]  # fd
    mov rdx, rax    # count
    mov rax, 1      # SYS_write
    syscall

    # Close
    pop rdi         # fd
    mov rax, 3      # SYS_close
    syscall

    # Write
    pop rdi         # fd
    lea rsi, resp   # buf
    mov rdx, 19     # count
    mov rax, 1      # SYS_write
    syscall

_exit:

    mov rdi, 0
    mov rax, 60     # SYS_exit
    syscall


str_to_int:
    push rbp
    mov rbp, rsp

    xor rax, rax
    xor rbx, rbx

_convert_loop:
    mov bl, byte ptr [rdi]
    cmp bl, '0'
    jb _str_to_int_done
    cmp bl, '9'
    ja _str_to_int_done

    sub bl, '0'     # Convert ASCII character to its numeric value
    imul rax, 10    # Multiply the existing result by 10
    add rax, rbx    # Add the new digit to the result

    inc rdi
    jmp _convert_loop

_str_to_int_done:
    mov rsp, rbp
    pop rbp
    ret

find_substring:
    # Input:
    #  - rsi (DWORD): Address of the first string (null-terminated)
    #  - rdi (DWORD): Address of the second string (null-terminated)
    # Output:
    #  - EAX: Index (0-based) of the first occurrence of str2 in str1,
    #        or -1 if str2 is not found.

    push rbp                # Save base pointer
    mov rbp, rsp            # Set up stack frame
    push rbx

    xor rbx, rbx            # RBX will hold the index of the match
    xor rdx, rdx

outer_loop:
    mov rax, rsi           # Copy str1 pointer for inner loop
    push rdi
    push rbx               # Save current index on the stack

inner_loop:
    cmp byte ptr [rax], 0  # Check for end of str1
    je not_found          # If end of str1, str2 not found

    mov dl, [rdi]
    cmp byte ptr [rax], dl # Compare characters from str1 and str2
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
    pop rbx
    pop rdi
    mov rax, -1           # Return -1 if not found

find_substring_done:
    pop rbx
    pop rbp                # Restore base pointer
    ret                    # Return from procedure


find_next_string:
    # Input:
    # - rsi (DWORD): Address of string to parse
    # - rdi (char): Splitter
    # Output:
    # - RAX: Index of next string after \0 termination

    push rbp
    mov rbp, rsp
    push rcx
    push rbx

    xor rcx, rcx
    xor rbx, rbx
    xor rax, rax

_find_next_string_loop:
    mov bl, [rsi+rax]
    cmp bx, di
    je _find_next_string_done
    inc rax
    jmp _find_next_string_loop

_find_next_string_done:
    inc rax
    pop rbx
    pop rcx
    pop rbp
    ret
