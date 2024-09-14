import pwn

from yan85 import CPU
from os.path import basename

LEVEL = basename(__file__).replace('lvl', '').replace('.py', '')


def run():
    binary = f"binaries/babyrev_level{LEVEL}"
    cpu = CPU(binary)
    cpu.imm(0x10, 0x71)
    cpu.imm(1, 6)
    cpu.imm(8, 0)
    cpu.sys(8, 8)
    cpu.imm(0x10, 0x91)
    cpu.imm(1, 1)
    cpu.imm(8, 0xb)
    cpu.stm(0x10, 8)
    cpu.add(0x10, 1)
    cpu.imm(8, 0x13)
    cpu.stm(0x10, 8)
    cpu.add(0x10, 1)
    cpu.imm(8, 0x33)
    cpu.stm(0x10, 8)
    cpu.add(0x10, 1)
    cpu.imm(8, 0xad)
    cpu.stm(0x10, 8)
    cpu.add(0x10, 1)
    cpu.imm(8, 0x4c)
    cpu.stm(0x10, 8)
    cpu.add(0x10, 1)
    cpu.imm(8, 0xc2)
    cpu.stm(0x10, 8)
    cpu.add(0x10, 1)

    return bytes(cpu.memory[0x91:])


if __name__ == '__main__':
    output = run()
    print(output.hex(' '))

    r = pwn.ssh(user="hacker", host="pwn.college", keyfile="~/.ssh/pwn.college")
    p = r.process(f"/challenge/babyrev_level{LEVEL}")
    p.recvuntil(b'[+]\n')
    p.sendline(output)
    #p.recvuntil(b"flag: ")
    print(p.recvall(timeout=1).decode())

