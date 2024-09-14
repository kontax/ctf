import pwn

from os.path import basename

LEVEL = basename(__file__).replace('lvl', '').replace('.py', '')


def run():
    binary = f"binaries/babyrev_level{LEVEL}"
    from yan85 import CPU
    cpu = CPU(binary)

    cpu.imm(1, 0x75)
    cpu.imm(0x40, 4)
    cpu.imm(8, 0)
    cpu.sys(4, 8)
    cpu.imm(1, 0x95)
    cpu.imm(0x40, 1)
    cpu.imm(8, 0xed)
    cpu.stm(1, 8)
    cpu.add(1, 0x40)
    cpu.imm(8, 0xa1)
    cpu.stm(1, 8)
    cpu.add(1, 0x40)
    cpu.imm(8, 0xfb)
    cpu.stm(1, 8)
    cpu.add(1, 0x40)
    cpu.imm(8, 0xe7)
    cpu.stm(1, 8)
    cpu.add(1, 0x40)
    return bytes(cpu.memory[0x95:])


if __name__ == '__main__':
    r = pwn.ssh(user="hacker", host="pwn.college", keyfile="~/.ssh/pwn.college")
    p = r.process(f"/challenge/babyrev_level{LEVEL}")
    p.recvuntil(b'[+]\n')

    output = run()
    print(output.hex(' '))

    p.sendline(output)
    p.recvuntil(b"flag: ")
    print(p.recvline().decode())

