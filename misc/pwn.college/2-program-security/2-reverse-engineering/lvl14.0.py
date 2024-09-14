import pwn

from os.path import basename

LEVEL = basename(__file__).replace('lvl', '').replace('.py', '')


def run():
    binary = f"binaries/babyrev_level{LEVEL}"
    from yan85 import CPU
    cpu = CPU(binary)

    cpu.imm(8, 0x59)
    cpu.imm(1, 8)
    cpu.imm(0x10, 0)
    cpu.sys(0x20, 0x10)
    cpu.imm(8, 0x79)
    cpu.imm(1, 1)
    cpu.imm(0x10, 0x16)
    cpu.stm(8, 0x10)
    cpu.add(8, 1)
    cpu.imm(0x10, 0x9f)
    cpu.stm(8, 0x10)
    cpu.add(8, 1)
    cpu.imm(0x10, 0x94)
    cpu.stm(8, 0x10)
    cpu.add(8, 1)
    cpu.imm(0x10, 0xc8)
    cpu.stm(8, 0x10)
    cpu.add(8, 1)
    cpu.imm(0x10, 0x9a)
    cpu.stm(8, 0x10)
    cpu.add(8, 1)
    cpu.imm(0x10, 0x68)
    cpu.stm(8, 0x10)
    cpu.add(8, 1)
    cpu.imm(0x10, 0x7e)
    cpu.stm(8, 0x10)
    cpu.add(8, 1)
    cpu.imm(0x10, 0xae)
    cpu.stm(8, 0x10)
    cpu.add(8, 1)

    return bytes(cpu.memory[0x79:])


if __name__ == '__main__':
    r = pwn.ssh(user="hacker", host="pwn.college", keyfile="~/.ssh/pwn.college")
    p = r.process(f"/challenge/babyrev_level{LEVEL}")
    p.recvuntil(b'[+]\n')

    output = run()
    print(output.hex(' '))

    p.sendline(output)
    #p.recvuntil(b"flag: ")
    print(p.recvall(timeout=1).decode())

