import pwn
from os.path import basename

LEVEL = basename(__file__).replace('lvl', '').replace('.py', '')

REG_VALS = {
    'a': 0x20,
    'b': 0x10,
    'c': 0x01,
    'd': 0x08,
    's': 0x02,
    'i': 0x40,
    'f': 0x04,
}

SYSCALLS = {
    'open': 0x08,
    'read': 0x20,
    'write': 0x02,
    'sleep': 0x04,
    'exit': 0x01
}


class CPU:
    def __init__(self):
        self.registers = self._init_registers()
        self.memory = self._init_memory()
        self.flags = None

    def add(self, r1, r2):
        reg1 = self.registers[r1]
        reg2 = self.registers[r2]
        print(f"[*] ADD {reg1} {reg2}")
        reg1.val = reg1.val + reg2.val

    def imm(self, r, val):
        reg = self.registers[r]
        print(f"[*] IMM {reg} = {hex(val)}")
        reg.val = val

    def stm(self, rloc, rval):
        reg_loc = self.registers[rloc]
        reg_val = self.registers[rval]
        print(f"[*] STM *{reg_loc} = {reg_val}")
        self.memory[reg_loc.val] = reg_val.val

    def sys(self, num, r):
        reg = self.registers[r]
        syscall = [x for x in SYSCALLS if SYSCALLS[x] == num][0]
        print(f"[*] SYS {syscall} {reg}")


    def push(self, r):
        pass

    def pop(self, r):
        pass

    def _init_registers(self):
        registers = Registers([Register(x, REG_VALS[x]) for x in REG_VALS])
        return registers

    def _init_memory(self):
        return [0]*256


class Register:
    def __init__(self, name, idx):
        self.name = name
        self.idx = idx
        self.val = 0

    def __eq__(self, value: object, /) -> bool:
        if value is not Register or value is not str:
            return False

        return (value is Register and value.name == self.name) or \
               (value is str and value == self.name)

    def __str__(self) -> str:
        return self.name

class Registers(list):
    def __getitem__(self, key):
        if isinstance(key, str):
            for i, obj in enumerate(self):
                if obj.name == key:
                    return obj
            raise ValueError(f"No object with name '{key}' found")
        elif isinstance(key, int):
            for i, obj in enumerate(self):
                if obj.idx == key:
                    return obj
            raise ValueError(f"No object with name '{key}' found")
        else:
            return super().__getitem__(key)

def run():
    cpu = CPU()
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

