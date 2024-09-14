
import pwn
from os.path import basename

LEVEL = basename(__file__).replace('lvl', '').replace('.py', '')

REG_VALS = {
    'a': 0x04,
    'b': 0x08,
    'c': 0x10,
    'd': 0x02,
    's': 0x01,
    'i': 0x20,
    'f': 0x40,
}


class CPU:
    def __init__(self):
        self.registers = self._init_registers()
        self.memory = self._init_memory()
        self.flags = None

    def add(self, r1, r2):
        print(f"[*] ADD {r1} {r2}")
        reg1 = self.registers[r1]
        reg2 = self.registers[r2]
        reg1.val = reg1.val + reg2.val

    def imm(self, r, val):
        print(f"[*] IMM {r} = {hex(val)}")
        reg = self.registers[r]
        reg.val = val

    def stm(self, rloc, rval):
        print(f"[*] STM *{rloc} = {rval}")
        reg_loc = self.registers[rloc]
        reg_val = self.registers[rval]
        self.memory[reg_loc.val] = reg_val.val

    def push(self, r):
        pass

    def pop(self, r):
        pass

    def _init_registers(self):
        registers = Registers([
            Register('a', REG_VALS['a']),
            Register('b', REG_VALS['b']),
            Register('c', REG_VALS['c']),
            Register('d', REG_VALS['d']),
            Register('s', REG_VALS['s']),
            Register('i', REG_VALS['i']),
            Register('f', REG_VALS['f']),
        ])
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

class Registers(list):
    def __getitem__(self, key):
        if isinstance(key, str):
            for i, obj in enumerate(self):
                if obj.name == key:
                    return obj
            raise ValueError(f"No object with name '{key}' found")
        else:
            return super().__getitem__(key)

def run():
    cpu = CPU()
    cpu.imm('b', 0x7b)
    cpu.imm('c', 0x1)
    cpu.imm('a', 0x19)
    cpu.stm('b', 'a')
    cpu.add('b', 'c')
    cpu.imm('a', 0x64)
    cpu.stm('b', 'a')
    cpu.add('b', 'c')
    cpu.imm('a', 0x3b)
    cpu.stm('b', 'a')
    cpu.add('b', 'c')
    cpu.imm('a', 0x8f)
    cpu.stm('b', 'a')
    cpu.add('b', 'c')
    cpu.imm('a', 0x8b)
    cpu.stm('b', 'a')
    cpu.add('b', 'c')
    cpu.imm('a', 0x9b)
    cpu.stm('b', 'a')
    cpu.add('b', 'c')
    cpu.imm('a', 0x8c)
    cpu.stm('b', 'a')
    cpu.add('b', 'c')
    cpu.imm('a', 0x12)
    cpu.stm('b', 'a')
    cpu.add('b', 'c')

    return bytes(cpu.memory[0x7b:])


if __name__ == '__main__':
    output = run()
    print(output.hex(' '))

    r = pwn.ssh(user="hacker", host="pwn.college", keyfile="~/.ssh/pwn.college")
    p = r.process(f"/challenge/babyrev_level{LEVEL}")
    p.recvuntil(b'[+]\n')
    p.sendline(output)
    p.recvuntil(b"flag: ")
    print(p.recvall(timeout=1).decode())

