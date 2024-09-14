import pwn
import re
import sys

from yan85_interpreter import CPU

class Level:
    def __init__(self, hostname):
        self.level = hostname.split('~')[1].replace('level', '').replace('-','.').splitlines()[0] \
            if '~' in hostname \
            else hostname
        self.remote_process = f"/challenge/babyrev_level{self.level}"
        self.local_process = f"binaries/babyrev_level{self.level}"
        self.func_name = f"level{self.level.replace('.', '_')}"
        self.run = globals()[self.func_name]

def _memcmp(level):
    binary = level.local_process
    cpu = CPU(binary)

    code = cpu.decomp('execute_program').splitlines()
    mem_idx = 0
    for line in code:
        if 'memcmp' in line:
            pattern = r'\+ (\d+)'
            match = re.search(pattern, line)
            if match:
                mem_idx = int(match.group(1))
                break

        elif 'cpu' in line:
            exec(line.strip())

    return bytes(cpu.memory[mem_idx:])

def _extract_memory(level, bp1, bp2):
    binary = level.local_process
    cpu = CPU(binary)
    code = cpu.decomp('execute_program').splitlines()[9:]
    linenum = 0
    mem_idx = 0
    for line in code:
        print(f"{linenum}:{line}")
        exec(line.strip())
        if linenum == bp1:
            match = re.search(r'cpu.imm\(\d+, (\d+)\)', line)
            if match:
                mem_idx = int(match.group(1))
                print(f"MEM_IDX: {mem_idx}")

        if linenum == bp2:
            print(cpu.memory[mem_idx:])
            return bytes(cpu.memory[mem_idx:])
        linenum += 1

def _generate_bytecode(level, filename):
    with open(filename, 'r') as f:
        y85 = f.read()

    binary = level.local_process
    cpu = CPU(binary)
    bytecode = cpu.to_bytecode(y85)
    return bytecode


def level13_0(level):
    return _memcmp(level)

def level13_1(level):
    return _memcmp(level)

def level14_0(level):
    return _memcmp(level)

def level14_1(level):
    return _memcmp(level)

def level15_0(level):
    return _memcmp(level)

def level15_1(level):
    return _memcmp(level)

def level16_0(level):
    return _extract_memory(level, 4, 29)

def level16_1(level):
    return _extract_memory(level, 4, 25)

def level17_0(level):
    return _extract_memory(level, 4, 57)

def level17_1(level):
    return _extract_memory(level, 4, 57)

def level18_0(level):
    # Compares after each add, so can't get the memory dump
    return b"\x79\x5d\x8e\xb0\x55\x35"

def level18_1(level):
    inpt = [0xb3, 0x2b, 0xd5, 0xf3, 0x74, 0xcc, 0xbb, 0x4c, 0x11]
    adtn = [0x6a, 0xf2, 0xd6, 0xbd, 0x8f, 0x99, 0xbe, 0x62, 0x43]
    res = []
    for a, b in zip(inpt, adtn):
        res.append((a+b)%256)

    return b''.join([x.to_bytes(1, 'little') for x in res])

def level19_0(level):
    return b"\x8d\xfc\xa1\xd9\xb2\x04\x8f\xd4\x86\x6b\xc8\x18"

def level19_1(level):
    return b"\x60\x05\x0c\xb6\x0c\x0e\x41\x41"

def level20_0(level):
    # What I want the result to equal
    res = [0xa0,0x4d,0x82,0xd5,0xa9,0x47,0xed,
           0x59,0x79,0xa8,0x1e,0x2b,0x72,0xe3,
           0x92,0x03,0x84,0xf8,0xca,0x07,0x3b,
           0x02,0xfd,0x73,0x30,0x36,0x36,0x62]

    # What i need to add to the input to get the result
    add = [0x48,0x9c,0x0a,0x9a,0x3f,0x41,0x93,
           0x94,0xac,0xd4,0x72,0xdd,0x5a,0x07,
           0xc6,0x90,0xa2,0xc0,0xdd,0x37,0xa4,
           0x04,0x22,0x9c,0xad,0xc2,0xd5,0xa6]

    output = []
    for a, r in zip(add, res):
        print(f"{r:x} - {a:x} --> ", end='')
        if a > r:
            r = r + 0x100
        print(f"{r:x} - {a:x} = {r-a:x}")
        output.append(r-a)

    return bytes(output)

def level20_1(level):
    # What I want the result to equal
    res = [0x6f,0xdc,0xf0,0x83,0xb5,0xa0,0xc6,
           0xa7,0xa2,0x75,0xb3,0x3b,0xc4,0x60,
           0xc6,0xcd,0x4d,0x50,0x4a,0xce,0xb7]

    # What i need to add to the input to get the result
    add = [0xa4,0x40,0xa4,0x09,0x2f,0x81,0x03,
           0x70,0xf3,0xf4,0x32,0xcb,0x5e,0xaf,
           0x16,0x71,0x00,0xf4,0xa7,0x28,0xc7]

    output = []
    for a, r in zip(add, res):
        print(f"{r:x} - {a:x} --> ", end='')
        if a > r:
            r = r + 0x100
        print(f"{r:x} - {a:x} = {r-a:x}")
        output.append(r-a)

    return bytes(output)

def level21_0(level):
    return _generate_bytecode(level, 'code/open_flag.y85')

def level21_1(level):
    return _generate_bytecode(level, 'code/open_flag.y85')

def get_level(r):
    p = r.process("hostname")
    hostname = p.recvall(timeout=1).decode()
    level = Level(hostname)
    print(f"LEVEL {level.level}")
    return level

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <remote|local> (level)")
        exit()

    if len(sys.argv) == 3 and sys.argv[1] == 'local':
        level = Level(sys.argv[2])
        p = pwn.process(level.local_process)

    elif sys.argv[1] == 'remote':
        r = pwn.ssh(user="hacker", host="pwn.college", keyfile="~/.ssh/pwn.college")
        level = get_level(r)
        p = r.process(level.remote_process)

    elif sys.argv[1] == 'local':
        r = pwn.ssh(user="hacker", host="pwn.college", keyfile="~/.ssh/pwn.college")
        level = get_level(r)
        p = pwn.process(f"binaries/babyrev_level{level.level}")

    else:
        print(f"Usage: {sys.argv[0]} <remote|local> (level)")
        exit()

    p.recvuntil(b'[+]\n')

    output = level.run(level)
    print(output.hex(' '))

    p.sendline(output)
    #p.recvuntil(b"flag: ")
    print(p.recvall(timeout=1).decode())

