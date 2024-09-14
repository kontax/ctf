import pwn

from itertools import cycle
from os.path import basename

LEVEL = basename(__file__).replace('lvl', '').replace('.py', '')
OUTPUT = b'\x20\x24\x2b\x35\x3d\x40\x4e\x51\x53\x5c\x5e\x84\x85\x8c\x92\xa9\xab\xae\xb2\xb3\xbd\xc5\xd1\xd9\xdc\xea'


def xor(data, key):
    output = []
    for d, k in zip(data, cycle(key)):
        output.append((d^k).to_bytes())

    return b''.join(output)

def reverse(data):
    return data[::-1]

def swapbytes(data, f, t):
    data = list(data)
    x = data[f]
    data[f] = data[t]
    data[t] = x
    return b''.join([x.to_bytes() for x in data])


def solve(data):
    data = xor(data, b'\x9c\x55\x85\xaf\xc8')
    data = swapbytes(data, 7, 23)
    data = xor(data, b'\xa4\x89\x63\x06\x87')
    data = reverse(data)
    return data


if __name__ == '__main__':
    solved = solve(OUTPUT)
    r = pwn.ssh(user="hacker", host="pwn.college", keyfile="~/.ssh/pwn.college")
    p = r.process(f"/challenge/babyrev_level{LEVEL}")
    resp = p.recvuntil(b"key!\n\n")
    p.sendline(solved)
    #print(p.recvall(timeout=1).decode())
    p.recvuntil(b"flag:\n")
    print(p.recvall(timeout=1).decode())
