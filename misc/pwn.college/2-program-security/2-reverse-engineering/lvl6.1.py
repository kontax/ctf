import pwn

from itertools import cycle
from os.path import basename

LEVEL = basename(__file__).replace('lvl', '').replace('.py', '')
OUTPUT = b'lqcxwjqpuqgzcyh'


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
    print(data)
    rev = reverse(data)
    print(rev)
    swap = swapbytes(rev, 5, 12)
    print(swap)
    swap = swapbytes(swap, 2, 1)
    print(swap)
    return swap


if __name__ == '__main__':
    solved = solve(OUTPUT)
    r = pwn.ssh(user="hacker", host="pwn.college", keyfile="~/.ssh/pwn.college")
    p = r.process(f"/challenge/babyrev_level{LEVEL}")
    resp = p.recvuntil(b"key!\n\n")
    p.sendline(solved)
    #print(p.recvall(timeout=1).decode())
    p.recvuntil(b"flag:\n")
    print(p.recvall(timeout=1).decode())
