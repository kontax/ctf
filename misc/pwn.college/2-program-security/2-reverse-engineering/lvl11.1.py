import pwn

from itertools import cycle
from os.path import basename

LEVEL = basename(__file__).replace('lvl', '').replace('.py', '')

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
    pass


if __name__ == '__main__':
    r = pwn.ssh(user="hacker", host="pwn.college", keyfile="~/.ssh/pwn.college")
    p = r.process(f"/challenge/babyrev_level{LEVEL}")
    p.recvuntil(b"change: ")
    p.sendline(b"281B")
    p.recvuntil(b"New value (hex): ")
    p.sendline(b"84")
    p.recvuntil(b"change: ")
    p.sendline(b"28FC")
    p.recvuntil(b"New value (hex): ")
    p.sendline(b"74")
    p.recvuntil(b"key!\n\n")
    p.sendline(b"AAAA")
    #print(p.recvall(timeout=1).decode())
    p.recvuntil(b"flag:\n")
    print(p.recvall(timeout=1).decode())
