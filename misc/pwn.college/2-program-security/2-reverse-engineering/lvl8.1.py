import pwn

from itertools import cycle
from os.path import basename

LEVEL = basename(__file__).replace('lvl', '').replace('.py', '')
#OUTPUT = b'\x2A\xD7\x7C\xE7\x56\x22\x39\xF5\x6D\xC9\x49\x0F\x25\xD9\x76\xEC\x5D\x2A\x2F\xE3\x78\xD2\x54\x13\x39\xC4\x6C\xF9\x48\x3C\x26\xE9\x70\xDB\x5B\x1B'

OUTPUT = b'\x00\x2a\xd7\x7c\xe7\x56\x22\x39\xf5\x6d\xc9\x49\x0f\x25\xd9\x76\xec\x5d\x2a\x2f\xe3\x78\xd2\x54\x13\x39\xc4\x6c\xf9\x48\x3c\x26\xe9\x70\xdb\x5b\x1b'


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
    data = reverse(data)
    #data = xor(data, b'\x0f\xa4\x4a\xb6\x70\x52')
    data = xor(data, b'\x52\x70\xb6\x4a\xa4\x0f')
    data = xor(data, b'\x18')
    data = reverse(data)
    data = reverse(data)
    data = xor(data, b'\x30\x57\x11\x47')
    #data = xor(data, b'\x47\x11\x57\x30')
    return data


if __name__ == '__main__':
    solved = solve(OUTPUT)
    print(solved)
    r = pwn.ssh(user="hacker", host="pwn.college", keyfile="~/.ssh/pwn.college")
    p = r.process(f"/challenge/babyrev_level{LEVEL}")
    resp = p.recvuntil(b"key!\n\n")
    print(solved)
    p.sendline(solved)
    #print(p.recvall(timeout=1).decode())
    p.recvuntil(b"flag:\n")
    print(p.recvall(timeout=1).decode())
