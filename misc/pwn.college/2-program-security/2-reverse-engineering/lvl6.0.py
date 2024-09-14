import pwn

from itertools import cycle
from os.path import basename

LEVEL = basename(__file__).replace('lvl', '').replace('.py', '')
OUTPUT = b'\x27\xbc\x25\xbd\x22\xbb\x21\xb5\x2b\xae\x34\xad\x35\xaa\x32\xa8\x31\xa6\x3f'


def xor(data, key):
    output = []
    for d, k in zip(data, cycle(key)):
        output.append((d^k).to_bytes())

    return b''.join(output)


def solve(data):
    unxor = xor(data, b'\x5e\xc1')
    unxor = xor(unxor, b'\x18\x1f')
    return unxor


if __name__ == '__main__':
    r = pwn.ssh(user="hacker", host="pwn.college", keyfile="~/.ssh/pwn.college")
    p = r.process(f"/challenge/babyrev_level{LEVEL}")
    resp = p.recvuntil(b"key!\n\n")
    solved = solve(OUTPUT)
    p.sendline(solved)
    p.recvuntil(b"flag:\n")
    print(p.recvall(timeout=1).decode())
