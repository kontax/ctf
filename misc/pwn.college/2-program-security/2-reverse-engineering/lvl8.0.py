import pwn

from itertools import cycle
from os.path import basename

LEVEL = basename(__file__).replace('lvl', '').replace('.py', '')
OUTPUT = b'\x1f\xa9\x11\xae\x06\xb5\x1d\xbf\x08\xaa\x02\xbc\x17\xb3\x14\xb1\x17\xa8\x03\xa9\x15\xa8\x18\xab\x0a\xad\x1b\xa2\x08\xb7\x06\xab\x11\xa1\x18\xaa\x07'



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
    data = swapbytes(data, 6, 10)
    data = reverse(data)
    data = swapbytes(data, 4, 34)
    data = xor(data, b'\x72\xc5')
    data = reverse(data)
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
