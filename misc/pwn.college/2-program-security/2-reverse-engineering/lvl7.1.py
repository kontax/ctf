import pwn

from itertools import cycle
from os.path import basename

LEVEL = basename(__file__).replace('lvl', '').replace('.py', '')
OUTPUT = b'\x87\xE6\xA4\x89\x87\xE1\xAB\x91\x92\xEE\xA3\x90\x8D\xF7\xA8\x9E\x94\xE5\xFF\x8D\x8A\xBF\xB2\x82\x8E'



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
    data = swapbytes(data, 18, 21)
    data = swapbytes(data, 15, 23)
    data = xor(data, b'\xe4\x94\xc5\xe4')
    data = swapbytes(data, 4, 20)
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
