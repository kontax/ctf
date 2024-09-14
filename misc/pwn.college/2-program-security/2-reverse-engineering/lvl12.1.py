import pwn

from os.path import basename

LEVEL = basename(__file__).replace('lvl', '').replace('.py', '')


if __name__ == '__main__':
    r = pwn.ssh(user="hacker", host="pwn.college", keyfile="~/.ssh/pwn.college")
    p = r.process(f"/challenge/babyrev_level{LEVEL}")
    p.recv()
    p.sendline(b"\x98\xdf\x1d\xc2\x65\x6B\x02\x36")
    p.recvuntil(b"flag: ")
    print(p.recvall(timeout=1).decode())

