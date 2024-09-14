import pwn

from os.path import basename

LEVEL = basename(__file__).replace('lvl', '').replace('.py', '')


if __name__ == '__main__':
    r = pwn.ssh(user="hacker", host="pwn.college", keyfile="~/.ssh/pwn.college")
    p = r.process(f"/challenge/babyrev_level{LEVEL}")
    p.recv()
    p.sendline(b"\xA9\x7A\xD7\x33\xDD\xE6")
    p.recvuntil(b"flag: ")
    print(p.recvall(timeout=1).decode())

