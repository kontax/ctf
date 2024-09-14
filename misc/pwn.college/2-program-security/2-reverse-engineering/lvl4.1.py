import pwn
from os.path import basename

LEVEL = basename(__file__).replace('lvl', '').replace('.py', '')
OUTPUT = b'bkowy'

r = pwn.ssh(user="hacker", host="pwn.college", keyfile="~/.ssh/pwn.college")
p = r.process(f"/challenge/babyrev_level{LEVEL}")
resp = p.recvuntil(b"key!\n\n")
p.sendline(b''.join([chr(c).encode() for c in sorted(OUTPUT)]))
p.recvuntil(b"flag:\n")
print(p.recvall(timeout=1).decode())
