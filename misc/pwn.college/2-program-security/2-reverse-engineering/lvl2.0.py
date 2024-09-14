import pwn

LEVEL = 2.0
OUTPUT = 'mzrzr'

r = pwn.ssh(user="hacker", host="pwn.college", keyfile="~/.ssh/pwn.college")
p = r.process(f"/challenge/babyrev_level{LEVEL}")
resp = p.recvuntil(b"key!\n\n")
p.sendline(b"mzrrz")
p.recvuntil(b"flag:\n")
print(p.recvall(timeout=1).decode())
