import pwn

LEVEL = 2.1
OUTPUT = 'qbnkf'

r = pwn.ssh(user="hacker", host="pwn.college", keyfile="~/.ssh/pwn.college")
p = r.process(f"/challenge/babyrev_level{LEVEL}")
resp = p.recvuntil(b"key!\n\n")
p.sendline(b"bqnkf")
p.recvuntil(b"flag:\n")
print(p.recvall(timeout=1).decode())
