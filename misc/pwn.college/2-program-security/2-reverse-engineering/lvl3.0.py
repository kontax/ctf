import pwn

LEVEL = 3.0
OUTPUT = b'\x6d\x6f\x72\x6a\x74'

r = pwn.ssh(user="hacker", host="pwn.college", keyfile="~/.ssh/pwn.college")
p = r.process(f"/challenge/babyrev_level{LEVEL}")
resp = p.recvuntil(b"key!\n\n")
p.sendline(OUTPUT[::-1])
p.recvuntil(b"flag:\n")
print(p.recvall(timeout=1).decode())
