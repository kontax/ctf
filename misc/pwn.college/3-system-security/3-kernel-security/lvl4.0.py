import fcntl
import os

fd = os.open('/proc/pwncollege', os.O_RDWR)
fcntl.ioctl(fd, 0x539, 'bzwgjygwcmubnzhp')
os.close(fd)
with open('/flag', 'r') as f:
    print(f.read())
