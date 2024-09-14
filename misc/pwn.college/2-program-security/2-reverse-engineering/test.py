from yan85_interpreter import CPU, Debugger

def autoexec(cpu):

    code = cpu.decomp('interpreter_loop')
    tmp = ["def run(cpu):"]
    tmp.extend(code.splitlines()[9:])
    tmp.append("run(cpu)")
    py = '\n'.join(tmp)
    print(py)
    print('-'*15)
    exec(py)


def run(cpu):
    pass


def get_bytecode(cpu):
    with open('code/open_flag.y85', 'r') as f:
        y85 = f.read()

    print("Y85:")
    print(y85)

    print("\nBYTECODE:")
    bytecode = cpu.to_bytecode(y85)
    i = 0
    while i < len(bytecode):
        bc = bytecode[i:i+3]
        print([hex(b) for b in bc])
        i += 3

    return bytecode



if __name__ == '__main__':
    cpu = CPU('binaries/babyrev_level22.0')
    #cpu.load_vm_mem()
    get_bytecode(cpu)
    exit()

    print(f"BINARY: {cpu.proj.filename}")
    d = Debugger(cpu)
    d.debug()
    #autoexec(cpu)

