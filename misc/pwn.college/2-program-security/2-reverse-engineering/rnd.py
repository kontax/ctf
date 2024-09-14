import pwn

BINARY = 'binaries/babyrev_level22.1'
CODES = [b'\x00', b'\x01', b'\x02', b'\x04', b'\x08', b'\x10', b'\x20', b'\x40', b'\x80']
pwn.context.log_level = 'error'



OPCODE_ORDER = {'op': 0xff, 'arg1': 0xff, 'arg2': 0xff}
REGS = {
    'a': b'\xff',
    'b': b'\xff',
    'c': b'\xff',
    'd': b'\xff',
    'i': b'\xff',
    's': b'\xff',
    'f': b'\xff',
}
INSN = {
    'imm': 0xff,
    'add': 0xff,
    'stk': 0xff,
    'stm': 0xff,
    'ldm': 0xff,
    'cmp': 0xff,
    'jmp': 0xff,
    'sys': 0xff,
}
SYS = {
    'open': 0xff,
    'read_code': 0xff,
    'read_mem': 0xff,
    'write': 0xff,
    'sleep': 0xff,
    'exit': 0xff,
}



def pb(data):
    return "".join(f"\\x{byte:02x}" for byte in data)


def find_vals(ops, arg1s, arg2s, pred, indices, prepend=None, append=None, debug=False):
    commands = []
    for op in ops:
        for a1 in arg1s:
            for a2 in arg2s:
                data_list = [b'\0']*3
                data_list[indices[0]] = op
                data_list[indices[1]] = a1
                data_list[indices[2]] = a2

                x = b''.join(data_list)
                if debug:
                    print(x.hex())
                if prepend is not None:
                    x = prepend + x
                if append is not None:
                    x = x + append
                if get_exit_code(x, pred, debug):
                    commands.append(data_list)

    return commands

def get_exit_code(yancode, test_code, debug=False):
    with pwn.process(BINARY) as p:
        p.recvuntil(b"yancode: ")
        p.sendline(yancode)
        p.recvuntil(b"luck!")
        output = p.recv().decode()
        exit_code = p.poll()
        if debug:
            print(f"INPUT: {pb(yancode)}")
            print(output)
            print(f"EXIT: {exit_code}")
            print("-"*20)
        return exit_code is not None and exit_code == test_code

def get_data(yancode, test_data, debug=False):
    with pwn.process(BINARY) as p:
        p.recvuntil(b"yancode: ")
        p.sendline(yancode)
        p.recvuntil(b"luck!")
        output = p.recv().decode()
        if debug:
            print(f"echo -e \"{pb(yancode)}\" | {BINARY}")
            print(output)
        exit_code = p.poll()
        if debug:
            print(output)
            print(f"EXIT: {exit_code}")
            print("-"*20)
        return test_data.decode() in output


def ins(op, arg1, arg2):
    insn = [b'\0']*3
    o = op if type(op) is bytes else INSN[op].to_bytes()
    a1 = arg1 if type(arg1) is bytes else REGS[arg1] if len(arg1) == 1 else SYS[arg1].to_bytes()
    a2 = arg2 if type(arg2) is bytes else REGS[arg2]
    insn[OPCODE_ORDER['op']] = o
    insn[OPCODE_ORDER['arg1']] = a1
    insn[OPCODE_ORDER['arg2']] = a2
    return b''.join(insn)


def get_write():
    # IMM a = 0x41
    # STK 0 a
    # STK 0 a
    # STK 0 a
    # IMM a = 1
    # IMM c = 4 (test)
    # SYS write (test)
    # SYS exit
    imm_a_a = ins('imm', 'a', b'\x41')
    imm_a_1 = ins('imm', 'a', b'\x01')
    psh_a = ins('stk', b'\0', 'a')
    for c in CODES:
        sys_write = ins('sys', c, 's')
        for r in CODES:
            imm_c_4 = ins('imm', r, b'\04')
            code = imm_a_a + psh_a + psh_a + psh_a + imm_a_1 + imm_c_4 + sys_write + sys_exit
            if get_data(code, b'AAA'):
                SYS['write'] = int.from_bytes(c)
                REGS['c'] = r
                return




if __name__ == '__main__':

    # Find the opcode for sys_exit
    potential_sys_codes = find_vals(CODES, CODES, CODES, 0, [0, 1, 2])
    potential_order = {}
    potential_order[0] = len(set(p[0] for p in potential_sys_codes))
    potential_order[1] = len(set(p[1] for p in potential_sys_codes))
    potential_order[2] = len(set(p[2] for p in potential_sys_codes))

    for ix in potential_order:
        if potential_order[ix] > 1:
            OPCODE_ORDER['arg2'] = ix
            break

    print(OPCODE_ORDER)

    exit_bytecode = [b'\0']*3
    for i in range(3):
        if OPCODE_ORDER['arg2'] != i:
            exit_bytecode[i] = potential_sys_codes[0][i]
        else:
            exit_bytecode[i] = b'\0'
    sys_exit = b''.join(exit_bytecode)
    print(sys_exit.hex())


    # Find IMM a = 0xa; SYS exit \0
    test_val = b'\x0a'
    indices = [0, 1, 2]
    indices.remove(OPCODE_ORDER['arg2'])
    indices.append(OPCODE_ORDER['arg2'])
    print(indices)

    imm_bytecode_list = find_vals(CODES, CODES, [test_val],
                              int.from_bytes(test_val),
                              indices, None, sys_exit)[0]
    print(imm_bytecode_list)

    # Find:
    #   IMM a = 0xa
    #   IMM i = 3 (test op + arg1)
    #   SYS exit
    #   IMM a = 0xb
    #   SYS exit
    test_val = b'\x0b'
    imm_a = b''.join(imm_bytecode_list)
    imm_bytecode_list[OPCODE_ORDER['arg2']] = test_val
    imm_b = b''.join(imm_bytecode_list)
    append = sys_exit + imm_b + sys_exit
    insn_bytecode_list = find_vals(CODES, CODES, [b'\x03'],
                              int.from_bytes(test_val),
                              indices, imm_a, append)[0]
    print(insn_bytecode_list)
    print(imm_bytecode_list)

    for i in range(3):
        if insn_bytecode_list[i] == imm_bytecode_list[i]:
            OPCODE_ORDER['op'] = i
            INSN['imm'] = int.from_bytes(imm_bytecode_list[i])
            INSN['sys'] = sys_exit[i]
        elif imm_bytecode_list[i] == test_val:
            continue
        else:
            OPCODE_ORDER['arg1'] = i
            REGS['i'] = insn_bytecode_list[i]
            REGS['a'] = imm_bytecode_list[i]
            SYS['exit'] = sys_exit[i]

    print("-"*10)
    print(OPCODE_ORDER)
    print(REGS)
    print(INSN)


    # IMM a = 0xa
    # IMM x = 0x30
    # ADD x  a (test)
    # SYS exit ( == 0xa)
    imm_a = ins('imm', 'a', b'\x0a')
    reg_x = [i for i in CODES if i not in [REGS['i'], REGS['a'], b'\0']][0]
    imm_x = ins('imm', reg_x, b'\x30')
    for c in CODES:
        add = ins(c, 'a', reg_x)
        code = imm_a + imm_x + add + sys_exit
        if get_exit_code(code, 0x3a):
            INSN['add'] = int.from_bytes(c)
            break
    print(INSN)

    # IMM a = 0x0a
    # STK 0 a (test)
    # IMM a = 1
    # STK a 0 (test)
    # SYS exit ( == 0a)
    potential_stk = []
    imm_a_a = ins('imm', 'a', b'\x0a')
    imm_a_1 = ins('imm', 'a', b'\x01')
    for c in CODES:
        psh = ins(c, b'\0', 'a')
        pop = ins(c, 'a', b'\0')
        code = imm_a_a + psh + imm_a_1 + pop + sys_exit
        if get_exit_code(code, 10):
            INSN['stk'] = int.from_bytes(c)
            break

    print(INSN)

    # PSH {reg} 0
    # PSH {reg} 0
    # ADD a {reg}
    # SYS exit ( == 2)
    for c in CODES:
        psh = ins('stk', b'\0', 'a')
        add = ins('add', 'a', c)
        code = psh + psh + add + sys_exit
        if get_exit_code(code, 2):
            REGS['s'] = c
            break

    print(REGS)

    # IMM a = 0xa
    # STM *s = a (test)
    # IMM a = 0
    # STK a 0
    # SYS exit ( == 0xa)
    imm_a_a = ins('imm', 'a', b'\x0a')
    imm_a_0 = ins('imm', 'a', b'\0')
    pop_a = ins('stk', 'a', b'\0')
    for c in CODES:
        stm = ins(c, 's', 'a')
        code = imm_a_a + stm + imm_a_0 + pop_a + sys_exit
        if get_exit_code(code, 0xa):
            INSN['stm'] = int.from_bytes(c)
            break

    print(INSN)


    # IMM a = 0xa
    # STK 0 a
    # IMM a = 0
    # LDM a = *s (test)
    # SYS exit ( == 0xa)
    imm_a_a = ins('imm', 'a', b'\x0a')
    imm_a_0 = ins('imm', 'a', b'\0')
    psh_a = ins('stk', b'\0', 'a')
    for c in CODES:
        ldm = ins(c, 'a', 's')
        code = imm_a_a + psh_a + imm_a_0 + ldm + sys_exit
        if get_exit_code(code, 0xa):
            INSN['ldm'] = int.from_bytes(c)
            break

    print(INSN)


    get_write()

    print(SYS)
    print(REGS)

    # IMM a = 0x41
    # IMM s = 0x30
    # STK 0 a
    # STK 0 a
    # STK 0 a
    # IMM a = 1
    # IMM c = 4
    # IMM b = 0x30 (test)
    # SYS write
    # SYS exit
    imm_a_a = ins('imm', 'a', b'\x41')
    imm_a_1 = ins('imm', 'a', b'\x01')
    psh_a = ins('stk', b'\0', 'a')
    imm_c_4 = ins('imm', 'c', b'\x04')
    imm_s_30 = ins('imm', 's', b'\x30')
    sys_write = ins('sys', 'write', 's')
    for c in CODES:
        imm_b_30 = ins('imm', c, b'\x30')
        code = imm_a_a + imm_s_30 + psh_a + psh_a + psh_a + imm_a_1 + \
            imm_c_4 + imm_b_30 + sys_write + sys_exit
        if get_data(code, b'AAA'):
            REGS['b'] = c
            break

    print(REGS)


    # Find open and read_mem as readmem from stdin doesn't work

    # IMM a = 0x74
    # STK 0 a
    # IMM a = 0x73
    # STK 0 a
    # IMM a = 0x74
    # STK 0 a
    # IMM a = 0
    # IMM b = 0
    # SYS open a (test)
    # IMM b = 0
    # IMM c = 0xff
    # SYS read_mem a (test)
    # IMM b = 0
    # IMM c = 0
    # ADD c a
    # IMM a = 1
    # SYS write a
    # IMM a = 0
    # SYS exit
    pre = ins('imm', 'a', b'\x74') + \
          ins('stk', b'\0', 'a') + \
          ins('imm', 'a', b'\x73') + \
          ins('stk', b'\0', 'a') + \
          ins('imm', 'a', b'\x74') + \
          ins('stk', b'\0', 'a') + \
          ins('imm', 'a', b'\x01') + \
          ins('imm', 'b', b'\0')

    mid = ins('imm', 'b', b'\0') + \
          ins('imm', 'c', b'\xff')

    pst = ins('imm', 'b', b'\0') + \
          ins('imm', 'c', b'\0') + \
          ins('add', 'c', 'a') + \
          ins('imm', 'a', b'\x01') + \
          ins('sys', 'write', 'a') + \
          ins('imm', 'a', b'\0') + \
          ins('sys', 'exit', b'\0')

    test = [o for o in CODES if o not in [SYS[x].to_bytes() for x in SYS]]
    for o in test:
        sys_open = ins('sys', o, 'a')
        for r in test:
            read_mem = ins('sys', r, 'a')
            code = pre + sys_open + mid + read_mem + pst
            if get_data(code, b'AAA'):
                SYS['open'] = int.from_bytes(o)
                SYS['read_mem'] = int.from_bytes(r)
                break

    print(SYS)


    # Get the flag
    code = ins('imm', 'a', b'\x2f') + \
           ins('stk', b'\0', 'a') + \
           ins('imm', 'a', b'\x66') + \
           ins('stk', b'\0', 'a') + \
           ins('imm', 'a', b'\x6c') + \
           ins('stk', b'\0', 'a') + \
           ins('imm', 'a', b'\x61') + \
           ins('stk', b'\0', 'a') + \
           ins('imm', 'a', b'\x67') + \
           ins('stk', b'\0', 'a') + \
           ins('imm', 'a', b'\0') + \
           ins('stk', b'\0', 'a') + \
           ins('imm', 'a', b'\x01') + \
           ins('imm', 'b', b'\0') + \
           ins('sys', 'open', 'a') + \
           ins('imm', 'b', b'\0') + \
           ins('imm', 'c', b'\xff') + \
           ins('sys', 'read_mem', 'a') + \
           ins('imm', 'b', b'\0') + \
           ins('imm', 'c', b'\0') + \
           ins('add', 'c', 'a') + \
           ins('imm', 'a', b'\x01') + \
           ins('sys', 'write', 'a') + \
           ins('imm', 'a', b'\0') + \
           ins('sys', 'exit', b'\0')

    with pwn.process(BINARY) as p:
        p.recvuntil(b"yancode: ")
        p.sendline(code)
        p.recvuntil(b"luck!")
        output = p.recv().decode()
        print(output)
