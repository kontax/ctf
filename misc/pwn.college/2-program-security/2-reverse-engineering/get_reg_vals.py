import angr

REG_LABELS = {
    0x100: 'a',
    0x101: 'b',
    0x102: 'c',
    0x103: 'd',
    0x104: 's',
    0x105: 'i',
    0x106: 'f',
}

def get_reg_read_func(cfg):
    for func in cfg.functions.values():

        if func.symbol is not None and func.symbol.name == 'read_register':
            return func

        cmp_instructions = 0
        for block in func.blocks:
            for insn in (i for i in block.capstone.insns if i.mnemonic == 'cmp'):
                cmp_instructions += 1

        if cmp_instructions == 7:
            return func

def get_reg_vals(func):

    output = {}
    registers = []
    reg_vals = []

    for block in func.blocks:

        insns = block.capstone.insns

        # Entry Block
        if block.addr == func.addr:
            entry = insns[7].bytes[-1]
            reg_vals.append(entry)
            continue

        if block.size == 13:
            val = int.from_bytes(insns[1].bytes[3:5], 'little')
            registers.append(val)
            continue

        if block.size == 6:
            entry = insns[0].bytes[-1]
            reg_vals.append(entry)
            continue

    for r, v in zip(registers, reg_vals):
        output[REG_LABELS[r]] = v

    return output

def get_sys_func(cfg):
    for func in cfg.functions.values():
        func_name = hex(func.addr) if not func.symbol else func.symbol.name
        num_blocks = len(list(func.blocks))
        if num_blocks not in [26,15]:
            continue

        distinct_functions = set()
        for block in func.blocks:
            distinct_functions.update(
                set([i.op_str
                    for i in block.capstone.insns
                    if i.mnemonic == 'call']))

        num_funcs = len(distinct_functions)

        if (num_blocks == 26 and num_funcs == 10) or \
            (num_blocks == 15 and num_funcs == 6 and func_name != 'interpret_stk'):
            return func

def get_sys_vals(func):
    output = {}
    funcs = ['open', 'read', 'write', 'sleep', 'exit']
    func_vals = []

    for block in func.blocks:

        for insn in (i for i in block.capstone.insns if i.mnemonic == 'and'):
            src = insn.op_str.split(', ')[1]
            func_vals.append(int(src, 16))

    for f, v in zip(funcs, func_vals):
        output[f] = v

    return output

if __name__ == '__main__':
    #proj = angr.Project('binaries/babyrev_level16.1', auto_load_libs=False)
    for b in ['12.0', '12.1', '13.0', '13.1', '14.0', '14.1', '15.0', '15.1', '16.0', '16.1']:
        print(b)
        proj = angr.Project(f"binaries/babyrev_level{b}", auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        reg_read_func = get_reg_read_func(cfg)
        reg_vals = get_reg_vals(reg_read_func)
        print(reg_vals)
        sys_func = get_sys_func(cfg)
        sys_vals = get_sys_vals(sys_func)
        print(sys_vals)
