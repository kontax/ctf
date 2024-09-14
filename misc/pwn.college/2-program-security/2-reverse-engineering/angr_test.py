import angr


def get_sys_func(cfg):
    for func in cfg.functions.values():
        num_blocks = len(list(func.blocks))
        #print(num_blocks)
        #print(func)
        if num_blocks not in [26,15]:
            continue

        distinct_functions = set()
        for block in func.blocks:
            distinct_functions.update(
                set([i.op_str
                    for i in block.capstone.insns
                    if i.mnemonic == 'call']))

        num_funcs = len(distinct_functions)
        func_name = hex(func.addr) if not func.symbol else func.symbol.name

        #print(func)
        #print(f"BLOCKS: {num_blocks}")
        #print(f"DISTINCT FUNCTIONS: {num_funcs}")
        #print(f"FUNC NAME: {func_name}")
        if (num_blocks == 26 and num_funcs == 10) or \
            (num_blocks == 15 and num_funcs == 6 and func_name != 'interpret_stk'):
            #print(distinct_functions)
            return func

def get_sys_vals(func):
    output = {}
    funcs = ['open', 'read', 'write', 'sleep', 'exit']
    func_vals = []

    for block in func.blocks:

        insns = block.capstone.insns
        block_object = proj.factory.block(block.addr)
        #for insn in block_object.capstone.insns:
        for insn in (i for i in block_object.capstone.insns if i.mnemonic == 'and'):
            src = insn.op_str.split(', ')[1]
            func_vals.append(int(src, 16))
            #print(insn)
            #print(src)

    for f, v in zip(funcs, func_vals):
        output[f] = v

    return output

def get_exec_prog_func(proj, cfg, start_func):
    call_insn = list(start_func.blocks)[0].capstone.insns[-1]
    offset_insn = list(start_func.blocks)[0].capstone.insns[-2]
    offset = int(offset_insn.op_str.split('+ ')[1].replace(']', ''), 16)
    target_addr = call_insn.address + offset
    main = cfg.functions.get(target_addr)

    for block in main.blocks:
        for insn in (f for f in block.capstone.insns if f.mnemonic == 'call'):
            call_addr = int(insn.op_str, 16)
            print(call_addr)
            if proj.loader.find_section_containing(call_addr).name == '.text':
                return cfg.functions.get(call_addr)

    raise Exception("execute_program function not found")

if __name__ == '__main__':
    for b in ['12.0', '12.1', '13.0', '13.1', '14.0', '14.1', '15.0', '15.1', '16.0', '16.1']:
        print(b)
        proj = angr.Project(f"binaries/babyrev_level{b}", auto_load_libs=False)
        cfg = proj.analyses.CFGEmulated()
        entry = proj.entry
        #for f in cfg.functions.values():
        #    print(f"{f.symbol}: {f.addr}")
        start = cfg.functions.get(entry)
        exec_prog = get_exec_prog_func(proj, cfg, start)
        print(exec_prog)
        exec_prog.normalize()
        decomp = proj.analyses.Decompiler(exec_prog)
        if decomp.codegen is not None and decomp.codegen.text is not None:
            print(decomp.codegen.text)
