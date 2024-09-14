from array import array
import ast
import os

REG_LABELS = {
    0x400: 'a',
    0x401: 'b',
    0x402: 'c',
    0x403: 'd',
    0x404: 's',
    0x405: 'i',
    0x406: 'f',
}

SYSCALLS = ['open', 'read_code', 'read_mem', 'write', 'sleep', 'exit']

FLAGS = ['lt','gt','eq','ne','z']

INSTRUCTIONS = ['imm', 'add', 'stk', 'stm', 'ldm', 'cmp', 'jmp', 'sys']

class Function:
    def __init__(self, name, function):
        self.name = name
        self.bin_name = function.name
        self.addr = function.addr
        self.func = function

    def __str__(self) -> str:
        return f"{self.name} ({self.bin_name}) @ {self.addr}"


class Register:
    def __init__(self, name, idx):
        self.name = name
        self.idx = idx
        self.val = 0

    def __eq__(self, value: object, /) -> bool:
        if value is not Register or value is not str:
            return False

        return (value is Register and value.name == self.name) or \
               (value is str and value == self.name)

    def __str__(self) -> str:
        return f"{self.name}:\t{hex(self.val)}"


class Registers(list):
    def __getitem__(self, key):
        if isinstance(key, str):
            for i, obj in enumerate(self):
                if obj.name == key:
                    return obj
            raise ValueError(f"No object with name '{key}' found")
        elif isinstance(key, int):
            for i, obj in enumerate(self):
                if obj.idx == key:
                    return obj
            raise ValueError(f"No object with name '{key}' found")
        else:
            return super().__getitem__(key)

    def __str__(self) -> str:
        return '\n'.join([r.__str__() for r in self])


class Memory(array):
    def __init__(self, proj, typecode, initializer=None):
        self.proj = proj
        super().__init__(typecode, initializer or [])

    def set(self, data, loc):
        if type(data) is int:
            self[loc] = data
        else:
            i = 0
            while i < len(data):
                self[i] = data[i]
                i+=1

    def populate(self, memory, idx):
        pass



class CPU:
    def __init__(self, binary):
        import angr
        self.proj = angr.Project(binary, auto_load_libs=False)
        self.cfg = self.proj.analyses.CFGFast()
        self._reg_read_func = None
        self.functions = self._init_functions()
        self.registers = self._init_registers()
        print("\nSYS:")
        self.syscalls = self._extract_code_vals('interpret_sys', SYSCALLS, ['and'])
        print("\nFLAG:")
        self.flag_values = self._extract_code_vals('interpret_cmp', FLAGS, ['or'])
        print("\nINSNS:")
        self.instructions = self._extract_code_vals('interpret_instruction', INSTRUCTIONS, ['and', 'jns'])
        self.memory = self._init_memory()
        self.opcode_order = self._extract_opcode_order()

    def load_vm_mem(self):
        self.code = self._extract_code()
        self._load_mem(self.code, 0)
        self.vmmem = self._extract_vmmem()
        self._load_mem(self.vmmem, 0x300)

    def to_bytecode(self, yan85):
        output = []
        lines = yan85.splitlines()
        for line in lines:
            line = line.replace('*', '').replace('= ', '').lower()
            opcode, arg1, arg2 = line.split(' ')

            op = self.instructions[opcode]

            if opcode == 'sys':
                a1 = self.syscalls[arg1]
            else:
                a1 = self.registers[arg1].idx

            if arg2 in [r.name for r in self.registers]:
                a2 = self.registers[arg2].idx
            else:
                a2 = int(arg2, 16)

            insn = [0, 0, 0]
            insn[self.opcode_order['op']] = op
            insn[self.opcode_order['arg1']] = a1
            insn[self.opcode_order['arg2']] = a2

            output.extend(insn)

        return bytes(output)

    def decomp(self, func_name):
        if self.functions is None:
            raise Exception(f"Function {func_name} not found")

        func = self.functions[func_name]
        func.func.normalize()
        decomp = self.proj.analyses.Decompiler(func.func)
        if decomp.codegen is None or decomp.codegen.text is None:
            raise Exception("Can't decompile function")

        text = decomp.codegen.text
        for f in self.functions:
            text = text.replace(self.functions[f].bin_name, self.functions[f].name)

        return text

    def imm(self, r, val, d=False, run=True):
        reg = self.registers[r]
        if d:
            print(f"[*] IMM {reg.name} = {hex(val)}")
        if not run:
            return
        reg.val = val

    def add(self, r1, r2, d=False, run=True):
        reg1 = self.registers[r1]
        reg2 = self.registers[r2]
        if d:
            print(f"[*] ADD {reg1.name} {reg2.name}")
        if not run:
            return
        reg1.val = (reg1.val + reg2.val) % 256

    def stk(self, r1, r2, d=False, run=True):
        add_tab = ''
        if r2 != 0:
            push_reg = self.registers[r2]
            if d:
                print(f"[*] PUSH {push_reg.name}")
            if run:
                self.registers['s'].val += 1
                self.memory[self.registers['s'].val+0x300] = push_reg.val
            if d:
                add_tab = '\t'
        if r1 != 0:
            pop_reg = self.registers[r1]
            if d:
                print(f"{add_tab}[*] POP {pop_reg.name}")
            if run:
                pop_reg.val = self.memory[self.registers['s'].val+0x300]
                self.registers['s'].val -= 1

    def stm(self, rloc, rval, d=False, run=True):
        reg_loc = self.registers[rloc]
        reg_val = self.registers[rval]
        if d:
            print(f"[*] STM *{reg_loc.name} = {reg_val.name}")
        if not run:
            return
        self.memory[reg_loc.val+0x300] = reg_val.val

    def ldm(self, rdst, rsrc, d=False, run=True):
        reg_dst = self.registers[rdst]
        reg_src = self.registers[rsrc]
        if d:
            print(f"[*] LDM {reg_dst.name} = *{reg_src.name}")
        if not run:
            return
        reg_dst.val = self.memory[reg_src.val+0x300]

    def cmp(self, r1, r2, d=False, run=True):
        flags = self.registers['f']
        reg1 = self.registers[r1]
        reg2 = self.registers[r2]

        if d:
            print(f"[*] CMP {reg1.name} {reg2.name}")
        if not run:
            return

        flags.val = 0

        if reg1.val < reg2.val:
            flags.val |= self.flag_values['lt']

        if reg1.val > reg2.val:
            flags.val |= self.flag_values['gt']

        if reg1.val == reg2.val:
            flags.val |= self.flag_values['eq']

        if reg1.val != reg2.val:
            flags.val |= self.flag_values['ne']

        if reg1.val == 0 and reg2.val == 0:
            flags.val |= self.flag_values['z']

    def jmp(self, flags, reg, d=False, run=True):
        loc = self.registers[reg].val
        name = self.registers[reg].name
        flag_str = self._describe_flags(flags)
        if d:
            print(f"[*] JMP {flag_str} {name} ({hex(loc)})")
        if not run:
            return

        if flags != 0 and self.registers['f'].val & flags == 0:
            if d:
                print("[j] ... NOT TAKEN")
        else:
            if d:
                print("[j] ... TAKEN")
            self.registers['i'].val = loc

    def sys(self, num, r, d=False, run=True):
        reg = self.registers[r]
        syscall = [x for x in self.syscalls if self.syscalls[x] == num][0]
        if d:
            print(f"[*] SYS {syscall} {reg.name}")

        if not run:
            return

        if syscall == 'open':
            try:
                reg.val = self._sys_open(reg)
            except OSError as ex:
                print(f"[-] ERROR: {ex}")
                reg.val = 0xff

        elif syscall == 'read_mem':
            try:
                reg.val = self._sys_read(reg, 0x300)
            except OSError as ex:
                print(f"[-] ERROR: {ex}")
                reg.val = 0xff

        elif syscall == 'read_code':
            try:
                reg.val = self._sys_read(reg, 0)
            except OSError as ex:
                print(f"[-] ERROR: {ex}")
                reg.val = 0xff

        elif syscall == 'write':
            try:
                reg.val = self._sys_write(reg)
            except OSError as ex:
                print(f"[-] ERROR: {ex}")
                reg.val = 0xff

        elif syscall == 'exit':
            exit(self.registers['a'].val)

        else:
            raise NotImplementedError

        if d:
            print(f"... return value (in register {reg.name}): {hex(reg.val)}")

    def _sys_open(self, reg):
        memloc = self.registers['a'].val
        flags = self.registers['b'].val
        filename = []
        while self.memory[memloc+0x300] != 0:
            filename.append(self.memory[memloc+0x300].to_bytes(1, 'little'))
            memloc += 1
        filename = b''.join(filename)
        return os.open(filename, flags)

    def _sys_read(self, reg, offset):
        fd = self.registers['a'].val
        fd = os.dup2(fd, fd+10)
        size = self.registers['c'].val
        memloc = self.registers['b'].val
        with os.fdopen(fd, 'r') as f:
            val = list(f.buffer.readline().strip())[:size]
            for i in range(len(val)):
                self.memory[memloc+i+offset] = val[i]

        return len(val)

    def _sys_write(self, reg):
        fd = self.registers['a'].val
        fd = os.dup2(fd, fd+10)
        size = self.registers['c'].val
        memloc = self.registers['b'].val
        with os.fdopen(fd, 'w') as f:
            res = self.memory[memloc+0x300:memloc+size+0x300]
            x = b''.join([c.to_bytes(1, 'little') for c in res])
            return f.buffer.write(x)

    def _init_registers(self):
        reg_read_func = self._get_reg_read_func()
        reg_vals = self._get_reg_vals(reg_read_func)
        registers = Registers([Register(x, reg_vals[x]) for x in reg_vals])
        registers.append(Register("none", 0))
        print("REG:")
        for r in registers:
            print(f"{r.name}\t| {hex(r.idx)}")
        return registers

    def _init_memory(self):
        return [0]*0x400

    def _init_functions(self):
        output = {}
        names = [
            'interpret_imm',
            'interpret_add',
            'interpret_stk',
            'interpret_stm',
            'interpret_ldm',
            'interpret_cmp',
            'interpret_jmp',
            'interpret_sys',
            'interpret_instruction',
            'interpreter_loop',
            'main',
        ]
        interp_loop = self._get_interp_loop()
        all_funcs = list(self.cfg.functions.values())
        idx = all_funcs.index(interp_loop)
        funcs = all_funcs[idx-9:idx+2]
        for n, f in zip(names, funcs):
            output[n] = Function(n, f)

        return output

    def _get_reg_read_func(self):
        if self._reg_read_func is not None:
            return self._reg_read_func

        for func in self.cfg.functions.values():

            if func.symbol is not None and func.symbol.name == 'read_register':
                return func

            cmp_instructions = 0
            for block in func.blocks:
                for insn in (i for i in block.capstone.insns if i.mnemonic == 'cmp'):
                    cmp_instructions += 1

            if cmp_instructions == 7:
                self._reg_read_func = func
                return func

    def _get_reg_vals(self, func):

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

    def _get_sys_func(self):
        if hasattr(self, 'functions'):
            return self.functions['interpret_sys'].func

        for func in self.cfg.functions.values():
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

    def _get_sys_vals(self, func):
        output = {}
        funcs = ['open', 'read_code', 'read_mem', 'write', 'sleep', 'exit']
        func_vals = []

        for block in func.blocks:

            for insn in (i for i in block.capstone.insns if i.mnemonic == 'and'):
                src = insn.op_str.split(', ')[1]
                func_vals.append(int(src, 16))

        for f, v in zip(funcs, func_vals):
            output[f] = v

        return output

    def _extract_code_vals(self, func_name, options, mnemonics):
        if self.functions is None:
            raise Exception("Functions property is not set")

        output = {}
        output = {}
        func_vals = []

        func = self.functions[func_name].func
        for block in func.blocks:

            for insn in (i for i in block.capstone.insns if i.mnemonic in mnemonics):
                if ',' in insn.op_str:
                    src = insn.op_str.split(', ')[1]
                    func_vals.append(int(src, 16))
                else:
                    func_vals.append(0x80)

        for f, v in zip(options, func_vals):
            output[f] = v

        for s in output:
            print(f"{s}\t| {hex(output[s])}")

        return output

    def _get_interp_loop(self):
        if hasattr(self, 'functions'):
            return self.functions['interpreter_loop'].func

        main = self._get_main_function()

        for block in main.blocks:
            for insn in (f for f in block.capstone.insns if f.mnemonic == 'call'):
                call_addr = int(insn.op_str, 16)
                section = self.proj.loader.find_section_containing(call_addr)
                if section is not None and section.name == '.text':
                    self._interp_loop = self.cfg.kb.functions[call_addr]
                    return self._interp_loop

        raise Exception("interpreter_loop function not found")

    def _get_main_function(self):
        start = self.cfg.kb.functions[self.proj.entry]
        call_insn = list(start.blocks)[0].capstone.insns[-1]
        offset_insn = list(start.blocks)[0].capstone.insns[-2]
        offset = int(offset_insn.op_str.split('+ ')[1].replace(']', ''), 16)
        target_addr = call_insn.address + offset
        main = self.cfg.kb.functions[target_addr]
        return main

    def _extract_code(self):

        # Convert symbol to address if available
        try:
            code_addr = self.proj.loader.find_symbol('vm_code').rebased_addr
            size_addr = self.proj.loader.find_symbol('vm_code_length').rebased_addr
        except Exception:
            # Extract params from the memcpy function
            memcpy = [m for m in self.decomp('main').splitlines() if 'memcpy' in m][0]
            code_loc = memcpy.split(',')[1].strip().replace('g_', '').replace('&', '')
            size_loc = memcpy.split(',')[2].strip().replace('g_', '').replace('&', '').replace(');', '')
            code_addr = int(code_loc, 16)
            size_addr = int(size_loc, 16)

        # Extract the size and code data
        state = self.proj.factory.entry_state()
        size_bv = state.memory.load(size_addr, 4, endness='Iend_LE')
        size = state.solver.eval(size_bv)
        code_bv = state.memory.load(code_addr, size)
        code = list(state.solver.eval(code_bv, cast_to=bytes))
        return code

    def _extract_vmmem(self):
        #TODO: Try merge this and extract_code
        try:
            mem_addr = self.proj.loader.find_symbol('vm_mem').rebased_addr
        except Exception:
            code = self.decomp('main').splitlines()
            mov_idx = 0
            for i in range(len(code)):
                if 'memcpy' in code[i]:
                    mov_idx = i+1
                    break
            mov = code[mov_idx]
            mem_loc = mov.split(' = ')[1].strip().replace('g_', '').replace(';', '')
            mem_addr = int(mem_loc, 16)

        state = self.proj.factory.entry_state()
        vm_mem_bv = state.memory.load(mem_addr, 0x100)
        vm_mem = list(state.solver.eval(vm_mem_bv, cast_to=bytes))
        return vm_mem

    def _load_mem(self, data, idx):
        i = idx
        while i < len(data)+idx:
            self.memory[i] = data[i-idx]
            i += 1

    def _extract_opcode_order(self):
        if self.functions is None:
            raise Exception("Functions property is not set")

        # This is too hard to figure out
        if self.proj.filename is None:
            raise Exception("No filename")

        if self.proj.filename.find('19.0') > 0:
            return {'op': 0, 'arg1': 1, 'arg2': 2}
        elif self.proj.filename.find('19.1') > 0:
            return {'op': 1, 'arg1': 2, 'arg2': 0}
        elif self.proj.filename.find('20.0') > 0:
            return {'op': 1, 'arg1': 0, 'arg2': 2}
        elif self.proj.filename.find('20.1') > 0:
            return {'op': 2, 'arg1': 1, 'arg2': 0}
        elif self.proj.filename.find('21.0') > 0:
            return {'op': 1, 'arg1': 2, 'arg2': 0}
        elif self.proj.filename.find('21.1') > 0:
            return {'op': 1, 'arg1': 0, 'arg2': 2}
        elif self.proj.filename.find('22.0') > 0:
            return {'op': 0, 'arg1': 2, 'arg2': 1}
        elif self.proj.filename.find('22.1') > 0:
            return {'op': 1, 'arg1': 2, 'arg2': 0}

        """
        19.0: {0, 1, 2}
        19.1: {1, 2, 0}
        20.0: {1, 0, 2}
        20.1: {2, 1, 0}
        21.0: {1, 2, 0}
        21.1: {1, 0, 2}
        22.0: {0, 2, 1}
        22.1: {1, ?, ?}
        """

        output = {}
        ii = self.functions['interpret_instruction'].func

        print(self.decomp('interpret_instruction'))
        for block in ii.blocks:
            #for insn in block.capstone.insns:
            for insn in (f for f in block.capstone.insns if f.mnemonic == 'movzx' and 'rbp' in f.op_str):
                if insn.op_str.split(' - ')[1] == '0xe]':
                    output['op'] = 2
                    break
                elif insn.op_str.split(' - ')[1] == '0xf]':
                    output['op'] = 1
                    break
                elif insn.op_str.split(' - ')[1] == '0x10]':
                    output['op'] = 0
                    break

                raise Exception(f"Opcode position not found: {insn}")

        ii = self.functions['interpret_jmp'].func
        for block in ii.blocks:
            #for insn in block.capstone.insns:
            i = 0
            insns = list(block.capstone.insns)
            for i in range(len(insns)):
            #for insn in (f for f in block.capstone.insns):
                insn = insns[i]
                if insn.mnemonic == 'movzx' and insns[i+1].mnemonic == 'test':
                    print(insn)
                else:
                    continue
                if insn.op_str.split(' - ')[1] == '0xe]':
                    output['op'] = 2
                    break
                elif insn.op_str.split(' - ')[1] == '0xf]':
                    output['op'] = 1
                    break
                elif insn.op_str.split(' - ')[1] == '0x10]':
                    output['op'] = 0
                    break

        print(output)
        exit()

    def _describe_flags(self, flag):
        flags = []
        if flag & self.flag_values['lt'] != 0:
            flags.append('L')
        if flag & self.flag_values['gt'] != 0:
            flags.append('G')
        if flag & self.flag_values['eq'] != 0:
            flags.append('E')
        if flag & self.flag_values['ne'] != 0:
            flags.append('N')
        if flag & self.flag_values['z'] != 0:
            flags.append('Z')
        if flag == 0:
            flags.append('*')

        return ''.join(flags)


class Debugger:
    def __init__(self, cpu) -> None:
        self.cpu = cpu
        self.breakpoints = []
        self.ins_dbg = True
        self.stk_dbg = True
        self.reg_dbg = True

    def run(self):
        while True:
            self.step()

    def debug(self):
        last = 'h'
        while True:
            i = self.cpu.registers['i'].val
            c = input("> ")
            if len(c) == 0:
                c = last

            if len(c) == 1 and c[0] in ['h', '?']:
                self.help()
            elif len(c) == 1 and c[0] == 'q':
                exit()
            elif len(c) == 1 and c[0] == 'd':
                self.disassemble(0, len(self.cpu.memory)/3-1, i)
            elif len(c) == 1 and c[0] == 'n':
                self.step()
                if self.reg_dbg:
                    self._print_sec("REGISTERS")
                    print(self.cpu.registers)
                if self.stk_dbg:
                    self.print_memory(0x300, 0, 'x')
                if self.ins_dbg:
                    self.get_instructions()
                self._print_sec("")
            elif len(c) == 1 and c[0] == 'c':
                self.cont()
            elif c[0] == 'i':
                self.info(c)
            elif c[0] == 'x':
                try:
                    self.examine(c)
                except Exception:
                    pass
            elif c[0] == 'b':
                self.breakpoint(c)
            elif c.startswith("set"):
                self.setopt(c)
            last = c

    def help(self):
        print("Commands:")
        print("  n: next")
        print("  c: continue")
        print("  x [n] [mem]: examine n bytes in memory at location `mem`")
        print("      n=[six]: examine data as string / integers / hex")
        print("      mem=$r: examine data pointed to by register r")
        print("      mem=0xm: examine data pointed to at location 0xm")
        print("  i r: Get register info")
        print("  i b: Get breakpoint info")
        print("  set [opt] [val]: Set an option to a value")
        print("      debug {i,s,r}: Set debug flags for instructions, stack or registers on or off")
        print("      m [val]: Set a memory location to a value (can be a list)")
        print("      [r] [val]: Set a register to a value")
        print("  q: quit ")
        print("  [h,?]: help ")

    def cont(self):
        while True:
            if self.cpu.registers['i'].val in self.breakpoints:
                return
            self.step()

    def step(self):
        i = self.cpu.registers['i'].val
        self.cpu.registers['i'].val += 1
        insn = self.cpu.memory[i*3:i*3+3]

        opcode_idx = self.cpu.opcode_order['op']
        arg1_idx = self.cpu.opcode_order['arg1']
        arg2_idx = self.cpu.opcode_order['arg2']

        opcode = insn[opcode_idx]
        func = [f for f in self.cpu.instructions if self.cpu.instructions[f] == opcode][0]
        op = f"self.cpu.{func}({insn[arg1_idx]}, {insn[arg2_idx]}, d={self.ins_dbg})"
        exec(op)

    def get_instructions(self):
        self._print_sec("INSTRUCTIONS")
        i = self.cpu.registers['i'].val
        #print(self.cpu.registers)
        f = 0 if i < 3 else i-3
        t = len(self.cpu.memory) if i > len(self.cpu.memory)-1 else i+1
        self.disassemble(f, t, i)

    def print_memory(self, start, end, enc):
        i = start
        e = len(self.cpu.memory) if end == 0 else end
        per_line = 8
        stack_ptr = self.cpu.registers['s'].val + 0x300

        print()
        self._print_sec("MEMORY")
        print("addr\t\t", end='')
        for p in range(per_line):
            print(f"{hex(p)}\t", end='')
        print()
        print()

        while i < e:
            ptr = "-->" if stack_ptr >= i and stack_ptr < i+per_line else ""
            m = self.cpu.memory
            print(f"{hex(i)}\t{ptr}\t", end='')
            for n in range(per_line):
                val = hex(m[i+n])
                if i+n == stack_ptr:
                    print(f"[{val}]\t", end='')
                else:
                    print(f"{val}\t", end='')
                n += 1
            i += per_line
            print()

    def info(self, cmd):
        cmd = cmd.replace(' ', '')
        if len(cmd) == 2 or len(cmd) == 3:
            if cmd[1] == 'b':
                print([hex(b) for b in self.breakpoints])
            elif cmd[1] == 'r':
                if len(cmd) == 3:
                    reg = cmd[1]
                    print(self.cpu.registers[reg])
                else:
                    print(self.cpu.registers)

    def examine(self, cmd):
        cmd = cmd.split(' ')
        if len(cmd) != 3:
            return

        # x 0x3c $a
        if cmd[2].startswith('$'):
            loc = self.cpu.registers[cmd[2][1]].val + 0x300
        else:
            loc = self._get_num(cmd[2])

        enc = cmd[1][-1]
        cnt = self._get_num(cmd[1][:-1])

        mem = self.cpu.memory[loc:loc+cnt]
        if enc == 'i':
            print(mem)
        elif enc == 'c':
            print([chr(i) for i in mem])
        elif enc == 's':
            print(''.join([chr(i) for i in mem]))
        elif enc == 'x':
            print([hex(i) for i in mem])

    def breakpoint(self, cmd):
        cmd = cmd.split(' ')
        if len(cmd) == 2:
            loc = self._get_num(cmd[1])

            if loc not in self.breakpoints and loc <= len(self.cpu.memory):
                self.breakpoints.append(loc)

    def disassemble(self, f, t, hl):
        i = f
        while i <= t:
            try:
                self._debug_ins(i, hl)
            except Exception:
                bytecode = self.cpu.memory[i*3:i*3+3]
                print(f"[e] Instruction Error @ i={i}: {bytecode}")
            i += 1

    def setopt(self, cmd):
        cmd = cmd.split(' ')
        if cmd[1].lower() == 'debug':
            c = cmd[2].lower()
            self._set_debug(c)
        else:
            self._set_mem(cmd)

    def _set_debug(self, c):
        if 'i' in c:
            self.ins_dbg = not self.ins_dbg
        if 'r' in c:
            self.reg_dbg = not self.reg_dbg
        if 's' in c:
            self.stk_dbg = not self.stk_dbg
        print(f"INS_DBG: {self.ins_dbg}")
        print(f"REG_DBG: {self.reg_dbg}")
        print(f"STK_DBG: {self.stk_dbg}")

    def _set_mem(self, cmd):
        if cmd[1][0] == '$':
            val = self._get_num(cmd[2])
            reg = self.cpu.registers[cmd[1][1]]
            print(f"Setting reg {reg} to {val}")
            reg.val = val
        else:
            addr = self._get_num(cmd[1])
            if cmd[2].startswith('['):
                vals = ast.literal_eval(cmd[2])
                i = 0
                while i < len(vals):
                    self.cpu.memory[addr+i] = vals[i]
                    i += 1
            else:
                val = self._get_num(cmd[2])
                self.cpu.memory[addr] = val


    def _debug_ins(self, i, hl):
        insn = self.cpu.memory[i*3:i*3+3]

        opcode_idx = self.cpu.opcode_order['op']
        arg1_idx = self.cpu.opcode_order['arg1']
        arg2_idx = self.cpu.opcode_order['arg2']

        opcode = insn[opcode_idx]
        func = [x for x in self.cpu.instructions if self.cpu.instructions[x] == opcode][0]
        prt = f"{hex(i)}: -->" if i == hl else f"{hex(i)}:"
        print(prt, end="\r\t")
        op = f"self.cpu.{func}({insn[arg1_idx]}, {insn[arg2_idx]}, {self.ins_dbg}, False)"
        exec(op)


    def _get_num(self, num):
        print(num)
        if num.startswith('0x'):
            return int(num, 16)
        else:
            return int(num)

    def _print_sec(self, text):
        max_len = 80

        if len(text) == 0:
            print("-"*max_len)
        else:
            split = int((max_len - len(text) - 2) / 2)
            print('-'*split + " " + text + " " + "-"*split)
