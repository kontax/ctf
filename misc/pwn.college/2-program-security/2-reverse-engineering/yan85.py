import os
import re

REG_LABELS = {
    0x100: 'a',
    0x101: 'b',
    0x102: 'c',
    0x103: 'd',
    0x104: 's',
    0x105: 'i',
    0x106: 'f',
}

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
        return self.name


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


class CPU:
    def __init__(self, binary):
        import angr
        self.proj = angr.Project(binary, auto_load_libs=False)
        self.cfg = self.proj.analyses.CFGFast()
        self._reg_read_func = None
        self.functions = self._init_functions()
        self.registers = self._init_registers()
        self.syscalls = self._init_syscalls()
        self.decomp('interpret_cmp')
        self.flag_values = self._get_flag_values()
        self.memory = self._init_memory()

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

        text = self._transform_ins(text)
        text = self._transform_flag(text)
        text = self._transform_if(text)
        text = text.replace("{", "")\
                   .replace("}", "")\
                   .replace("!", "not ")\
                   .replace(";", "")\
                   .replace("else", "else:")
        return text

    def _transform_ins(self, text):
        pattern = r'interpret_(\w+)\(.*, (\d+), (\d+)\)\;'
        replacement = r'cpu.\1(\2, \3)'
        return re.sub(pattern, replacement, text)

    def _transform_flag(self, text):
        pattern = r'if \((!?)\(a0->field_(\d+) & (\d+)\)\)'
        replacement = r'if \1cpu.registers["f"].val & \3'
        return re.sub(pattern, replacement, text)

    def _transform_if(self, text):
        pattern = r'if (.*)'
        replacement = r'if \1:'
        return re.sub(pattern, replacement, text)

    def imm(self, r, val):
        reg = self.registers[r]
        print(f"[*] IMM {reg} = {hex(val)}")
        reg.val = val

    def add(self, r1, r2):
        reg1 = self.registers[r1]
        reg2 = self.registers[r2]
        print(f"[*] ADD {reg1} {reg2}")
        reg1.val = (reg1.val + reg2.val) % 256

    def stk(self, r1, r2):
        if r2 != 0:
            push_reg = self.registers[r2]
            print(f"[*] PUSH {push_reg}")
            self.registers['s'].val += 1
            self.memory[self.registers['s']] = push_reg.val
        if r1 != 0:
            pop_reg = self.registers[r1]
            print(f"[*] POP {pop_reg}")
            self.registers['s'].val -= 1
            self.memory[self.registers['s']] = pop_reg.val

        return None #TODO: Should this return a value?

    def stm(self, rloc, rval):
        reg_loc = self.registers[rloc]
        reg_val = self.registers[rval]
        print(f"[*] STM *{reg_loc} = {reg_val}")
        self.memory[reg_loc.val] = reg_val.val
        #print(f"Mem[{reg_loc.val}] = {self.memory[reg_loc.val]}")

    def ldm(self, rdst, rsrc):
        reg_dst = self.registers[rdst]
        reg_src = self.registers[rsrc]
        print(f"[*] LDM {reg_dst} = *{reg_src}")
        reg_dst.val = self.memory[reg_src.val]

    def cmp(self, r1, r2):
        flags = self.registers['f']
        flags.val = 0

        reg1 = self.registers[r1]
        reg2 = self.registers[r2]

        print(f"[*] CMP {reg1} {reg2}")

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

    def jmp(self, x, y):
        raise NotImplementedError()

    def sys(self, num, r):
        reg = self.registers[r]
        syscall = [x for x in self.syscalls if self.syscalls[x] == num][0]
        print(f"[*] SYS {syscall} {reg}")

        if syscall == 'open':
            try:
                reg.val = self._sys_open(reg)
            except OSError as ex:
                print(f"[-] ERROR: {ex}")
                reg.val = 0xff

        elif syscall == 'read':
            try:
                reg.val = self._sys_read(reg)
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

        print(f"... return value (in register {reg.name}): {hex(reg.val)}")

    def _sys_open(self, reg):
        memloc = self.registers['a'].val
        flags = self.registers['b'].val
        filename = []
        while self.memory[memloc] != 0:
            filename.append(self.memory[memloc].to_bytes(1, 'little'))
            memloc += 1
        filename = b''.join(filename)
        return os.open(filename, flags)

    def _sys_read(self, reg):
        fd = self.registers['a'].val
        fd = os.dup2(fd, fd+10)
        size = self.registers['c'].val
        memloc = self.registers['b'].val
        with os.fdopen(fd, 'r') as f:
            val = list(f.buffer.readline().strip())[:size]
            for i in range(len(val)):
                self.memory[memloc+i] = val[i]

        return len(val)

    def _sys_write(self, reg):
        result = '\\x' + '\\x'.join([f"{x:x}" for x in self.memory[0x66:0x66+6]])
        print(result)
        entry = '\\x' + '\\x'.join([f"{x:x}" for x in self.memory[0x46:0x46+6]])
        print(entry)
        fd = self.registers['a'].val
        fd = os.dup2(fd, fd+10)
        size = self.registers['c'].val
        memloc = self.registers['b'].val
        with os.fdopen(fd, 'w') as f:
            res = self.memory[memloc:memloc+size]
            x = b''.join([c.to_bytes(1, 'little') for c in res])
            return f.buffer.write(x)

    def _init_registers(self):
        reg_read_func = self._get_reg_read_func()
        reg_vals = self._get_reg_vals(reg_read_func)
        registers = Registers([Register(x, reg_vals[x]) for x in reg_vals])
        return registers

    def _init_syscalls(self):
        sys_func = self._get_sys_func()
        sys_vals = self._get_sys_vals(sys_func)
        return sys_vals

    def _init_memory(self):
        return [0]*256

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
            'execute_program',
        ]
        exec_prog = self._get_exec_func()
        all_funcs = list(self.cfg.functions.values())
        idx = all_funcs.index(exec_prog)
        funcs = all_funcs[idx-8:idx+1]
        for n, f in zip(names, funcs):
            output[n] = Function(n, f)

        return output

    def _get_flag_values(self):
        if self.functions is None:
            raise Exception("Functions property is not set")

        output = {}
        ops = ['lt','gt','eq','ne','z']
        vals = []

        cmp_func = self.functions['interpret_cmp'].func
        for block in cmp_func.blocks:
            insns = block.capstone.insns
            for insn in (i for i in insns if i.mnemonic == 'or'):
                src = insn.op_str.split(', ')[1]
                vals.append(int(src, 16))

        for o, v in zip(ops, vals):
            output[o] = v

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
        funcs = ['open', 'read', 'write', 'sleep', 'exit']
        func_vals = []

        for block in func.blocks:

            for insn in (i for i in block.capstone.insns if i.mnemonic == 'and'):
                src = insn.op_str.split(', ')[1]
                func_vals.append(int(src, 16))

        for f, v in zip(funcs, func_vals):
            output[f] = v

        return output

    def _get_exec_func(self):
        if hasattr(self, 'functions'):
            return self.functions['execute_program'].func

        start = self.cfg.kb.functions[self.proj.entry]
        call_insn = list(start.blocks)[0].capstone.insns[-1]
        offset_insn = list(start.blocks)[0].capstone.insns[-2]
        offset = int(offset_insn.op_str.split('+ ')[1].replace(']', ''), 16)
        target_addr = call_insn.address + offset
        main = self.cfg.kb.functions[target_addr]

        for block in main.blocks:
            for insn in (f for f in block.capstone.insns if f.mnemonic == 'call'):
                call_addr = int(insn.op_str, 16)
                section = self.proj.loader.find_section_containing(call_addr)
                if section is not None and section.name == '.text':
                    self._exec_func = self.cfg.kb.functions[call_addr]
                    return self._exec_func

        raise Exception("execute_program function not found")


class Debugger:
    def __init__(self, cpu):
        self.cpu = cpu
