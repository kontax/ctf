from yan85_interpreter import CPU

def _generate_bytecode(filename, binary):
    with open(filename, 'r') as f:
        y85 = f.read()

    cpu = CPU(binary)
    bytecode = cpu.to_bytecode(y85)
    return bytecode


if __name__ == '__main__':
    binary = 'binaries/babyrev_level21.0'
    filename = 'code/push_test.y85'
    bc = ''.join([f"\\x{b:x}" for b in _generate_bytecode(filename, binary)])
    print(f'echo -e "{bc}" | {binary}')
