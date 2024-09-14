import sys
from yan85 import CPU


if __name__ == '__main__':
    binary = sys.argv[1]
    cpu = CPU(binary)
    print(cpu.decomp('execute_program'))
