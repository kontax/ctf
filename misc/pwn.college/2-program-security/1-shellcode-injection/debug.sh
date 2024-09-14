
#!/bin/bash
# Debug shellcode locally
# Usage: ./debug.sh <asm_file>

set -uo pipefail
trap 's=$?; echo "$0: Error on line "$LINENO": $BASH_COMMAND"; exit $s' ERR

# Print out usage
if [ "$#" -ne 1 ]; then
        echo "Usage: $0 <asm_file>"
        exit
fi

# Get filename, removing suffix
asm="${1%.*}"

# Assemble the program (can also use `gcc -nostdlib -static -o $asm.o $asm.s`)
echo "Assembling $asm.o into $asm.s"
#as -o $asm.o $asm.s
gcc -Wl,-NX -nostdlib -static -z execstack -o $asm.o $asm.s

objdump -M intel -d $asm.o

# Debug the code with GDB
echo "Debugging the code with GBD"
gdb -ex 'b _start' -ex 'r' $asm.o

# Remove the temp files
rm $asm.o
