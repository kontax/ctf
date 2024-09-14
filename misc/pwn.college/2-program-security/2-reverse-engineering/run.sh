#!/bin/bash
# Remotely run a pwn.college file
# Usage: ./run.sh <asm_file>

set -uo pipefail
trap 's=$?; echo "$0: Error on line "$LINENO": $BASH_COMMAND"; exit $s' ERR

# Print out usage
if [ "$#" -ne 1 ]; then
        echo "Usage: $0 <asm_file>"
        exit
fi

# Get filename, removing suffix
asm="${1%.*}"
level="level${asm##*[!0-9]}"

# Assemble the program (can also use `gcc -nostdlib -static -o $asm.o $asm.s`)
echo "Assembling $asm.o into $asm.s"
#as -o $asm.o $asm.s
gcc -nostdlib -static -o $asm.o $asm.s

objdump -M intel -d $asm.o

# Extract the .text section
echo "Extracting the .text section to $asm.bin"
objcopy -O binary --only-section=.text ./$asm.o ./$asm.bin

# Run the code against the challenge
echo "Running $asm.bin against /challenge/babyshell_$level"
cat $asm.bin | ssh -i ~/.ssh/pwn.college hacker@pwn.college "cat - | /challenge/babyshell_$level"

# Remove the temp files
rm $asm.bin $asm.o
