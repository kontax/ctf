#!/bin/bash
set -uo pipefail
trap 's=$?; echo "$0: Error on line "$LINENO": $BASH_COMMAND"; exit $s' ERR

if [ "$#" -ne 1 ]; then
        echo "Usage: $0 <asm_file>"
        exit
fi
asm="${1%.*}"
as -o $asm.o $asm.s
objcopy -O binary --only-section=.text ./$asm.o ./$asm.bin
rm $asm.o
