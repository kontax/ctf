as -o $1.o $1.s && objcopy -O binary --only-section=.text $1.o $1.bin
