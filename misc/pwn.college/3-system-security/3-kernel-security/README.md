## Kernel Security

### Level 1

- Reverse the binary, see a password is required in `device_write` function.
- Write the password to /proc/pwncollege
- Read /proc/pwncollege to get the flag

### Level 2

- Similar to Level1, write the password to /proc/pwncollege
- Flag is now in kernel logs via `dmesg`

### Level 3

- When writing the password to /proc/pwncollege, the module elevates the process to UID 0
- Once done, read `/flag`

### Level 4

- Send an ioctl message with 2 parameters - the CTL arg and password
- Open and read `/flag` from the same process

### Level 5

- Send an ioctl message with the CTL arg and address of the `win` function

### Level 6

### Level 7

### Level 8

- There is a binary in /challenge which opens the kernel module for writing in FD 3
- Create shellcode which contains both user and kernel code, with the user code loading the kernel code into the module via the open file descriptor
- The kernel code should modify current thread's flags via a `current->thread_info.flags &= ~_TIF_SECCOMP;` call within assembly
- Finding the `current_thread`'s offset from the gs register is found by the following command within GDB: `p/x &current_task` (which was found to be gs:0x15d00).
- The kernel code also needs to create a stack frame so avoid a kernel crash.
- User code then is able to perform any syscall, with a `sendfile(open('/flag'))` being an option

### Level 9

- There are enough bytes in the input buffer to write over the return address.
- Overwrite the return address to point to the `run_cmd` command
- The start of the shellcode should be a useful command, eg `/usr/bin/chmod 777 /flag`
- When the `__indirect_thunk_rax` call is run, the parameters are set for the `run_cmd` command

### Level 10

- Write 0x100 bytes to /proc/pwncollege, then leak the return address
- Use the offset from this address to run_cmd to calculate what address to write
- Use the same exploit as the previous level with this new address
- Note: there's probably an "intended" way to do this using the logger variable (seen in ida)

### Level 11

- Physical memory is mapped to a location in kernel memory at page_offset_base (`p/x page_offset_base`)
- The assembly passed to the user challenge file does the following:
  - Copy kernel assembly code to kernel space
  - Search the physical memory data for `pwn.college{`, which should be mapped to 040 (so add 0x1000 a time)
  - When found, leave that location in rsi and call \_copy_to_user(0x404040)
  - Run write(0x404040) which should contain the flag

### Level 12

- Same as level 11
