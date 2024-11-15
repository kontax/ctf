
#!/bin/bash
# Copy all asm files to the pwn.college server
# Usage: ./copy.sh

set -uo pipefail
trap 's=$?; echo "$0: Error on line "$LINENO": $BASH_COMMAND"; exit $s' ERR

# Print out usage
if [ "$#" -ne 0 ]; then
        echo "Usage: $0"
        exit
fi

# Copy files
echo "Copying asm files to pwn.college server"
scp -i ~/.ssh/pwn.college *.s hacker@pwn.college:~/3-program-security/1-shellcode-injection/
