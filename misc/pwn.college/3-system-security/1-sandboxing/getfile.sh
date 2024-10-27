#!/bin/bash
# Retrieve the local challenge file from the server
# Usage: ./getfile.sh

set -uo pipefail
trap 's=$?; echo "$0: Error on line "$LINENO": $BASH_COMMAND"; exit $s' ERR

# Print out usage
if [ "$#" -ne 0 ]; then
        echo "Usage: $0"
        exit
fi

echo "Getting the challenge level from the server"
challenge=$(ssh -i ~/.ssh/pwn.college hacker@pwn.college "hostname" | sed 's/.*level\([0-9]*\)/\1/')
echo $challenge

echo "Retrieving the challenge file and saving it locally"
scp -i ~/.ssh/pwn.college hacker@pwn.college:/challenge/babyjail_level${challenge}* ./binaries/
