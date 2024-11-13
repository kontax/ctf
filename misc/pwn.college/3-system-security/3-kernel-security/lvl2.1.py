import subprocess

def get_dmesg():
    process = subprocess.Popen(['dmesg'], stdout=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()
    return stdout

with open('/proc/pwncollege', 'wb') as f:
    f.write(b'mwzzvrrouvgtskoz')


for line in get_dmesg().splitlines():
    print(line)
    if 'pwn' in line:
        print(line)
        exit()
