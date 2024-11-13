with open('/proc/pwncollege', 'wb') as f:
    f.write(b'ysrxhmxtsfctmnuv')

with open('/flag', 'r') as f:
    print(f.read())
