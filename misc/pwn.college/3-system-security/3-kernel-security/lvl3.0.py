with open('/proc/pwncollege', 'wb') as f:
    f.write(b'axocbmfqtmtotiqp')

with open('/flag', 'r') as f:
    print(f.read())
