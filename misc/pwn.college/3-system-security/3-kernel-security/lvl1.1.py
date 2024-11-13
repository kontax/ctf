with open('/proc/pwncollege', 'wb') as f:
    f.write(b'fokjjoxyeehspwvq')

with open('/proc/pwncollege', 'rb') as f:
    print(f.read(54).decode())
