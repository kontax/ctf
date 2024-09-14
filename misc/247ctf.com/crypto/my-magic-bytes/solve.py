from itertools import cycle

MAGIC_BYTES = {
    'a': b'\xFF\xD8\xFF\xDB',
    'b': b'\xFF\xD8\xFF\xE0\x00\x10\x4A\x46\x49\x46\x00\x01',
    'c': b'\xFF\xD8\xFF\xEE',
    'd': b'\xFF\xD8\xFF\xE0',
    'e': b'\x00\x00\x00\x0C\x6A\x50\x20\x20\x0D\x0A\x87\x0A',
    'f': b'\xFF\x4F\xFF\x51',
}

def decrypt(image_bytes, xor_key):
    output = []
    for b, d in zip(image_bytes, cycle(xor_key)):
        print(f"{hex(b)} ^ {hex(d)} = {hex(b ^ d)}")
        output.append(b ^ d)

    # return b''.join(output)
    return bytes(output)

with open('my_magic_bytes.jpg.enc', 'rb') as f:
    enc = f.read()

for k in MAGIC_BYTES.keys():
    key = [e ^ d for e, d in zip(enc, MAGIC_BYTES[k])]


    print(f"Key: {key}")
    dec = decrypt(enc, key)
    with open(f'output/{k}.jpg', 'wb') as f:
        f.write(dec)
