import requests

BASE_URL = "https://a24369b1cb8ee8be.247ctf.com"
USER = "impossible_flag_user"


def encrypt(user):
    url = f"{BASE_URL}/encrypt"
    params = {
        "user": user.encode("utf-8").hex()
    }
    resp = requests.get(url, params=params)
    return resp.text

def get_flag(user):
    url = f"{BASE_URL}/get_flag"
    params = {
        "user": user
    }
    resp = requests.get(url, params=params)
    return resp.text

def get_first_block():
    i = 1
    prior_f = ""
    while i < len(USER):
        test = USER[:i]
        encrypted = encrypt(test)
        print(f"{encrypted} <= {test}")
        f, _ = encrypted[:len(encrypted)//2], encrypted[len(encrypted)//2:]
        if f != prior_f:
            prior_f = f
        else:
            print(f"Found it @ i = {i-1}")
            print(f)
            return f, i-1
        i += 1

    raise Exception("Not found")

def get_block_size():
    i = 1
    while i < 64:
        encrypted = encrypt('a'*i)
        print(f"Block size = {i}")
        print(encrypted)
        f, e = encrypted[:len(encrypted)//2], encrypted[len(encrypted)//2:]
        print(f)
        print(e)
        if f == e:
            print(f"Found it! Block size = {i}")
            break

        i += 1


if __name__ == '__main__':
    first_block, blocksize = get_first_block()
    second_block = encrypt("x"* blocksize + USER[blocksize:])
    print(f"Second Block: {second_block}")
    second_block = second_block[len(second_block)//2:]
    print("Flag: ")
    print(get_flag(first_block + second_block))
