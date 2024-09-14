import math
import re
import sqlite3

from pwn import *
from time import sleep

HOST = "grinchgame.advent2021.overthewire.org"
PORT = 1217
DATABASE = "paths.db"
BG_GREEN = '\033[92m'
BG_END = '\033[0m'


def create_and_populate_database():
    create_database()
    populate_table()


def create_database():
    con = sqlite3.connect(DATABASE)
    cur = con.cursor()

    column_structure = []

    table = cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='possible_paths'")
    num_tables = len(list(table))
    if num_tables > 0:
        print("Table has already been created")
        return
    else:
        print("No table found, creating")

    for i in range(101):
        column_structure.append(f'"{i}" int')

    cur.execute("DROP TABLE IF EXISTS possible_paths;")
    cur.execute(f"CREATE TABLE possible_paths (seed int, {', '.join(column_structure)})")
    con.commit()
    con.close()



def populate_table():

    con = sqlite3.connect(DATABASE)
    cur = con.cursor()

    rowcount = cur.execute("SELECT COUNT(*) FROM possible_paths").fetchone()[0]
    if rowcount == int(math.pow(2,20)):
        print("All possible paths saved to database already")
        return
    else:
        print("Table is not yet populated with all possible values")


    possible_seeds = int(math.pow(2, 20))
    for i in range(possible_seeds):
        r = random.Random(i)
        if i % 1000 == 0:
            con.commit()
            print(f"{i}/{possible_seeds}", end='\r')

        values = [str(i)]
        for _ in range(101):
            guess = r.randrange(100)
            values.append(str(guess))

        cur.execute(f"INSERT INTO possible_paths VALUES ({','.join(values)});")

    con.commit()
    con.close()
    print('\n')


def get_closest_value(value, possible_values):
    absolute_difference_function = lambda list_value : abs(list_value - value)
    closest_value = min(possible_values, key=absolute_difference_function)
    return closest_value


def binary_search(conn, possible_values, ran_already=False):
    low = 0
    high = 100
    mid = 0

    while low <= high:
        # for get integer result 
        if not ran_already:
            resp = conn.recvuntil(b"Guess my number:\n")

        if len(possible_values) > 0:
            mid = get_closest_value((high + low) // 2, possible_values)
        else:
            mid = (high + low) // 2

        print(f"Sending {mid}", end='\r')
        conn.sendline(bytes(f'{mid}', 'utf-8'))
        resp = conn.recvline()

        # Check if n is present at mid 
        if b'Too low' in resp:
            print("Too low", end='\r')
            low = mid + 1

        elif b'Too high' in resp:
            print("Too high", end='\r')
            high = mid - 1

        elif b'Correct' in resp:
            resp = conn.recvuntil(b"Guess my number:\n")
            guess_round = int(re.findall("round (\d*)/\d*", resp.decode('utf-8'))[0])
            print(f"Correct! Now on round {guess_round}")
            return mid

        # If n is smaller, compared to the left of mid
        else:

            raise ValueError(f"Weird response {resp}")

        ran_already = False
            # element was not present in the list, return -1
    return None


def get_possible_value_count(values, guess_round):
    where_items = []
    for col, val in zip(range(guess_round), values):
        where_items.append(f'"{col}" = {val}')


    where_clause = ' AND'.join(where_items)
    count_query = f'SELECT COUNT(*) FROM possible_paths WHERE {where_clause}'

    con = sqlite3.connect(DATABASE)
    cur = con.cursor()
    rowcount = cur.execute(count_query).fetchone()[0]
    return rowcount


def get_all_possible_values(values, guess_round):
    where_items = []
    for col, val in zip(range(guess_round), values):
        where_items.append(f'"{col}" = {val}')


    where_clause = ' AND '.join(where_items)
    query = f'SELECT * FROM possible_paths WHERE {where_clause}'

    con = sqlite3.connect(DATABASE)
    cur = con.cursor()
    result = cur.execute(query).fetchone()
    return result


def get_possible_values(values, guess_round):
    where_items = []
    for col, val in zip(range(guess_round), values):
        where_items.append(f'"{col}" = {val}')


    where_clause = ' AND '.join(where_items)
    query = f'SELECT DISTINCT "{guess_round}" FROM possible_paths WHERE {where_clause}'

    con = sqlite3.connect(DATABASE)
    cur = con.cursor()
    result = cur.execute(query).fetchall()
    output = []
    for row in result:
        output.append(row[0])

    output.sort()
    return output


def get_flag_response(conn, possible_values):
    curr_round = guess_round
    for v in possible_values[guess_round:]:
        print(f"Using value {v} for round {curr_round}", end='\r')
        conn.sendline(str(v).encode('utf-8'))
        resp = conn.recv()
        if b'AOTW' in resp:
            return resp
        else:
            sleep(0.1)
            curr_round += 1

    raise ValueError("Cannot find flag in response")


if __name__ == '__main__':

    # Create a table with all possible seed values
    create_and_populate_database()

    conn = remote(HOST, PORT)

    guess_round = 1
    values = []
    possible_values = []
    ran_already = False
    while True:
        value = binary_search(conn, possible_values, ran_already)
        print(f"Round {guess_round}: Answer = {value}")
        values.append(value)

        rowcount = get_possible_value_count(values, guess_round)
        print(f"Number of possible options: {rowcount}/{int(math.pow(2,20))} options")

        if rowcount == 1:
            print("Only one possible value left")
            guess_round += 1
            break

        possible_values = get_possible_values(values, guess_round)
        print(f"Number of possible values: {len(possible_values)}")

        guess_round += 1
        ran_already = True

    possible_values = get_all_possible_values(values, guess_round)
    resp = get_flag_response(conn, possible_values)

    flag = re.findall("AOTW(.*)", resp.decode('utf-8'))[0]
    print("\n\nFLAG:")
    print(f"{BG_GREEN}AOTW{flag}{BG_END}")
