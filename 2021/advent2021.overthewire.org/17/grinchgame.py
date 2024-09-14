#!/usr/bin/env python3

import asyncio
import random
import secrets
import sys

from REDACTED import FLAG
assert(type(FLAG) is str)

HOST = "0.0.0.0"
PORT = 1217

TIMEOUT = 60*2

async def sendline(writer, line):
	writer.write(line.encode() + b"\n")
	await writer.drain()

async def handle_client(reader, writer):
	await sendline(writer, f"""\
SYSTEM INFO:
CPython {sys.version} on {sys.platform}

Are you feeling lucky? Let's play a game...
""")

	r = random.Random(secrets.randbits(20))  # initialise RNG with secure entropy

	numbers_to_guess = 100
	lives_remaining = 20

	my_number = r.randrange(100)

	while True:
		await sendline(writer, f"[round {101-numbers_to_guess}/100] Guess my number:")

		answer = await reader.readline()
		try:
			answer = int(answer.decode().strip())
		except:
			await sendline(writer, "Invalid input. Bye.")
			return
		
		if answer == my_number:
			await sendline(writer, "Correct!")
			numbers_to_guess -= 1
			my_number = r.randrange(100)
		elif answer < my_number:
			await sendline(writer, "Too low...")
			lives_remaining -= 1
		else:
			await sendline(writer, "Too high...")
			lives_remaining -= 1
		
		if lives_remaining == 0:
			await sendline(writer, "GAME OVER! Better luck next time...")
			return
		
		if numbers_to_guess == 0:
			await sendline(writer, "YOU WIN! How are you so lucky!?!??")
			await sendline(writer, FLAG)
			return

async def handle_client_safely(reader, writer):
	peer = writer.get_extra_info("peername")
	print("[+] New connection from", peer)
	try:
		await asyncio.wait_for(handle_client(reader, writer), TIMEOUT)
		writer.close()
		print("[+] Gracefully closed connection from", peer)
	except ConnectionResetError:
		print("[*] Connection reset by", peer)
	except asyncio.exceptions.TimeoutError:
		print("[*] Connection timed out", peer)
		writer.close()

async def main():
	server = await asyncio.start_server(handle_client_safely, HOST, PORT)
	print("[+] Server started")
	async with server:
		await server.serve_forever()

asyncio.run(main())
