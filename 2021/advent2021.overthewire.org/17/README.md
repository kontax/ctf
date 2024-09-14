# Day 17: Grinch's Game

We identified a game service being run by the Grinch. Can you beat it?

## Overview

This challenge is a guessing game where you have to guess a number between 1 
and 100, however must do it 100 times to get the flag. The caveat is that you 
only have 20 "lives" in order to do so.

## Required Software

* Python

## Solving the challenge

The source code for this challenge is given to us at 
[grinchgame.py](grinchgame.py), and we can see that the numbers are generated 
using the Python library random, using `secrets.randbits(20)` as a seed. If we 
can find the exact seed for the random number generator, then we can figure 
out all the following numbers in the sequence and solve the challenge.

`secrets.randint(20)` returns a 20bit integer, meaning the maximum number of 
possible sequences is capped at 1,048,576. To solve this challenge, we can 
loop through all these seeds and get the sequence associated with that seed.
This has been stored in a database for ease of use, preventing having to 
generate each sequence every time the script is run.

Once the sequences have been generated, it's a simple matter of guessing the 
first number using binary search, and then filtering the sequences to only 
those seeds that contain that first number as the first number in the sequence.
We do the same thing for the second number and continue to filter down the 
seeds until only one possible solution is left. Once that seed has been found,
we loop through the remaining numbers in the sequence and the flag is output:

> AOTW{wh3n_th3_0nly_w1nn1n6_m0ve_15_n0t_2_p14y}
