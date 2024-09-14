# Day 11: Hack Back

> Oh no! Santa's computer has been infected with malware. He created a memory 
> image for you to analyse, identify the malware and hack the hacker!

## Overview

This is a forensics challenge, where you must analyse a memory dump and 
extract some malware to analyise. Various bits of information about the 
memory dump are necessary to pass to the malware for it to execute correctly.
Once this has been correctly parsed, TODO:

## Required Software

* Python
* [Volatility](https://github.com/volatilityfoundation/volatility3)
* [DotPeek](https://www.jetbrains.com/decompiler/)

## Solving the challenge

### Finding the malware

The memory dump is split into two files - a `vmem` which is a dump of the 
memory snapshot, with the other a `vmsn` containing details of the VMWare 
machine that was being run. By browsing briefly through the `vmsn` file we 
can see it's a Windows 10 Machine, which will help with the memory analysis.

Using Volatility, we can pull information on the memory snapshot with the 
following command:
```bash
python vol.py -f hack_back.vmem windows.info
```
This adds more information about the machine.

In order to start looking for malware, the open network connections seems like
a good place to start. This can be achieved with the following command:
```bash
python vol.py -f hack_back.vmem windows.netscan | grep ESTABLISHED
```
to find all the established connections on the computer at the time. This leads
to two connections from `svchost.exe`:
```
0xca835313ebc0  TCPv4   10.0.25.12      49746   13.51.63.193    443     ESTABLISHED     5412    svchost.exe     2021-12-08 21:40:22.000000 
0xca835318c460  TCPv4   10.0.25.12      49695   20.199.120.85   443     ESTABLISHED     1164    svchost.exe     2021-12-08 21:30:55.000000
```
Looking at the first process, with ID 5412, we can see what command line args 
were used to run this command with the following volatility plugin:
```bash
python vol.py -f hack_back.vmem windows.cmdline --pid 5412
```
Which has the dubious path of `C:\ProgramData\Mircosoft\svchost.exe`. In order
to extract this file from the memory dump, we can use the following command: 
```bash
python vol.py -f hack_back.vmem windows.pslist --pid 5412 --dump
```

### Analysing the malware

Looking into the extracted file a bit, we can see that it's a .NET application
which we can open in dotPeek to see the C# code. It's a relatively simple 
application, with a simple function used to decode the hardcoded strings for 
the URL and filename. Firstly the update function is called to ensure the file
from the server is the latest version, then it connects to the server to get 
a list of commands to run on the server. The server URL is 
`gr1nch3r.advent2021.overthewire.org`.



## Flag

> AOTW{}
