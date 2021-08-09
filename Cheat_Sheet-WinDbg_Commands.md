# Cheat Sheet - WinDbg Commands

## Table of Content
* [1.0 - General.](#General)
* [2.0 - Reading from Memory.](#Reading)
* [3.0 - Dumping Structure from Memory.](#Dumping)
* [4.0 - Writing to Memory.](#Writing)
* [5.0 - Search.](#Search)
* [6.0 - Registers.](#Registers)
* [7.0 - Breakpoints.](#Breakpoints)
  * [7.1 - Software Breakpoints.](#Software-bp)
  * [7.2 - Hardware Breakpoints.](#Hardware-bp)
* [8.0 - Stepping Through the Code.](#STC)
* [9.0 - Do Maths!](#Maths)
* [10. - Pseudo Registers.](#PseudoRegisters)

### 1. General.<a name="general"></a>

Continue Flow Execution :
```bash
0:005> g
```

Reload modules and symbols :
```
0:005> .reload /f
```

Display the assembly translation of a specified program code in memory :
```bash
0:005> u kernel32!GetCurrentThread
```

Listing all modules starting with "kernel" :
```bash
0:007> lm m kernel*
```

Dump information regarding symbols present from the KERNELBASE module :
```bash
0:002> x kernelbase!CreateProc*
```

Converting between different formats at once :
```bash
0:000> .formats 41414141
Evaluate expression:
Hex:
41414141
Decimal: 1094795585
Octal:
10120240501
Binary: 01000001 01000001 01000001 01000001
Chars:
AAAA
Time:
Fri Sep 10 07:53:05 2004
Float:
low 12.0784 high 0
Double: 5.40901e-315
```

Display information about specifiy memory address :
```bash
0:005> !address 01243c2e  
```

### 2. Reading from Memory.<a name="Reading"></a>

We can read process memory content using the display command followed by the size indicator.


Display bytes :
```bash
0:000> db esp                  # Default
0:000> db 00faf974             # With explicit addresses
0:000> db kernel32!WriteFile   # With symbol names
```

Display data in a larger size format :
```bash
0:000> dw esp                  # Prints WORDs (two bytes) rather than single bytes
```

Display DWORDs (four bytes) :
```bash
0:000> dd esp
```

Display QWORDs (eight bytes) :
```bash
0:000> dq 00faf974             # ESP Register is replaced by hexadecimal value
```

Display ASCII characters in memory along with WORDs :
```bash
0:000> dw KERNELBASE+0x40
```

Display ASCII characters in memory along with DWORDs :
```bash
0:000> dc KERNELBASE
```

Display data through the pointer to data command poi, which displays data referenced from a memory address :
```bash
0:000> dd poi(esp)
```

Change the length displayed :
```bash
0:000> dd esp L4

0:000> dd esp L10

0:000> dw KERNELBASE L2

0:000> db KERNELBASE L2
```

### 3. Dumping Structure from Memory.<a name="Dumping"></a>

Dumping structure :
```bash
0:000> dt ntdll!_TEB
	+0x000 NtTib		: _NT_TIB
```

Display recursively nested structures where present :
```bash
:002> dt -r ntdll!_TEB @$teb
```

Sisplay specific fields in the structure :
```bash
0:000> dt ntdll!_TEB @$teb ThreadLocalStoragePointer
	+0x02c ThreadLocalStoragePointer : 0x02b31bf8 Void
```

Display the size of a structure extracted from a symbol file :
```bash
0:000> ?? sizeof(ntdll!_TEB)
unsigned int 0x1000
```


### 4. Writing to Memory.<a name="Writing"></a>

Main command for modifying process memory data (edit) : 
```bash
e\*
```

Edit a DWORD pointed to by ESP :
```bash
0:000> dd esp L1
003cb710 00000000

0:000> ed esp 41414141

0:000> dd esp L1
003cb710 41414141
```

Write or modify ASCII  or Unicode characters.

```
0:000> da esp
003cb710 ""

0:000> ea esp "Hello"

0:000> da esp
003cb710 "Hello"
```

### 5. Search.<a name="Search"></a>

Search the debugged process memory space as DWORDs starting at address "0",  search for the whole memory range :
```bash
0:000> s -a 0 L?80000000 "This program cannot be run in DOS mode"
```

Search ASCII :
```bash
0:006> s -a 0x0 L?80000000 w00tw00t
```

Search Unicode :
```
0:006> s -u 0x0 L?80000000 w00tw00t
00843918  0077 0030 0030 0074 0077 0030 0030 0074  w.0.0.t.w.0.0.t.
```

### 6. Registers.<a name="Registers"></a>

Dump all registers :
```bash
0:006> r
eax=00b43000 ebx=00000000 ecx=77d59bc0 edx=01008802 esi=77d59bc0 edi=77d59bc0
eip=77d21430 esp=03f1fc5c ebp=03f1fc88 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
ntdll!DbgBreakPoint:
77d21430 41              inc     ecx
```

Looking for EIP register value :
```bash
0:006> r eip
eip=77d21430
```

Editing EIP register value :
```bash
0:006> r eip=41414141

0:006> r eip
eip=41414141
```

### 7. Breakpoints.<a name="Breakpoints"></a>

#### 7.1 Software Breakpoints.<a name="Software-bp"></a>

Set a breakpoint at the WriteFile API :
```bash
0:005> bp kernel32!WriteFile
```

List breakpoints :
```bash
0:000> bl
0 e Disable Clear 767ec6d0    0001 (0001) 0:**** KERNEL32!WriteFile
```

The command bd is used to disable the breakpoint. be is used to enable breakpoint. bc is used to clear breakpoint.

Disable breakpoint :
```
0:000> bl
     0 e Disable Clear  76b2c6d0     0001 (0001)  0:**** KERNEL32!WriteFile
0:000> bd 0
0:000> bl
     0 d Enable Clear  76b2c6d0     0001 (0001)  0:**** KERNEL32!WriteFile
0:000> bd 0
```

Enable breakpoint :
```bash
0:000> bl
     0 d Enable Clear  76b2c6d0     0001 (0001)  0:**** KERNEL32!WriteFile
0:000> be 0
0:000> bl
     0 e Disable Clear  76b2c6d0     0001 (0001)  0:**** KERNEL32!WriteFile
```

Delete a specific breakpoint :
```bash
0:000> bl
     0 e Disable Clear  76b2c6d0     0001 (0001)  0:**** KERNEL32!WriteFile
0:000> bc 0
0:000> bl
```

Delete all breakpoints :
```bash
0:000> bp kernel32!WriteFile
0:000> bp kernel32!UnlockFile
0:000> bl
     0 e Disable Clear  76b2c6d0     0001 (0001)  0:**** KERNEL32!WriteFile
     1 e Disable Clear  76b2c6b0     0001 (0001)  0:**** KERNEL32!UnlockFile
0:000> bc *
0:000> bl
```


Set a breakpoint on unresolved function WriteStringStream of ole32 :
```
0:006> lm m ole32
Browse full module list
start    end        module name

0:006> bu ole32!WriteStringStream

0:006> bl
     0 e Disable Clear u             0001 (0001) (ole32!WriteStringStream)
```

#### 7.2 Hardware Breakpoints.<a name="Hardware-bp"></a>

The "ba" command need three arguments :
- The type of access, e(execute), w(write), r(read).
- The size in bytes for the specified memory access
- The memory address where we want to set the breakpoint.

Set a hardware breakpoint :
```bash
0:006> ba e 1 kernel32!WriteFile
0:006> bl
     0 e Disable Clear  76b2c6d0 e 1 0001 (0001)  0:**** KERNEL32!WriteFile
```

### 8. Stepping Through the Code<a name="STC"></a>

The p command execute one single instruction at a time and steps over function calls. :
```bash
0:005> p
```

The t command will do the same, but will also step into function calls :
```bash
0:005> t
```

The command pt (step to next return), allows us to fast-forward to the end of a function :
```bash
0:005> pt
```

Like the pt command, ph executes code until a branching instruction is reached. This includes conditional or unconditional branches, function calls, and return instructions :
```bash
0:005> ph
```

### 9. Do Maths!<a name="Mathsl"></a>

Calculations :
```bash
0:007> ? 77269bc0 - 77231430
Evaluate expression: 231312 = 00038790

0:007> ? 77269bc0 >> 18
Evaluate expression: 119 = 00000077
```

Convert 41414141 to decimal :
```bash
0:000> ? 41414141
Evaluate expression: 1094795585 = 41414141
```

Convert decimal to hexadecimal :
```bash
0:000> ? 0n41414141
Evaluate expression: 41414141 = 0277edfd
```

Convert the binary to decimal and hexadecimal :
```bash
0:000> ? 0y1110100110111
Evaluate expression: 7479 = 00001d37
```

### 10. Pseudo Registers.<a name="Pseudo Registers"></a>

There are 20 user-defined pseudo registers named $t0 to $t19 that can be used as variables during mathematical calculations.

Basic Calcul :
```bash
0:000> ? ((41414141 - 414141) * 0n10) >> 8
Evaluate expression: 42598400 = 028a0000
```

Same calcul using pseudo registers  :
```bash
# Use the $t0 pseudo register and store the value of the first calculation. 
0:000> r @$t0 = (41414141 - 414141) * 0n10

# Read the $t0 register and WinDbg outputs the result to verify the value.
0:000> r @$t0
$t0=8a000000*

# Right-shift $t0 by 8 bits to get the final result.
0:000> ? @$t0 >> 8
Evaluate expression: 42598400 = 028a0000
```
