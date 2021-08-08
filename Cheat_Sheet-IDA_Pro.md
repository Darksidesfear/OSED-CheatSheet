# Cheat Sheet - IDA Pro

## Table of Content

* 1.0 [User Interface.](#UserInterface)
* 2.0 [Basic Functionality.](#BasicFunc)
* 3.0 [Search Functionality.](#Search)
* 4.0 [Sync WinDbg and IDA Pro.](#Sync)

### 1. User Interface.<a name="UserInterface"></a>

Switch between graph view and text view : 
```bash
[space]
```

In the text view, virtual addresses are displayed for each instruction. We can add this for the graph view :
```bash
Options > General > Line prefixes box (enable)
```

Proximity view is for viewing and browsing the relationships between functions, global variables, and constants :
```bash
View > Open subviews > Proximity browser
```

Reset the IDA Pro layout to its default setting.

To adjust a single window, let’s place the cursor just below the title of the window. When a small bar appears, we can drag and dock the window next to other windows.

Completely reset the UI :
```bash
Windows > Reset desktop.
```

### 2. Basic Functionality.<a name="BasicFunc"></a>

Set a comment through the dialog box :
- Place the cursor at a specific line of code and pressing the colon (:) key.

Function name :
- A default function name of “sub_XXXXXX” and a global variable name of “dword_XXXXXX” is used if no names included in any symbols files loaded are found.

Rename :
- We can rename a function by locating it in the Functions window, right-clicking it, and selecting Edit function.... From here, we can modify the function name.

Bookmarks :
- We can create a bookmark by choosing the line we want to bookmark and pressing Alt + M.
- This brings up the dialog box for naming and creating our new bookmark.
- If we need to come back to the same location in the code, press Alt + M will open the dialog box, double click on the bookmark name will jump to it.

### 3. Search Functionality.<a name="Search"></a>

Search for a string :
- We can search for a string using the text option in the Search menu.
- We can likewise search for an immediate value, such as a hardcoded DWORD or a specific sequence of bytes, from the Search menu or by using "ALT + I" and "ALT + B", respectively.

Search for function :
- We can search for function names in the Functions window or through the "Jump to function" command from the "Jump" menu. In the dialog window, we’ll right-click and use "Quick filter" to search for functions by name.
- In the same manner, we can search for global variables through the "Jump by name..."" submenu.

DLL Imported function :
- All the imported and exported functions are available from the Imports and Exports tabs respectively.

Cross Referencing : 
- We can use cross referencing (xref) to detect all usages of a specific function or global variable in the entire executable or DLL.
- To obtain the list of cross references for a function name or global variable, we’ll select its name from the graph view with the mouse cursor and press the "X" key. 

### 4. Sync WinDbg and IDA Pro.<a name="sync"></a>

To easily jump back and forth between the debugger and IDA Pro, we need to make sure that the base address of the target executable in IDA Pro coincides with that of the debugged process in WinDbg.

To do this, dump the base address of your attached application :
```
0:006> lm m notepad
Browse full module list
start		end			module name
00f20000 	00f5f000	notepad		(pdb symbols) ...
```

Now we switch back to IDA Pro and navigate to :
```bash
Edit > Segments > Rebase program...
```

Then put as value the base address of the applicaiton, in our exemple it's "0x00f20000".

Once IDA Pro complete the recalculation process. All addresses, references, and global variables will match those found in WinDbg during the debugging session.

By rebasing the executable in IDA Pro to the base address found in the debugger (0x00f20000), we can synchronize the static and dynamic analysis, which allows us to use absolute addresses.