---
layout: post
title: Viettel Mates CTF 2018 - ddu du ddu du ddu du ddu du ddu du ddu du ddu du ddu du ddu du d Writeup
tags: 
- ctf
- writeups
- Viettel Mates
---

What a long challenge name. This one is a simple oracle attack. Let's dive right in.

---

The challenge gives us one simple lines to netcat to:

```sh
nc ec2-13-251-81-16.ap-southeast-1.compute.amazonaws.com 3333
```

Connecting to this server gives us the following:

```sh
$ nc ec2-13-251-81-16.ap-southeast-1.compute.amazonaws.com 3333
Please select one of flowing options:
1 - You send me any message then I will give you corresponding cipher text
2 - I show you the challenge flag and you have 3 times to guess the plain text
Your choice:
```

Choosing option 1 gives you an oracle which will encrypt things you give it and give you the base64 encoded ciphertext:

```sh
$ nc ec2-13-251-81-16.ap-southeast-1.compute.amazonaws.com 3333
Please select one of flowing options:
1 - You send me any message then I will give you corresponding cipher text
2 - I show you the challenge flag and you have 3 times to guess the plain text
Your choice: 1
Your message: 1
The cipher text: SkVEQg==
Your message: 11
The cipher text: SkVEQktGQUE=
Your message: 111
The cipher text: SkVEQktGQUFKRURC
Your message: 1111
The cipher text: SkVEQktGQUFKRURCS0ZBQQ==
Your message:
```

Luckily, this connection seemingly stays open indefinitely (or at least longer than 10 minutes). Decoding some of the base64 gives us sequences of capital characters:

```python
$ python -c "import base64; print base64.b64decode('SkVEQg==')"
JEDB
$ python -c "import base64; print base64.b64decode('SkVEQktGQUE=')"
JEDBKFAA
```

By experimenting around, it seems that each character maps to 4 capital ascii letters (after base64 decode). I also found that the four capital characters corresponding to a particular input character in the plaintext will be different depending on where that character is in the input string. As in the above examples, a plaintext of `1` maps to a ciphertext of `JEDB` but a plaintext of `11` maps to a ciphertext of `JEDBKFAA`. Thus, we can only assume that the crypto algorithm being used is using previous portions of the plaintext to determine subsequent ciphertext output.  

When I choose option 2, I'm given a "challenge message" and told to guess what the plaintext is. Each time I open a new connection, I'm given a different challenge message. Some challenge messages are longer than others, but not significantly so. It's also important to note that every challenge message received is some length that is divisible by 4, which further backs up my previous assumption that each character of the plaintext maps to four capital letters in the ciphertext. Similar to when I chose option 1, it also seems like this connection just stays open. This makes it incredibly easy to open two connections at once -- one for getting the challenge message and another for brute forcing using the oracle. 

```sh
$ nc ec2-13-251-81-16.ap-southeast-1.compute.amazonaws.com 3333
Please select one of flowing options:
1 - You send me any message then I will give you corresponding cipher text
2 - I show you the challenge flag and you have 3 times to guess the plain text
Your choice: 2
Nice! Your challenge message: MKGPIACFNAHFJPDKOKEPLDBGMEGBPDFGLEBBNGHDLCBHPKFPIDCGLFBAODEGJHDCPBFEICCHMOGLKGADOJEMICCHOJEMKPAKOFEAIDCGNEHBKHACNCHHKLAOJPDKMNGIJJDMOPEKIOCLNPHKKFAAMDGGIBCEPCFHIDCG
Your guess:
```

So here's the basic idea:

1. Open a remote connection to the server to get the challenge message.
2. Open another remote connection to the server to use the oracle.
3. Slowly brute force the oracle for each character of the plaintext of the challenge message.

And here's my script which solves it:

**dusol.py**
---
```python
# Wellington Lee
# viettel mates CTF

from pwn import *
from base64 import b64decode
import string
import sys
import progressbar

HOST = 'ec2-13-251-81-16.ap-southeast-1.compute.amazonaws.com'
PORT = 3333

# A dictionary of all the first character mappings
# This is not really significant -- just marginally sped up cracking
d = {'OAEF': 'E', 'NDHG': 'v', 'KMAJ': '\t', 'NEHB': 'q', 'PEFB': 'Q', 'IKCP': '/', 'JNDI': '8', 'IICN': '-', 'KFAA': '\x00', 'NAHF': 'u', 'IGCD': '#', 'KKAP': '\x0f', 'OOEL': 'K', 'MEGB': 'a', 'LFBA': '\x10', 'JODL': ';', 'PBFE': 'T', 'MGGD': 'c', 'KCAH': '\x07', 'NOHL': '{', 'ONEI': 'H', 'IMCJ': ')', 'IECB': '!', 'NNHI': 'x', 'JHDC': '2', 'PNFI': 'X', 'OJEM': 'L', 'OLEO': 'N', 'JDDG': '6', 'IACF': '%', 'LJBM': '\x1c', 'LCBH': '\x17', 'JGDD': '3', 'PDFG': 'V', 'JCDH': '7', 'KHAC': '\x02', 'LHBC': '\x12', 'MJGM': 'l', 'PHFC': 'R', 'ICCH': "'", 'MLGO': 'n', 'PLFO': '^', 'MFGA': '`', 'JLDO': '>', 'OHEC': 'B', 'LGBD': '\x13', 'NKHP': '\x7f', 'LABF': '\x15', 'JJDM': '<', 'KGAD': '\x03', 'MCGH': 'g', 'NHHC': 'r', 'POFL': '[', 'NCHH': 'w', 'JEDB': '1', 'ILCO': '.', 'MAGF': 'e', 'JKDP': '?', 'MBGE': 'd', 'NLHO': '~', 'NBHE': 't', 'PFFA': 'P', 'PJFM': '\\', 'MOGL': 'k', 'KOAL': '\x0b', 'IFCA': ' ', 'NPHK': 'z', 'LPBK': '\x1a', 'LOBL': '\x1b', 'JPDK': ':', 'JADF': '5', 'NGHD': 's', 'KBAE': '\x04', 'IBCE': '$', 'OPEK': 'J', 'MKGP': 'o', 'OMEJ': 'I', 'OIEN': 'M', 'NIHN': '}', 'MIGN': 'm', 'NJHM': '|', '\xb5\xecm': '\n', 'JMDJ': '9', 'LEBB': '\x11', 'PAFF': 'U', 'IOCL': '+', 'MDGG': 'f', 'LKBP': '\x1f', 'LBBE': '\x14', 'MMGJ': 'i', 'JFDA': '0', 'MPGK': 'j', 'OCEH': 'G', 'PPFK': 'Z', 'JBDE': '4', 'IPCK': '*', 'ODEG': 'F', 'OKEP': 'O', 'LMBJ': '\x19', 'OFEA': '@', 'PIFN': ']', 'MHGC': 'b', 'KLAO': '\x0e', 'OBEE': 'D', 'PMFJ': 'Y', 'OGED': 'C', 'IHCC': '"', 'KAAF': '\x05', 'PKFP': '_', 'JIDN': '=', 'INCI': '(', '\xe1\x80\xb6I\xe1\x81\x80N': '\x80', 'KEAB': '\x01', 'NFHA': 'p', 'KDAG': '\x06', 'IJCM': ',', 'PCFH': 'W', 'LLBO': '\x1e', 'LNBI': '\x18', 'KJAM': '\x0c', 'MNGI': 'h', 'LIBN': '\x1d', 'PGFD': 'S', 'LDBG': '\x16', 'OEEB': 'A', 'KNAI': '\x08', 'IDCG': '&', 'NMHJ': 'y'}

# Iterates through string.printable to find next 
# character in sequence to match the challenge message
def findTarget(r2, target, so_far):

  for c in string.printable:
    r2.recvuntil('message: ')
    try_str = so_far + c 
    r2.sendline(try_str)
    s = r2.recvline()
    key = b64decode(s.strip().split(' ')[-1])
    if key == target:
      return c
    else:
      pass
  return None

# Cracks a given challenge message via oracle
def crackChallenge(challenge):
  global d 

  r2 = remote(HOST, PORT)
  r2.recvuntil('choice: ')
  r2.sendline('1')

  res_str = ''
  res_str += d[challenge[0:4]]

  with progressbar.ProgressBar(max_value=len(challenge), redirect_stdout=True, redirect_stderr=True) as bar:
    for i in range(4, len(challenge), 4):
      target = challenge[0:i+4]

      ret = findTarget(r2, target, res_str)

      if ret is not None:
        res_str += ret 
      else:
        r2.close()
        sys.exit(1)
      bar.update(i)
  r2.close()
  return res_str

# Get our challenge message
r = remote(HOST, PORT)
r.recvuntil('choice: ')
r.sendline('2')
challenge = r.recvline().strip()
challenge = challenge.split(' ')[-1]
print '[+] Challenge: %s' % (challenge)
r.recvuntil('guess: ')

# Use the oracle to brute force for the plaintext
print '[+] Cracking challenge...'
res = crackChallenge(challenge)

# Send the challenge solution
print '[+] Challenge solution: %s' % (res)
r.sendline(res)
print r.recvline()

```

After running the above script, I'm given:

```sh
[+] Challenge solution: 9t0cfkn6q4DrFo20R2UOjV9iDuCDWcnUin8bWyxp5lFuxTzS5BS
Awesome! Here is the final flag: Good fun with bad crypto
```

Thus, the flag for the challenge was `matesctf{Good fun with bad crypto}`.