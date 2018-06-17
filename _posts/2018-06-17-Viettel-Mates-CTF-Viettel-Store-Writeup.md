---
layout: post
title: Viettel Mates CTF 2018 - Viettel Store Writeup
tags: 
- ctf
- writeups
- Viettel Mates
---

This was a fun challenge because I got to use hash extension attack. To learn about hash extension attacks, Ron Bowes has [a great blog post about hash extension attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks) and a corresponding [GitHub repository of the hash_extender tool](https://github.com/iagox86/hash_extender) which I used directly in my solution to this challenge.

---

For Viettel Store, I was given a file **crypto1.py** and `nc 13.251.110.215 10001`.

**crypto1.py**
---

```python
import time
import string
import random
from hashlib import sha256
from urlparse import parse_qsl

money = random.randint(1000000, 5000000)
signkey = ''.join([random.choice(string.letters+string.digits) for _ in xrange(random.randint(8,32))])
items = [
    ('Samsung Galaxy S9', 19990000),
    ('Oppo F5', 5990000),
    ('iPhone X', 27790000),
    ('Vivo Y55s', 3990000),
    ('Itel A32F', 1350000),
    ('FLAG', 999999999)
]

def view_list():
    for i, item in enumerate(items):
        print "%d - %s: %d VND" % (i, item[0], item[1])

def order():
    try:
        n = int(raw_input('Item ID: '))
    except:
        print 'Invalid ID!'
        return
    if n < 0 or n >= len(items):
        print 'Invalid ID!'
        return
    payment = 'product=%s&price=%d&timestamp=%d' % (items[n][0], items[n][1], time.time()*1000000)
    sign = sha256(signkey+payment).hexdigest()
    payment += '&sign=%s' % sign
    print 'Your order:\n%s\n' % payment

def pay():
    global money
    print 'Your order: '
    payment = raw_input().strip()
    sp = payment.rfind('&sign=')
    if sp == -1:
        print 'Invalid Order!'
        return
    sign = payment[sp+6:]
    payment = payment[:sp]
    signchk = sha256(signkey+payment).hexdigest()
    if signchk != sign:
        print 'Invalid Order!'
        return

    for k,v in parse_qsl(payment):
        if k == 'product':
            product = v
        elif k == 'price':
            try:
                price = int(v)
            except:
                print 'Invalid Order!'
                return

    if money < price:
        print 'Sorry, you don\'t have enough money'
        return

    money -= price
    print 'Your current money: $%d' % money
    print 'You have bought %s' % product
    if product == 'FLAG':
        print 'Good job! Here is your flag: %s' % open('flag').read().strip()

def main():
    print 'Viettel Store'
    print 'You were walking on the street. Suddenly, you found a wallet and there are %d VND inside. You decided to go to Viettel Store to buy a new phone' % money
    while True:
        print 'Your wallet: %d VND' % money
        print '1. Phone list'
        print '2. Order'
        print '3. Pay'
        print '4. Exit'
        try:
            inp = int(raw_input())
            print 'Your option: ', inp
            if inp == 1:
                view_list()
            elif inp == 2:
                order()
            elif inp == 3:
                pay()
            elif inp == 4:
                break
        except:
            break

if __name__ == '__main__':
    main()
```

The general flow of the program seems simple enough. I'm given some random amount of money and can "order" an item, in which the URL parameters containing the product, price, and a timestamp (in nanosecond time) is hashed via sha256 after being prepended with a secret signing key of some random length between 8 and 32. I can then use this output to pay for the item. The menu item checks that the hash is the same and that I have enough money to purchase the item. The code shows obviously that I need to somehow purchase the item `FLAG` in order to get the flag for the challenge. The following shows some sample usage.

```sh
$ nc 13.251.110.215 10001
Viettel Store
You were walking on the street. Suddenly, you found a wallet and there are 4410308 VND inside. You decided to go to Viettel Store to buy a new phone
Your wallet: 4410308 VND
1. Phone list
2. Order
3. Pay
4. Exit
2
Your option:  2
Item ID: 5
Your order:
product=FLAG&price=999999999&timestamp=1529219946064768&sign=061d90bd351d5b994b9b5ecf4b84928563aa0449dc30f510d8f42d04a391fa59

Your wallet: 4410308 VND
1. Phone list
2. Order
3. Pay
4. Exit
3
Your option:  3
Your order:
product=FLAG&price=999999999&timestamp=1529219946064768&sign=061d90bd351d5b994b9b5ecf4b84928563aa0449dc30f510d8f42d04a391fa59
Sorry, you don't have enough money
Your wallet: 4410308 VND
1. Phone list
2. Order
3. Pay
4. Exit
```

The main problem seems to be that the price of the item `FLAG` is far too high -- and my starting money is determined via `random.randint(1000000, 5000000)`. The crypto part of the challenge comes from the code taking everything before `&sign`, prepending it with a secret signing key, and then calculating the sha256 hash. It turns out that this exact circumstance is vulnerable to a hash extension attack. I can use the tool [hash_extender](https://github.com/iagox86/hash_extender) called via python's `Popen` in order to calculate a new possible hash without knowing the secret signing key AND I can append arbitrary data to the end as well. This is perfect because I want to append `&price=1` to the end of the URL parameter list so that `FLAG` is affordable. This will work out since the for-loop using `parse_qsl` will overwrite previous parameters.

To clarify, I can give hash_extender prior knowledge such as `product=FLAG&price=999999999&timestamp=1529219946064768` hashing to `061d90bd351d5b994b9b5ecf4b84928563aa0449dc30f510d8f42d04a391fa59` and tell it that I want to append `&price=1` to the end of the string to give me a new hash. This new hash can be used to then buy the `FLAG` item. Easy!

I want to use hash extender in the following way:

```
$ ./hash_extender -d <originally hashed url string> --signature=<sha256 hash of url string> --format=sha256 --secret-min=8 --secret-max=31 --append=&price=1 --append-format=html --data-format=cstr --out-data-format=hex
```

This gives many lines of output of input strings corresponding to the resulting hash that we can use to trick the validation logic in **crypto1.py**. The following script is my solution to this ctf challenge where I use hash_extender to give me a list of new hashes and their corresponding url strings.

**crypto1sol.py**
---
```python
import time
import string
import random
from hashlib import sha256
from urlparse import parse_qsl
from pwn import *
from subprocess import Popen, PIPE
import binascii

HOST = '13.251.110.215'
PORT = 10001

# Use hash_extender's hash extension attack to get new hashes
def getPossibleExtensions(payment, signature):
  p = Popen(['./hash_extender/hash_extender', '-d', '%s' % (payment), '--signature=%s' % (signature), '--format=sha256', '--secret-min=8', '--secret-max=31', '--append=&price=1', '--append-format=html', '--data-format=cstr', '--out-data-format=hex'], stdout=PIPE)

  res = p.communicate()[0]

  l = [x.split(' ')[-1] for x in res.splitlines() if x.startswith('New string')]

  sigs = [x.split(' ')[-1] for x in res.splitlines() if x.startswith('New signature')]

  ret = []
  for i, line in enumerate(l):
    ret.append((binascii.unhexlify(line), sigs[i]))

  return ret

def getPretext(r):
  return '\n'.join(r.recvlines(2))

def getMenu(r):
  return '\n'.join(r.recvlines(5))

# Get the order and the hash
def getOrder(r):
  getMenu(r)
  r.sendline('2')
  r.recvline() # Your option: 
  r.recvuntil('ID: ')
  r.sendline('5')
  r.recvline() # Your order: 
  order = r.recvline().strip()

  sp = order.rfind('&sign=')
  sign = order[sp+6:]
  payment = order[:sp]

  print order
  print 'Payment: %s' % (payment)
  print 'Signature: %s' % (sign)
  r.recvline()
  return payment, sign

# Try one particular payment
# We have to try multiple hash extensions since we
# don't know the length of the secret signing key
def tryPayment(r, payment):
  try:
    m = getMenu(r)
    assert m.startswith('Your wallet:')
    r.sendline('3')
    r.recvline() # Your option: 
    r.recvline() # Your order:
    print '\t[x] Trying: %s' % (payment)
    r.sendline(payment)
    ret = r.recvline().rstrip()

    if ret.startswith('Invalid') or ret.startswith('Sorry'):
      print '[-] %s' % (ret)
      return 1
    else:
      print '[+] %s' % (ret)
      print '[+] %s' % (r.recvline())
      print '[+] %s' % (r.recvline())
      return 0
  except EOFError as e:
    print '[-] Failed due to EOFError'
    return 2
  except Exception as e:
    print '[-] Failed due to unknown exception'
    return 2
  
def main():
  while True:
    r = remote(HOST, PORT)
    getPretext(r)

    payment, sign = getOrder(r)

    possibleExtensions = getPossibleExtensions(payment, sign)

    for p in possibleExtensions:
      ret = tryPayment(r, '%s&sign=%s' % (p[0], p[1]))

      if ret == 2:
        continue
      elif ret == 0:
        r.close()
        return

if __name__ == '__main__':
  main()
```

Running the script will do all of this for me and give the flag (sometimes after many tries due to unknown length of secret signing key):

```sh
$ python crypto1sol.py
[+] Opening connection to 13.251.110.215 on port 10001: Done
product=FLAG&price=999999999&timestamp=1529220888230340&sign=427e7d37ad4031088022d5f3e58a620d3f1e338a64f40d80726b10224f22e34c
Payment: product=FLAG&price=999999999&timestamp=1529220888230340
Signature: 427e7d37ad4031088022d5f3e58a620d3f1e338a64f40d80726b10224f22e34c
    [x] Trying: product=FLAG&price=999999999&timestamp=1529220888230340\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00�&price=1&sign=a7d479dbed69942e27a7fe91665f36028cd22851d3e2bf842a3885b0fae38382
[+] Your current money: $3708842
[+] You have bought FLAG

[+] Good job! Here is your flag: matesctf{e4sy_3xt3nti0n_4tt4cK_x0x0}
```

The flag for this challenge is: `matesctf{e4sy_3xt3nti0n_4tt4cK_x0x0}`.