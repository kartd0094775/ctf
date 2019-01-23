from pwn import *
from time import sleep

def recvline(r):
    return str(r.recvuntil('\n'))[2:-3]

def writeInt(x):
    m = {'1': 'te', '0': 'le'}
    return ''.join(map(m.get, bin(x)[2:]))

def readInt(x):
    s = x.strip().replace('te', '1').replace('le', '0')
    return int(s, 2)

r1 = remote('edu-ctf.zoolab.org', 8402)
r2 = remote('edu-ctf.zoolab.org', 8402)


#### lock0
a = recvline(r1)
b = recvline(r2)
r1.sendline(b)
r2.sendline(a)
a = recvline(r1)
b = recvline(r2)
r1.sendline(b)
r2.sendline(a)
r1.recvuntil('\n')
r2.recvuntil('\n')

#### lock1
a = recvline(r1)
b = recvline(r2)
r1.sendline(b)
r2.sendline(a)
a = recvline(r1)
b = recvline(r2)
r1.sendline(b)
r2.sendline(a)
r1.recvuntil('\n')
r2.recvuntil('\n')


#### lock2
a = recvline(r1)
b = recvline(r2)
a = writeInt(readInt(a) ^ 13)
b = writeInt(readInt(b) ^ 13)
r1.sendline(a)
r2.sendline(b)
a = r1.recvuntil('[+] Great: ')
# b = r2.recvuntil('[+] Great: ')
a = r1.recvuntil('\n')
# b = r2.recvuntil('\n')
print(a, b)
# r1.interactive()