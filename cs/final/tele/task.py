#!/usr/bin/python3 -u
# -*- coding: utf-8 -*-

import os
import hmac
import hashlib
from Crypto.Util import number
from Crypto.Cipher import AES


def writeInt(x):
    m = {'1': 'te', '0': 'le'}
    print(''.join(map(m.get, bin(x)[2:])))


def readInt():
    s = input('').strip().replace('te', '1').replace('le', '0')
    return int(s, 2)


def lock0(key):
    nonceA = number.getRandomInteger(128)
    writeInt(nonceA)
    nonceB = readInt()
    if nonceA == nonceB:
        raise ValueError('[!] No hacking')

    nonceA = key + number.long_to_bytes(nonceA)
    nonceB = key + number.long_to_bytes(nonceB)
    proofA = int.from_bytes(hashlib.sha1(nonceA).digest(), 'big')
    proofB = int.from_bytes(hashlib.sha1(nonceB).digest(), 'big')

    writeInt(proofA)
    if proofB == readInt():
        print('[+] Access granted')
    else:
        raise PermissionError('[!] Access denied')


def lock1(key):
    nonceA = number.getRandomInteger(128)
    writeInt(nonceA)
    nonceB = readInt()
    if nonceA == nonceB:
        raise ValueError('[!] No hacking')

    nonceA = number.long_to_bytes(nonceA)
    nonceB = number.long_to_bytes(nonceB)
    proofA = int.from_bytes(hmac.new(key, nonceA, 'sha1').digest(), 'big')
    proofB = int.from_bytes(hmac.new(key, nonceB, 'sha1').digest(), 'big')

    writeInt(proofB)
    if proofA == readInt():
        print('[+] Access granted')
    else:
        raise PermissionError('[!] Access denied')


def lock2(key):
    iv = os.urandom(16)

    nonceA = os.urandom(32)
    aes = AES.new(key, AES.MODE_OFB, IV=iv)
    proofA = int.from_bytes(aes.encrypt(nonceA), 'big')
    writeInt(proofA)
    
    proofB = readInt()
    proofB = proofB.to_bytes(32, 'big')
    aes = AES.new(key, AES.MODE_OFB, IV=iv)
    nonceB = aes.decrypt(proofB)

    nonceA = int.from_bytes(nonceA, 'big')
    nonceB = int.from_bytes(nonceB, 'big')

    if nonceA + 13 == nonceB:
        print('[+] Access granted')
    else:
        raise PermissionError('[!] Access denied')


def main():
    with open('../private/keys.txt', 'rb') as f:
        keys = f.read().splitlines()
    with open('../private/flag.txt') as f:
        flag = f.read().strip()
    lock0(keys[0])
    lock1(keys[1])
    lock2(keys[2])
    print('[+] Great: %s' % flag)


if __name__ == '__main__':
    main()
