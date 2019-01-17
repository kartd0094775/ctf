import codecs
import random
from time import time

with open('out', 'r') as f:
    flag = f.readlines()[2][:-1]
    
flag = flag.encode('ascii')
flag = codecs.decode(flag, 'base64')
flag1, flag2 = flag[:len(flag) // 2], flag[len(flag) // 2: len(flag)]

#### decrypt flag1

token = b'flag{'
target_seq = list()

for i in range(5):
    target_seq.append(token[i] ^ flag1[i])

t = int(time())
for i in range(t):
    random.seed(t-i)
    seq = [random.randrange(256) for _ in range(5)]
    if seq == target_seq:
        print(f'seed 1: {t-i}')
        random.seed(t-i)
        flag1 = bytes(c ^ random.randrange(256) for c in flag1).decode('ascii')
        break

#### decrypt flag2
with open('rockyou.txt', 'rb') as f:
    for word in f:
        try:
            # word = b'punzalan\n'
            seed = int.from_bytes(word[:-1], 'little')
            random.seed(seed)
            seq = bytes(c ^ random.randrange(256) for c in flag2)
            if seq[-1] == ord('}'):
                flag2 = seq.decode('ascii')
                print(f'seed 2: {word[:-1]}')
                break
        except Exception as e:
            if type(e).__name__ == 'UnicodeDecodeError':
                None

print(flag1 + flag2)